// +----------------------------------------------------------------------------
// |
// |   Copyright (c) 2017 Christopher Stone
// |   Licensed under GPL v3, see LICENSE file.
// |
// |   THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
// |   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// |   MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// |   DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
// |   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// |   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// |   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
// |   BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// |   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// |   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// |   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// |
// +----------------------------------------------------------------------------
// |
// | dslgateway.c
// |
// |    This file is part of a dsl gateway that splits outgoing IP traffic between
// | two DSL lines. See dslgateway.c for an explanation of the features and intent
// | of the program. This file implements the home gateway (client side) 
// | functions.
// |
// +----------------------------------------------------------------------------


#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <net/if.h>
#include <stdarg.h>
#include <fcntl.h>
#include <syslog.h>
#include <signal.h>
#include <semaphore.h>
#include <sched.h>
#include <pthread.h>
#include <netdb.h>
#include <time.h>
#include <linux/if_tun.h>
#include <linux/sockios.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <ifaddrs.h>
#include <libconfig.h>

#include "circular_buffer.h"
#include "log.h"
#include "comms.h"
#include "util.h"
#include "dslgateway.h"


extern char                     *progname;
extern struct if_config_s       if_config[NUM_INGRESS_INTERFACES+NUM_EGRESS_INTERFACES];
extern unsigned int             egresscnt, ingresscnt;
extern struct statistics_s      if_stats;
extern unsigned int             cc_port;
extern  struct thread_list_s    dsl_threads[((NUM_INGRESS_INTERFACES+NUM_EGRESS_INTERFACES)*2)+2];
extern mempool                  mPool;
extern int                      comms_peer_fd;
extern int                      thread_exit_rc;
extern bool                     comms_addr_valid;
extern unsigned int             n_mbufs;
extern bool                     ipv6_mode;
extern bool                     q_control_on;
extern char                     *comms_name;

static bool                     is_daemon=false;
static uint8_t                  pkt_seq_no=0;
static unsigned int             num_threads;
static struct mbuf_s            *reorder_buf[REORDER_BUF_SZ];
static timer_t                  reorder_buf_timerid;
static struct itimerspec        reorder_buf_intvl;
static unsigned int             reorder_if_cnt[2] = {0, 0};
static struct sockaddr_in6      peer_addr6;
static struct sockaddr_in       peer_addr;
static bool                     debug=false;
static char                     config_file_name[PATH_MAX];
static char                     *remote_name=NULL;



// +----------------------------------------------------------------------------
// | Timer thread to drain reorder buf if packets have been there too long
// +----------------------------------------------------------------------------
static void reorder_buf_timer(union sigval arg)
{
    struct timespec     ts, tsdiff;
    int                 i, j, k;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    for (i=0; i<REORDER_BUF_SZ; i++) {
        if (reorder_buf[i] != NULL) {
            tsdiff = subtract_ts(&ts, &reorder_buf[i]->rx_time);
            if (tsdiff.tv_sec || (tsdiff.tv_nsec > REORDER_BUF_TIMEOUT)) {
                circular_buffer_push(if_config[INGRESS_IF].if_txq.if_pkts, reorder_buf[i]);
                sem_post(&if_config[INGRESS_IF].if_txq.if_ready);
                pkt_seq_no = reorder_buf[i]->seq_no + 1;
                reorder_buf[i] = NULL;
            } else break;
        }
    }
    for (i=0; i<REORDER_BUF_SZ; i++) {
        if (reorder_buf[i] != NULL) {
            if (i != 0) {
                for (j=i, k=0; j<REORDER_BUF_SZ; j++, k++) {
                    reorder_buf[k] = reorder_buf[j];
                    reorder_buf[j] = NULL;
                }
                break;
            } else break;
        }
    }
}


// +----------------------------------------------------------------------------
// | Start the reorder buffer timeout timer.
// +----------------------------------------------------------------------------
static void arm_reorder_buf_timer(void)
{
    reorder_buf_intvl.it_value.tv_sec   = reorder_buf_intvl.it_interval.tv_sec;
    reorder_buf_intvl.it_value.tv_nsec  = reorder_buf_intvl.it_interval.tv_nsec;
    timer_settime(reorder_buf_timerid, 0, &reorder_buf_intvl, NULL);
}


// +----------------------------------------------------------------------------
// | Stop the reorder buffer timeout timer.
// +----------------------------------------------------------------------------
static void disarm_reorder_buf_timer(void)
{
    reorder_buf_intvl.it_value.tv_sec   = 0;
    reorder_buf_intvl.it_value.tv_nsec  = 0;
    timer_settime(reorder_buf_timerid, 0, &reorder_buf_intvl, NULL);
}


// +----------------------------------------------------------------------------
// | Receive thread, one is started on each interface. Note that the rx threads 
// | for both egress interfaces on the home gateway, feed mbufs into the same 
// | circular buffer.
// +----------------------------------------------------------------------------
static void *rx_thread(void * arg)
{
    struct if_queue_s   *rxq = (struct if_queue_s *) arg;
    struct mbuf_s       *mbuf=NULL;
    ssize_t             rxSz;

    log_debug_msg(LOG_INFO, "%s-%d: Rx thread on interface %s started.\n", __FUNCTION__, __LINE__, if_config[rxq->if_index].if_rxname);
    while (rxq->if_thread->keep_going) {
        if (mbuf == NULL) mbuf = (struct mbuf_s*) mempool_alloc(mPool);
        if (mbuf == NULL) {
            sleep(1);
            continue;
        }
        // TODO: deal with partial packet receipt
        while (((rxSz = read(if_config[rxq->if_index].if_rx_fd, (void *) mbuf, sizeof(union mbuf_u))) < 0) && (errno == EINTR));
        if (rxSz < 0) {
            log_msg(LOG_ERR, "%s-%d: Error reading raw packets from interface %s - %s",
                    __FUNCTION__, __LINE__, if_config[rxq->if_index].if_rxname, strerror(errno));
            continue;
        }
        mbuf->if_index = rxq->if_index;

        // ignore packets from egress interfaces with if_ratio = 0
        if ((rxq->if_index == EGRESS_IF || rxq->if_index == EGRESS_IF+1) && if_config[rxq->if_index].if_ratio == 0) {
            if_stats.if_dropped_pkts_ratio[rxq->if_index]++;
            continue;
        }

        switch (mbuf->pkt.tcp_pkt.eth_hdr.ether_type) {
            case ETHERTYPE_IPV6:
                if (!ipv6_mode) {
                    // not ipv6 mode so drop the packet
                    if_stats.if_dropped_pkts_v4v6[rxq->if_index]++;
                    continue;
                }
                mbuf->ipv6 = true;
                break;
            case ETHERTYPE_IP:
                if (ipv6_mode) {
                    // not ipv4 mode so drop the packet
                    if_stats.if_dropped_pkts_v4v6[rxq->if_index]++;
                    continue;
                }
                mbuf->ipv6 = false;
                break;
            default:
                if_stats.if_dropped_pkts[rxq->if_index]++;
                continue;
        }
        clock_gettime(CLOCK_MONOTONIC, &mbuf->rx_time);

        // For debugging purposes, we have queue control that will only let a set number
        // of packets through
        if (rxq->q_control) {
            if (!rxq->q_control_cnt) {
                if_stats.if_dropped_pkts_qcontrol[rxq->if_index]++;
                continue;
            }
            rxq->q_control_cnt--;
        }

        // Accept the packet
        circular_buffer_push(rxq->if_pkts, (void *) mbuf);
        sem_post(&rxq->if_ready);
        mbuf = NULL;
        if_stats.if_rx_pkts[rxq->if_index]++;
        if_stats.if_rx_bytes[rxq->if_index] += rxSz;
    }

    thread_exit_rc = 0;
    pthread_exit(&thread_exit_rc);
    return &thread_exit_rc;   // for compiler warnings
}

// +----------------------------------------------------------------------------
// | Do the packet mangling on the home gateway between the home network and the vps.
// +----------------------------------------------------------------------------
static void *home_to_vps_pkt_mangler_thread(void * arg)
{
    struct mbuf_s   *mbuf;
    uint8_t         *if_ratios;
    unsigned char   *mbufc;
    unsigned int    active_if = 0;
    struct in6_addr *sv_dest_addr6;
    struct ip6_hdr  *ip6hdr;
    struct in_addr  *sv_dest_addr;
    struct ip       *iphdr;

    while (dsl_threads[HOME_TO_VPS_PKT_MANGLER_THREADNO].keep_going) {
        sem_wait(&if_config[INGRESS_IF].if_rxq.if_ready);
        if ((mbuf = circular_buffer_pop(if_config[INGRESS_IF].if_rxq.if_pkts)) == NULL) continue;
        mbufc                   = (unsigned char *) mbuf;
        // Save the destination address at the end of the packet. Also save the if_ratios
        // in one byte at the end of the packet. Increase packet length by the length
        // of the destination address plus 1 byte for if_ratios. Replace destination
        // address with vps ip address, so packet will go to the vps.
        if (mbuf->ipv6) {
            ip6hdr                  = (struct ip6_hdr *) (mbufc + sizeof(struct ether_header));
            sv_dest_addr6           = (struct in6_addr *) (mbufc + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + ip6hdr->ip6_plen);
            memcpy(sv_dest_addr6, &ip6hdr->ip6_dst, sizeof(struct in6_addr));
            if_ratios               = (uint8_t *) (mbufc + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + ip6hdr->ip6_plen + sizeof(struct in6_addr));
            memcpy(&ip6hdr->ip6_dst, &peer_addr6.sin6_addr, sizeof(struct in6_addr));
            ip6hdr->ip6_plen        = ip6hdr->ip6_plen + sizeof(struct in6_addr) + 2;
        } else {
            iphdr                   = (struct ip *) (mbufc + sizeof(struct ether_header));
            sv_dest_addr            = (struct in_addr *) (mbufc + sizeof(struct ether_header) + iphdr->ip_len);
            memcpy(sv_dest_addr, &iphdr->ip_dst, sizeof(struct in_addr));
            if_ratios               = (uint8_t *) (mbufc + sizeof(struct ether_header) + iphdr->ip_len + sizeof(struct in_addr));
            iphdr->ip_dst.s_addr    = peer_addr.sin_addr.s_addr;
            iphdr->ip_len           = iphdr->ip_len + sizeof(struct in_addr) + 2;
            iphdr->ip_sum           = iphdr_checksum((unsigned short*)(mbufc + sizeof(struct ether_header)), (sizeof(struct iphdr)/2));
        }
        if_ratios[0]            = if_config[0].if_ratio;
        if_ratios[1]            = if_config[1].if_ratio;
        circular_buffer_push(if_config[active_if].if_txq.if_pkts, mbuf);
        sem_post(&if_config[active_if].if_txq.if_ready);
        active_if               = (active_if+1) % NUM_EGRESS_INTERFACES;
    }

    thread_exit_rc = 0;
    pthread_exit(&thread_exit_rc);
    return &thread_exit_rc; // for compiler warnings
}


// +----------------------------------------------------------------------------
// | Drain the reorder buf until a gap is found.
// +----------------------------------------------------------------------------
static void drain_reorder_buf(bool *reorder_active)
{
    int     i=0, j;

    while ((reorder_buf[i] != NULL) && (i<REORDER_BUF_SZ)) {
        circular_buffer_push(if_config[INGRESS_IF].if_txq.if_pkts, reorder_buf[i]);
        sem_post(&if_config[INGRESS_IF].if_txq.if_ready);
        pkt_seq_no++;
        reorder_buf[i] = NULL;
        i++;
    }
    *reorder_active = false;
    reorder_if_cnt[0] = reorder_if_cnt[1] = 0;
    if (i<REORDER_BUF_SZ) {
        for (i=i+1, j=0; i<REORDER_BUF_SZ; i++, j++) {
            reorder_buf[j] = reorder_buf[i];
            if (reorder_buf[i] != NULL) {
                *reorder_active = true;
                reorder_if_cnt[reorder_buf[j]->if_index]++;
            }
            reorder_buf[i] = NULL;
        }
    }
    if (!reorder_active) disarm_reorder_buf_timer();
}


// +----------------------------------------------------------------------------
// | Completely drain the reorder buf.
// +----------------------------------------------------------------------------
static void force_drain_reorder_buf(void)
{
    int i;

    if_config[0].if_ratio = reorder_if_cnt[0];
    if_config[1].if_ratio = reorder_if_cnt[1];
    for (i=0; i<REORDER_BUF_SZ; i++) {
        if (reorder_buf[i] != NULL) {
            circular_buffer_push(if_config[INGRESS_IF].if_txq.if_pkts, reorder_buf[i]);
            sem_post(&if_config[INGRESS_IF].if_txq.if_ready);
            reorder_buf[i] = NULL;
        }
    }
    reorder_if_cnt[0] = reorder_if_cnt[1] = 0;
}


// +----------------------------------------------------------------------------
// | Do the packet mangling on the home gateway between the vps and the home network.
// +----------------------------------------------------------------------------
static void *home_from_vps_pkt_mangler_thread(void * arg)
{
    struct mbuf_s   *mbuf;
    uint8_t         *seq_no;
    int             seq_diff;
    unsigned char   *mbufc;
    unsigned int    i;
    bool            reorder_active=false;
    struct in6_addr *sv_dest_addr6;
    struct ip6_hdr  *ip6hdr;
    struct in_addr  *sv_dest_addr;
    struct ip       *iphdr;

    for (i=0; i<REORDER_BUF_SZ; i++) reorder_buf[i] = NULL;
    while (dsl_threads[HOME_FROM_VPS_PKT_MANGLER_THREADNO].keep_going) {
        sem_wait(&if_config[EGRESS_IF].if_rxq.if_ready);
        if ((mbuf = circular_buffer_pop(if_config[EGRESS_IF].if_rxq.if_pkts)) == NULL) continue;
        mbufc                   = (unsigned char *) mbuf;
        if (mbuf->ipv6) {
            ip6hdr                  = (struct ip6_hdr *) (mbufc + sizeof(struct ether_header));
            sv_dest_addr6           = (struct in6_addr *) (mbufc + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + ip6hdr->ip6_plen);
            seq_no                  = (uint8_t *) (mbufc + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + ip6hdr->ip6_plen + sizeof(struct in6_addr));
            memcpy(ip6hdr->ip6_dst.s6_addr, sv_dest_addr6, sizeof(struct in6_addr));
            ip6hdr->ip6_plen        = ip6hdr->ip6_plen - sizeof(struct in6_addr) - 1;
        } else {
        iphdr                   = (struct ip *) (mbufc + sizeof(struct ether_header));
            sv_dest_addr            = (struct in_addr *) (mbufc + sizeof(struct ether_header) + iphdr->ip_len);
            seq_no                  = (uint8_t *) (mbufc + sizeof(struct ether_header) + iphdr->ip_len + sizeof(struct in_addr));
            memcpy(&iphdr->ip_dst, sv_dest_addr, sizeof(struct in_addr));
            iphdr->ip_len           = iphdr->ip_len - sizeof(struct in_addr) - 1;
            iphdr->ip_sum           = iphdr_checksum((unsigned short*)(mbufc + sizeof(struct ether_header)), (sizeof(struct iphdr)/2));
        }
        seq_diff                = *seq_no - pkt_seq_no;
        if (seq_diff < 0) seq_diff = (255 - pkt_seq_no) + *seq_no + 1;
        if (seq_diff > 0) {
            if (seq_diff > REORDER_BUF_SZ) {
                // Packet we are waiting for is late, drain reorder buffer and let the tcp
                // layer deal with it.
                pkt_seq_no++;
                drain_reorder_buf(&reorder_active);
                seq_diff        = *seq_no - pkt_seq_no;
                if (seq_diff < 0) seq_diff = (255 - pkt_seq_no) + *seq_no + 1;
                if (seq_diff > 0) {
                    // There are multiple packets that are late, force drain the reorder
                    // buffer and let the tcp layer deal with it.
                    force_drain_reorder_buf();
                    pkt_seq_no = *seq_no;
                    reorder_active  = false;
                    disarm_reorder_buf_timer();
                    if_stats.reorder_failures++;
                }
            } else {
                if (!reorder_active) {
                    // Start a timer to clear packets from reorder buffer if they have been
                    // there too long.
                    arm_reorder_buf_timer();
                }
                reorder_buf[seq_diff-1] = mbuf;
                reorder_active          = true;
                reorder_if_cnt[mbuf->if_index]++;
                if_stats.reorders++;
                continue;
            }
        }
        circular_buffer_push(if_config[INGRESS_IF].if_txq.if_pkts, mbuf);
        sem_post(&if_config[INGRESS_IF].if_txq.if_ready);
        pkt_seq_no++;
        // Send any additional packets that were accumulating in the reorder buffer
        if (reorder_active) drain_reorder_buf(&reorder_active);
    }

    thread_exit_rc = 0;
    pthread_exit(&thread_exit_rc);
    return &thread_exit_rc;  // for compiler warnings
}


// +----------------------------------------------------------------------------
// | Create all the client threads
// +----------------------------------------------------------------------------
static int create_threads(void)
{
    int rc;

    snprintf(dsl_threads[0].thread_name, 16, "rx_thread0");
    if ((rc = create_thread(&dsl_threads[0].thread_id, rx_thread, RXPRIO, dsl_threads[0].thread_name, (void *) &if_config[0].if_rxq)) != 0) {
        log_msg(LOG_ERR, "%s-%d: Can not create rx thread for interface %s - %s.\n", __FUNCTION__, __LINE__, if_config[0].if_rxname, strerror(rc));
        return rc;
    }
    snprintf(dsl_threads[1].thread_name, 16, "rx_thread1");
    if ((rc = create_thread(&dsl_threads[1].thread_id, rx_thread, RXPRIO, dsl_threads[1].thread_name, (void *) &if_config[1].if_rxq)) != 0) {
        log_msg(LOG_ERR, "%s-%d: Can not create rx thread for interface %s - %s.\n", __FUNCTION__, __LINE__, if_config[1].if_rxname, strerror(rc));
        return rc;
    }
    snprintf(dsl_threads[2].thread_name, 16, "rx_thread2");
    if ((rc = create_thread(&dsl_threads[2].thread_id, rx_thread, RXPRIO, dsl_threads[2].thread_name, (void *) &if_config[2].if_rxq)) != 0) {
        log_msg(LOG_ERR, "%s-%d: Can not create rx thread for interface %s - %s.\n", __FUNCTION__, __LINE__, if_config[2].if_rxname, strerror(rc));
        return rc;
    }
    snprintf(dsl_threads[3].thread_name, 16, "tx_thread0");
    if ((rc = create_thread(&dsl_threads[3].thread_id, tx_thread, TXPRIO, dsl_threads[3].thread_name, (void *) &if_config[0].if_txq)) != 0) {
        log_msg(LOG_ERR, "%s-%d: Can not create tx thread for interface %s - %s.\n", __FUNCTION__, __LINE__, if_config[0].if_txname, strerror(rc));
        return rc;
    }
    snprintf(dsl_threads[4].thread_name, 16, "tx_thread1");
    if ((rc = create_thread(&dsl_threads[4].thread_id, tx_thread, TXPRIO, dsl_threads[4].thread_name, (void *) &if_config[1].if_txq)) != 0) {
        log_msg(LOG_ERR, "%s-%d: Can not create tx thread for interface %s - %s.\n", __FUNCTION__, __LINE__, if_config[1].if_txname, strerror(rc));
        return rc;
    }
    snprintf(dsl_threads[5].thread_name, 16, "tx_thread2");
    if ((rc = create_thread(&dsl_threads[5].thread_id, tx_thread, TXPRIO, dsl_threads[5].thread_name, (void *) &if_config[2].if_txq)) != 0) {
        log_msg(LOG_ERR, "%s-%d: Can not create tx thread for interface %s - %s.\n", __FUNCTION__, __LINE__, if_config[2].if_txname, strerror(rc));
        return rc;
    }
    snprintf(dsl_threads[HOME_TO_VPS_PKT_MANGLER_THREADNO].thread_name, 16, "home_to_vps");
    if ((rc = create_thread(&dsl_threads[HOME_TO_VPS_PKT_MANGLER_THREADNO].thread_id, home_to_vps_pkt_mangler_thread, HOME_TO_VPS_PRIO, dsl_threads[HOME_TO_VPS_PKT_MANGLER_THREADNO].thread_name, NULL)) != 0) {
        log_msg(LOG_ERR, "%s-%d: Can not create home to vps thread - %s.\n", __FUNCTION__, __LINE__, strerror(rc));
        return rc;
    }
    snprintf(dsl_threads[HOME_FROM_VPS_PKT_MANGLER_THREADNO].thread_name, 16, "home_from_vps");
    if ((rc = create_thread(&dsl_threads[HOME_FROM_VPS_PKT_MANGLER_THREADNO].thread_id, home_from_vps_pkt_mangler_thread, HOME_FROM_VPS_PRIO, dsl_threads[HOME_FROM_VPS_PKT_MANGLER_THREADNO].thread_name, NULL)) != 0) {
        log_msg(LOG_ERR, "%s-%d: Can not create home from vps thread - %s.\n", __FUNCTION__, __LINE__, strerror(rc));
        return rc;
    }
    num_threads = 8;
    return 0;
}

// +----------------------------------------------------------------------------
// | Handle a query on the comms socket
// +----------------------------------------------------------------------------
void handle_client_query(struct comms_query_s *query, int comms_client_fd, bool *connection_active)
{
    int                     rc, i, bytecnt;
    struct comms_reply_s    reply;
    char                    *query_c = (char *) query;
    char                    *reply_c = (char *) &reply;

//    log_debug_msg(LOG_INFO, "Received request %02x.\n", query->cmd);
    if (query->for_peer) {
//        log_debug_msg(LOG_INFO, "Request is for peer.\n");
        if (comms_addr_valid) {
            query->for_peer = false;
            bytecnt = 0;
//            log_debug_msg(LOG_INFO, "Sending request to peer.\n");
            do {
                if ((rc = send(comms_peer_fd, &query_c[bytecnt], sizeof(struct comms_query_s)-bytecnt, 0)) == -1) {
                    log_msg(LOG_ERR, "%s-%d: Error sending comms request to remote peer - %s", __FUNCTION__, __LINE__, strerror(errno));
                    reply.rc = errno;
                    send(comms_client_fd, &reply, sizeof(struct comms_reply_s), 0);
                    return;
                }
                bytecnt += rc;
            } while (bytecnt < sizeof(struct comms_query_s));
            bytecnt = 0;
            do {
                if ((rc = recv(comms_peer_fd, &reply_c[bytecnt], sizeof(struct comms_reply_s)-bytecnt, 0)) == -1) {
                    log_msg(LOG_ERR, "%s-%d: Error receiving reply from remote peer - %s", __FUNCTION__, __LINE__, strerror(errno));
                    reply.rc = errno;
                    send(comms_client_fd, &reply, sizeof(struct comms_reply_s), 0);
                    return;
                }
                bytecnt += rc;
            } while (bytecnt < sizeof(struct comms_reply_s));
//            log_debug_msg(LOG_INFO, "Received reply from peer, rc=%d.\n", reply.rc);
            reply.rc = 0;
        } else {
            reply.rc = 1;
        }
    } else {
        switch (query->cmd){
            case COMMS_GETSTATS:
                if_stats.mempool_freesz                         = mempool_freeSz(mPool);
                if_stats.mempool_overheadsz                     = mempool_overheadSz(mPool);
                if_stats.mempool_totalsz                        = mempool_totalSz(mPool);
                for (i=0; i<if_stats.num_interfaces; i++) {
                    if_stats.circular_buffer_rxq_freesz[i]      = circular_buffer_freesz(if_config[i].if_rxq.if_pkts);
                    if_stats.circular_buffer_txq_freesz[i]      = circular_buffer_freesz(if_config[i].if_txq.if_pkts);
                    if_stats.circular_buffer_rxq_overheadsz[i]  = circular_buffer_overheadsz(if_config[i].if_rxq.if_pkts);
                    if_stats.circular_buffer_txq_overheadsz[i]  = circular_buffer_overheadsz(if_config[i].if_txq.if_pkts);
                    if_stats.circular_buffer_rxq_sz[i]          = circular_buffer_sz(if_config[i].if_rxq.if_pkts);
                    if_stats.circular_buffer_txq_sz[i]          = circular_buffer_sz(if_config[i].if_txq.if_pkts);
                }
                memcpy(&reply.stats, &if_stats, sizeof(struct statistics_s));
                reply.rc    = 0;
                break;
            case COMMS_KILL:
                reply.rc        = 0;
                reply.is_client = true;
                send(comms_client_fd, &reply, sizeof(struct comms_reply_s), 0);
                exit_level1_cleanup();
                exit(EXIT_SUCCESS);
                break;
            case COMMS_EXIT:
                *connection_active  = false;
                break;
            case COMMS_SET_QCONTROL:
                if (query->q_control_cnt == -1) {
                    if_config[query->q_control_index].if_rxq.q_control      = false;
                } else {
                    if_config[query->q_control_index].if_rxq.q_control_cnt  = query->q_control_cnt;
                    if_config[query->q_control_index].if_rxq.q_control      = true;
                }
                reply.rc            = 0;
                break;
            default:
                log_debug_msg(LOG_INFO, "Received invalid request.\n");
                reply.rc    = -1;
        }
        reply.is_client = true;
    }

    bytecnt = 0;
    do {
        if ((rc = send(comms_client_fd, &reply_c[bytecnt], sizeof(struct comms_reply_s)-bytecnt, 0)) == -1) {
            log_msg(LOG_ERR, "%s-%d: Error sending comms request to remote peer - %s", __FUNCTION__, __LINE__, strerror(errno));
            reply.rc = errno;
            send(comms_client_fd, &reply, sizeof(struct comms_reply_s), 0);
            return;
        }
        bytecnt += rc;
    } while (bytecnt < sizeof(struct comms_reply_s));
}


// +----------------------------------------------------------------------------
// | Read the config file and set all the appropriate variables from the values.
// +----------------------------------------------------------------------------
static void read_config_file(void)
{
    config_t                cfg;
    const config_setting_t  *config_egress_list;
    const char              *config_string=NULL;
    int                     i, j;

    config_init(&cfg);

    if (!config_read_file(&cfg, config_file_name)) {
        log_msg(LOG_ERR, "%s-%d: Error reading config file, all parameters revert to defaults.\n", __FUNCTION__, __LINE__);
        return;
    }

    if (config_lookup_int(&cfg, "port", &cc_port))
        log_msg(LOG_INFO, "Configured for comms port on %d.\n", cc_port);
    if (config_lookup_int(&cfg, "mbufs", &n_mbufs))
        log_msg(LOG_INFO, "Configured for %d mbufs.\n", n_mbufs);
    if (config_lookup_int(&cfg, "ipversion", &i)) {
        if (i == 6) ipv6_mode = true;
        log_msg(LOG_INFO, "Configured for %s.\n", ipv6_mode ? "ipv6" : "ipv4");
    }
    if (config_lookup_bool(&cfg, "qcontrol", &i)) {
        q_control_on = i;
        log_msg(LOG_INFO, "Configured for debugging queue control %s.\n", q_control_on ? "on" : "off");
    }
    config_string = NULL;
    if (config_lookup_string(&cfg, "comms_name", &config_string)) {
        if ((comms_name = malloc(strlen(config_string)+1)) == NULL) {
            log_msg(LOG_ERR, "%s-%d: Out of memory.\n", __FUNCTION__, __LINE__);
            exit(ENOMEM);
        }
        strcpy(comms_name, config_string);
        log_msg(LOG_INFO, "Configured for comms on %s.\n", comms_name);
    }
    config_string = NULL;
    if (config_lookup_string(&cfg, "client.ingress.input", &config_string)) {
        strcpy(if_config[INGRESS_IF].if_rxname, config_string);
        log_msg(LOG_INFO, "Configured for client ingress rx on %s.\n", if_config[INGRESS_IF].if_rxname);
        ingresscnt = 1;
    }
    config_string = NULL;
    if (config_lookup_string(&cfg, "client.ingress.output", &config_string)) {
        strcpy(if_config[INGRESS_IF].if_txname, config_string);
        log_msg(LOG_INFO, "Configured for client ingress tx on %s.\n", if_config[INGRESS_IF].if_txname);
        ingresscnt = 1;
    }
    config_string = NULL;
    if (config_lookup_string(&cfg, "client.server_name", &config_string)) {
        if ((remote_name = malloc(strlen(config_string)+1)) == NULL) {
            log_msg(LOG_ERR, "%s-%d: Out of memory.\n", __FUNCTION__, __LINE__);
            exit(ENOMEM);
        }
        strcpy(remote_name, config_string);
        log_msg(LOG_INFO, "Configured for server name %s.\n", remote_name);
    }
    config_egress_list = config_lookup(&cfg, "client.egress.input");
    for (i=EGRESS_IF, j=0; i<config_setting_length(config_egress_list); i++, j++) {
        if (j == 2) break;  // no more than two egress interfaces
        egresscnt++;
        strcpy(if_config[i].if_rxname, config_setting_get_string_elem(config_egress_list, j));
        log_msg(LOG_INFO, "Configured for client egress rx interface on %s.\n", if_config[i].if_rxname);
    }
    config_egress_list = config_lookup(&cfg, "client.egress.output");
    for (i=EGRESS_IF, j=0; i<config_setting_length(config_egress_list); i++, j++) {
        if (j == 2) break;  // no more than two egress interfaces
        strcpy(if_config[i].if_txname, config_setting_get_string_elem(config_egress_list, j));
        log_msg(LOG_INFO, "Configured for client egress tx interface on %s.\n", if_config[i].if_txname);
    }
    config_egress_list = config_lookup(&cfg, "client.egress.ratio");
    for (i=EGRESS_IF, j=0; i<config_setting_length(config_egress_list); i++, j++) {
        if (j == egresscnt) break; // no more than 2 interface ratios
        if_config[i].if_ratio = config_setting_get_int_elem(config_egress_list, j);
        log_msg(LOG_INFO, "Configured for client egress interface ratio of %u on %s.\n", if_config[i].if_ratio, if_config[i].if_txname);
    }

    config_destroy(&cfg);
}


// +----------------------------------------------------------------------------
// | Main processing.
// +----------------------------------------------------------------------------
int main(int argc, char *argv[])
{
    int                         option, i, rc;
    bool                        daemonize = true;
    pid_t                       pid, sid;
    struct sigaction            sigact;
    struct sched_param          sparam;
    struct sigevent             se;
    struct comms_query_s        client_query;
    struct comms_reply_s        client_response;
    struct ifreq                ifr;
    sem_t                       goodnight;

    i=0;
    if (argv[0][0] == '.' || argv[0][0] == '/') i++;
    if (argv[0][1] == '.' || argv[0][1] == '/') i++;
    progname = &argv[0][i];

    memset(config_file_name, 0, PATH_MAX);
    strcpy(config_file_name, DEFAULT_CONFIG_FILE_NAME);

    for (i=0; i<NUM_INGRESS_INTERFACES+NUM_EGRESS_INTERFACES; i++) {
        memset(&if_config[i], 0, sizeof(struct if_config_s));
    }
    memset(&if_stats, 0, sizeof(struct statistics_s));
    memset(dsl_threads, 0, sizeof(struct thread_list_s)*9);
    for (i=0; i<9; i++) dsl_threads[i].keep_going = true;

    // Hook the sigterm and sigint signals
    memset(&sigact, 0, sizeof(sigact));
    sigact.sa_handler = &signal_handler;
    sigaction(SIGTERM, &sigact, NULL);
    sigaction(SIGINT, &sigact, NULL);

    // Check command line options
    while((option = getopt(argc, argv, "c:hdf")) > 0) {
        switch(option) {
            case 'd':
                debug = true;
                break;
            case 'f':
                daemonize = false;
                break;
            case 'h':
                usage(progname);
                break;
            case 'c':
                strncpy(config_file_name, optarg, strlen(optarg)+1);
                break;
            default:
                printf("Unknown option %c\n", option);
                usage(progname);
                exit(EINVAL);
        }
    }

    // daemonize
    if (daemonize) {
        pid = fork();
        if (pid < 0) {
            printf("Daemonize fork failed.\n");
            exit(EXIT_FAILURE);
        }
        if (pid > 0) {
            // parent exits
            exit(EXIT_SUCCESS);
        }
        umask(0);
        sid = setsid();
        if (sid < 0) {
            printf("Can not create new session id for daemon - %s.\n", strerror(errno));
            exit(errno);
        }
        if ((chdir("/")) < 0) {
            printf("Could not change running directory to / when daemonizing - %s.\n", strerror(errno));
            exit(errno);
        }
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        is_daemon = true;
    }

    // Initialize the system logger.
    if (is_daemon)
        log_init(debug, true, progname);
    else
        log_init(debug, false, progname);

    // configure this instance of the program
    read_config_file();

    if ((remote_name == NULL) || (strlen(remote_name) == 0)) {
        log_msg(LOG_ERR, "You must provide a server ip or name in config file.\n\n");
        exit(EINVAL);
    }

    if ((comms_name == NULL) || (strlen(comms_name) == 0)) {
        log_msg(LOG_ERR, "You must provide a comms ip or dns name in config file.\n\n");
        exit(EINVAL);
    }

    if (ingresscnt == 0) {
        log_msg(LOG_ERR, "You must provide an ingress interface name in the config file.\n\n");
        exit(EINVAL);
    }

    if (egresscnt == 0) {
        log_msg(LOG_ERR, "You must provide an egress interface name in the config file.\n\n");
        exit(EINVAL);
    }

    // Switch to real time scheduler
    sparam.sched_priority = sched_get_priority_min(SCHED_RR);
    if (sched_setscheduler(getpid(), SCHED_RR, &sparam) == -1) {
        log_msg(LOG_WARNING, "%s-%d: Set scheduler returns %s, continuing on SCHED_OTHER.\n",
                __FUNCTION__, __LINE__, strerror(errno));
    }

    // Allocate the memory pool for mbufs
    if ((mPool = mempool_create(sizeof(struct mbuf_s), n_mbufs)) == MEM_POOL_INVALID) {
        log_msg(LOG_ERR, "%s-%d: Out of memory.\n", __FUNCTION__, __LINE__);
        exit(ENOMEM);
    }

    // Open egress interfaces,
    // allocate rx and tx circular buffers for egress interfaces. Note there are
    // two egress interfaces on the home gateway, and one on the vps
    open_egress_interfaces();

    // Get ip addresses of all the interfaces
    get_ip_addrs();
    
    // Open raw socket for ingress tx interface, opened in IP mode so we don't have to
    // provide the ethernet header.
    if ((if_config[INGRESS_IF].if_tx_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
        rc = errno;
        log_msg(LOG_ERR, "%s-%d: Can not create tx socket for ingress interface %d - %s.\n", __FUNCTION__, __LINE__, i, strerror(errno));
        exit_level1_cleanup();
        exit(rc);
    }
    memset(&ifr, 0, sizeof(ifr));
    if (ipv6_mode)
        ifr.ifr_addr.sa_family = AF_INET6;
    else
        ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, if_config[INGRESS_IF].if_txname, sizeof(ifr.ifr_name));
    // Bind raw socket to a particular interface name (eg: ppp0 or ppp1)
    if (setsockopt(if_config[INGRESS_IF].if_tx_fd, SOL_SOCKET, SO_BINDTODEVICE, (void *) &ifr, sizeof(ifr)) < 0) {
        rc = errno;
        log_msg(LOG_ERR, "%s-%d: Can not bind socket to %s - %s.\n", __FUNCTION__, __LINE__, ifr.ifr_name, strerror(errno));
        exit_level1_cleanup();
        exit(rc);
    }
    // Open ingress rx socket interface, this socket is opened such that we get the ethernet
    // header as well as the ip header
    if ((if_config[INGRESS_IF].if_rx_fd = tuntap_init(if_config[INGRESS_IF].if_rxname)) < 0) {
        rc = errno;
        log_msg(LOG_ERR, "%s-%d: Can not create rx socket for ingress rx interface %d - %s.\n", __FUNCTION__, __LINE__, i, strerror(errno));
        exit_level1_cleanup();
        exit(rc);
    }
    // Bind raw socket to a particular interface name (eg: ppp0 or ppp1)
//    if (setsockopt(if_config[INGRESS_IF].if_rx_fd, SOL_SOCKET, SO_BINDTODEVICE, (void *) &ifr, sizeof(ifr)) < 0) {
//        rc = errno;
//        log_msg(LOG_ERR, "%s-%d: Can not bind socket to %s - %s.\n", __FUNCTION__, __LINE__, ifr.ifr_name, strerror(errno));
//        exit_level1_cleanup();
//        exit(rc);
//    }

    // Create the rx and tx queues for ingress interface
    if_config[INGRESS_IF].if_rxq.if_index  = INGRESS_IF;
    if_config[INGRESS_IF].if_rxq.if_thread = &dsl_threads[4];
    if ((if_config[INGRESS_IF].if_rxq.if_pkts   = circular_buffer_create(n_mbufs/(ingresscnt+egresscnt), mPool)) == CIRCULAR_BUFFER_INVALID) {
        log_msg(LOG_ERR, "%s-%d: Failure to create rx circular buffer for index 0.\n", __FUNCTION__, __LINE__);
        exit_level1_cleanup();
        exit(ENOMEM);
    }
    if (sem_init(&if_config[INGRESS_IF].if_rxq.if_ready, 0, 0) == -1) {
        rc = errno;
        log_msg(LOG_ERR, "%s-%d: Failure to create rx queue semaphore for index 0 - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
        exit_level1_cleanup();
        exit(rc);
    }
    if (q_control_on) {
        if_config[INGRESS_IF].if_rxq.q_control       = true;
        if_config[INGRESS_IF].if_rxq.q_control_cnt   = 0;
    } else if_config[INGRESS_IF].if_rxq.q_control    = false;
    if_config[INGRESS_IF].if_txq.if_index  = INGRESS_IF;
    if_config[INGRESS_IF].if_txq.if_thread = &dsl_threads[5];
    if ((if_config[INGRESS_IF].if_txq.if_pkts   = circular_buffer_create(n_mbufs/(ingresscnt+egresscnt), mPool)) == CIRCULAR_BUFFER_INVALID) {
        log_msg(LOG_ERR, "%s-%d: Failure to tx create circular buffer for index 0.\n", __FUNCTION__, __LINE__);
        exit_level1_cleanup();
        exit(ENOMEM);
    }
    if (sem_init(&if_config[INGRESS_IF].if_txq.if_ready, 0, 0) == -1) {
        rc = errno;
        log_msg(LOG_ERR, "%s-%d: Failure to create tx queue semaphore for index 0 - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
        exit_level1_cleanup();
        exit(rc);
    }
    if (q_control_on) {
        if_config[INGRESS_IF].if_txq.q_control       = true;
        if_config[INGRESS_IF].if_txq.q_control_cnt   = 0;
    } else if_config[INGRESS_IF].if_txq.q_control    = false;

    // Create timer to handle reorder buffer timeouts
    se.sigev_notify             = SIGEV_THREAD;
    se.sigev_value.sival_ptr    = &reorder_buf_timerid;
    se.sigev_notify_function    = reorder_buf_timer;
    se.sigev_notify_attributes  = NULL;
    if (timer_create(CLOCK_MONOTONIC, &se, &reorder_buf_timerid) == -1) {
        rc = errno;
        log_msg(LOG_ERR, "%s-%d: Failure to create reorder buffer timer - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
        exit_level1_cleanup();
        exit(rc);
    }
    reorder_buf_intvl.it_interval.tv_sec    = 0;
    reorder_buf_intvl.it_interval.tv_nsec   = 200 * ONE_MS;
    reorder_buf_intvl.it_value.tv_sec       = 0;
    reorder_buf_intvl.it_value.tv_nsec      = 200 * ONE_MS;

    // Convert server name to server ip address
    if (ipv6_mode) {
        if ((name_to_ip(remote_name, (struct sockaddr_storage *) &peer_addr6, AF_INET6)) != 0)
        {
            log_msg(LOG_ERR, "%s-%d: Could not translate hostname %s into ip address.\n", __FUNCTION__, __LINE__, remote_name);
            exit_level1_cleanup();
            exit(EINVAL);
        }
    } else {
        if ((name_to_ip(remote_name, (struct sockaddr_storage *) &peer_addr, AF_INET)) != 0)
        {
            log_msg(LOG_ERR, "%s-%d: Could not translate hostname %s into ip address.\n", __FUNCTION__, __LINE__, remote_name);
            exit_level1_cleanup();
            exit(EINVAL);
        }
    }

    // Start comms thread
    process_comms();

    if ((rc = reconnect_comms_to_server()) != 0) {
        exit_level1_cleanup();
        exit(rc);
    }
    
    // Handshake with server, send helo message and wait for ack.
    if (ipv6_mode) {
        memcpy(&client_query.helo_data.egress_addr[0], &if_config[0].if_ipaddr, sizeof(struct sockaddr_in6));
        memcpy(&client_query.helo_data.egress_addr[1], &if_config[1].if_ipaddr, sizeof(struct sockaddr_in6));
    } else {
        memcpy(&client_query.helo_data.egress_addr[0], &if_config[0].if_ipaddr, sizeof(struct sockaddr_in));
        memcpy(&client_query.helo_data.egress_addr[1], &if_config[1].if_ipaddr, sizeof(struct sockaddr_in));
    }
    client_query.helo_data.if_ratio[0]      = if_config[0].if_ratio;
    client_query.helo_data.if_ratio[1]      = if_config[1].if_ratio;
    client_query.helo_data.cc_port          = cc_port;
    client_query.for_peer                   = false;
    client_query.helo_data.ipv6_mode        = ipv6_mode;
    client_query.cmd                        = COMMS_HELO;
    send(comms_peer_fd, &client_query, sizeof(struct comms_query_s), 0);
    while((rc = recv(comms_peer_fd, &client_response, sizeof(struct comms_reply_s), 0) == -1) && (errno == EINTR));
    if (rc == -1) {
        rc = errno;
        log_msg(LOG_ERR, "%s-%d: Did not receive helo ack - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
        exit_level1_cleanup();
        exit(rc);
    }
    if (client_response.rc != 0) {
        log_msg(LOG_ERR, "%s-%d: Did not receive helo ack - rc=%d.\n", __FUNCTION__, __LINE__, client_response.rc);
    } else {
        log_msg(LOG_INFO, "Received HELO ack - rc=%d.\n", client_response.rc);
    }
    if_stats.num_interfaces = 3;
    if_stats.ipv6_mode      = ipv6_mode;
    for (i=0; i<if_stats.num_interfaces; i++) {
        strncpy(if_stats.if_name[i], if_config[i].if_txname, IFNAMSIZ);
    }

    // Start up the client threads
    if (create_threads()) {
        exit_level1_cleanup();
    	exit(EFAULT);
    }

    log_msg(LOG_INFO, "%s daemon started.\n", progname);
    
    // Go to sleep on a locked semaphore
    sem_init(&goodnight, 0, 0);
    sem_wait(&goodnight);
    
    exit(EFAULT);
}
