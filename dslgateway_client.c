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
#include <linux/netfilter.h>
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
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "circular_buffer.h"
#include "log.h"
#include "comms.h"
#include "util.h"
#include "dslgateway.h"


extern char                     *progname;
extern struct if_config_s       if_config[NUM_EGRESS_INTERFACES];
extern struct nf_queue_config_s nfq_config[NUM_NETFILTER_QUEUES];
extern unsigned int             egresscnt;
extern struct statistics_s      nf_stats;
extern int                      thread_exit_rc;
extern bool                     ipv6_mode;
extern void                     (*exit_level2_cleanup)(void);
extern void                     (*handle_comms_command)(struct comms_packet_s *query, struct comms_packet_s *reply,
                                    int comms_client_fd, bool *connection_active);

static bool                     is_daemon=false;
//static uint8_t                  pkt_seq_no=0;
//static struct mbuf_s            *reorder_buf[REORDER_BUF_SZ];
//static timer_t                  reorder_buf_timerid;
//static struct itimerspec        reorder_buf_intvl;
//static unsigned int             reorder_if_cnt[2] = {0, 0};
static struct sockaddr_in6      peer_addr6;
static struct sockaddr_in       peer_addr;
static bool                     debug=false;
static char                     config_file_name[PATH_MAX];
static char                     *remote_name=NULL;
static int                      comms_peer_fd=-1;
static unsigned int             cc_port=PORT;
static bool                     comms_addr_valid=false;
static char                     *comms_name=NULL;
static bool                     q_control_on=false;
static struct sockaddr_in6      comms_addr6;
static struct sockaddr_in       comms_addr;



//// +----------------------------------------------------------------------------
//// | Timer thread to drain reorder buf if packets have been there too long
//// +----------------------------------------------------------------------------
//static void reorder_buf_timer(union sigval arg)
//{
//    struct timespec     ts, tsdiff;
//    int                 i, j, k;
//
//    clock_gettime(CLOCK_MONOTONIC, &ts);
//    for (i=0; i<REORDER_BUF_SZ; i++) {
//        if (reorder_buf[i] != NULL) {
//            tsdiff = subtract_ts(&ts, &reorder_buf[i]->rx_time);
//            if (tsdiff.tv_sec || (tsdiff.tv_nsec > REORDER_BUF_TIMEOUT)) {
//                circular_buffer_push(if_config[INGRESS_IF].if_txq.if_pkts, reorder_buf[i]);
//                sem_post(&if_config[INGRESS_IF].if_txq.if_ready);
//                pkt_seq_no = reorder_buf[i]->seq_no + 1;
//                reorder_buf[i] = NULL;
//            } else break;
//        }
//    }
//    for (i=0; i<REORDER_BUF_SZ; i++) {
//        if (reorder_buf[i] != NULL) {
//            if (i != 0) {
//                for (j=i, k=0; j<REORDER_BUF_SZ; j++, k++) {
//                    reorder_buf[k] = reorder_buf[j];
//                    reorder_buf[j] = NULL;
//                }
//                break;
//            } else break;
//        }
//    }
//}
//
//
//// +----------------------------------------------------------------------------
//// | Start the reorder buffer timeout timer.
//// +----------------------------------------------------------------------------
//static void arm_reorder_buf_timer(void)
//{
//    reorder_buf_intvl.it_value.tv_sec   = reorder_buf_intvl.it_interval.tv_sec;
//    reorder_buf_intvl.it_value.tv_nsec  = reorder_buf_intvl.it_interval.tv_nsec;
//    timer_settime(reorder_buf_timerid, 0, &reorder_buf_intvl, NULL);
//}
//
//
//// +----------------------------------------------------------------------------
//// | Stop the reorder buffer timeout timer.
//// +----------------------------------------------------------------------------
//static void disarm_reorder_buf_timer(void)
//{
//    reorder_buf_intvl.it_value.tv_sec   = 0;
//    reorder_buf_intvl.it_value.tv_nsec  = 0;
//    timer_settime(reorder_buf_timerid, 0, &reorder_buf_intvl, NULL);
//}


// +----------------------------------------------------------------------------
// | do exit cleanup specific to the client
// +----------------------------------------------------------------------------
static void client_level2_cleanup()
{
    struct comms_packet_s    cya;


    // Tell server we are exiting
    if (comms_peer_fd > 0) {
        cya.cmd        = COMMS_CYA;
        send(comms_peer_fd, &cya, sizeof(struct comms_query_s), 0);
    }
}


// +----------------------------------------------------------------------------
// | Receive thread, one is started on each netfilter queue.
// +----------------------------------------------------------------------------
static void *rx_thread(void * arg)
{
    struct nf_queue_config_s    *nf_config = (struct nf_queue_config_s *) arg;
    struct mbuf_s               mbuf;
    int                         fd;

    if ((nf_config->qh = nfq_create_queue(nf_config->h, nf_config->nfq_q_no, nf_config->nfq_cb, NULL)) == NULL) {
        thread_exit_rc = errno;
        log_msg(LOG_ERR, "%s-%d: Error creating netfilter queue - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
        pthread_exit(&thread_exit_rc);
    }

    if (nfq_set_mode(nf_config->qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        thread_exit_rc = errno;
        log_msg(LOG_ERR, "%s-%d: Error setting copy mode on netfilter queue - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
        nfq_destroy_queue(nf_config->qh);
        nf_config->qh = NULL;
        pthread_exit(&thread_exit_rc);
    }

    fd = nfq_fd(nf_config->h);

    while (nf_config->nf_thread.keep_going) {
        while (((mbuf.len = recv(fd, &mbuf, sizeof(union mbuf_u), 0)) < 0) && (errno == EINTR));
        if (mbuf.len < 0) {
            if (errno == ENOBUFS) {
                nf_stats.nf_dropped_pkts_space[nf_config->nf_index]++;
                continue;
            } else {
                log_msg(LOG_ERR, "%s-%d: Error reading from netfilter queue %d - %s",
                        __FUNCTION__, __LINE__, nf_config->nfq_q_no, strerror(errno));
                continue;
            }
        }
        mbuf.nfq_index = nf_config->nf_index;

        // ignore packets from egress interfaces with if_ratio = 0
//        if ((rxq->if_index == EGRESS_IF || rxq->if_index == EGRESS_IF+1) && if_config[rxq->if_index].if_ratio == 0) {
//            nf_stats.if_dropped_pkts_ratio[rxq->if_index]++;
//            continue;
//        }

        clock_gettime(CLOCK_MONOTONIC, &mbuf.rx_time);
        nfq_handle_packet(nf_config->h, (char *) &mbuf, mbuf.len);
    }

    thread_exit_rc = 0;
    pthread_exit(&thread_exit_rc);
    return &thread_exit_rc;   // for compiler warnings
}


// +----------------------------------------------------------------------------
// | Do the packet mangling on the home gateway between the home network and the vps.
// +----------------------------------------------------------------------------
static int home_to_vps_pkt_mangler_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    struct mbuf_s               *mbuf = (struct mbuf_s *) data;
    uint8_t                     *if_ratios;
    unsigned char               *mbufc;
    unsigned int                active_if = 0;
    struct in6_addr             *sv_dest_addr6;
    struct ip6_hdr              *ip6hdr;
    struct in_addr              *sv_dest_addr;
    struct ip                   *iphdr;
    uint16_t                    *dest_port, *orig_dest_port;
    struct nfqnl_msg_packet_hdr    *ph;
    int                            pkt_id, rc;

    // For debugging purposes, we have queue control that will only let a set number
    // of packets through
    if (nfq_config[mbuf->nfq_index].q_control) {
        if (!nfq_config[mbuf->nfq_index].q_control_cnt) {
            nf_stats.nf_dropped_pkts_qcontrol[mbuf->nfq_index]++;
            return nfq_set_verdict(qh, 0, NF_DROP, 0, NULL);
        }
        nfq_config[mbuf->nfq_index].q_control_cnt--;
    }

    mbufc                   = (unsigned char *) mbuf;
    if ((ph    = nfq_get_msg_packet_hdr(nfa)) == NULL) {
        nf_stats.nf_dropped_pkts[mbuf->nfq_index]++;
        return nfq_set_verdict(qh, 0, NF_DROP, 0, NULL);
    }
    pkt_id = ntohl(ph->packet_id);

    // Save the destination address at the end of the packet and replace it with the
    // vps address. Save the destination port at the end of the packet and replace it
    // with the vps data port. Also save the if_ratios at the end of the packet.
    // Increase packet length by the length of the destination address plus the length
    // of the destination port plus 2 bytes for if_ratios.
    if (ipv6_mode) {
        ip6hdr                  = (struct ip6_hdr *) mbufc;
        if ((ip6hdr->ip6_nxt != IPPROTO_TCP) && (ip6hdr->ip6_nxt != IPPROTO_UDP)) {
            nf_stats.nf_dropped_pkts_proto[mbuf->nfq_index]++;
            return nfq_set_verdict(qh, pkt_id, NF_DROP, 0, NULL);
        }
        nf_stats.nf_rx_bytes[mbuf->nfq_index] += ip6hdr->ip6_plen;
        sv_dest_addr6           = (struct in6_addr *) (mbufc + sizeof(struct ip6_hdr) + ip6hdr->ip6_plen);
        dest_port                = (uint16_t *) (mbufc + sizeof(struct ip6_hdr)  + ip6hdr->ip6_plen + sizeof(sv_dest_addr6));
        if_ratios               = (uint8_t *) (mbufc + sizeof(struct ip6_hdr) + ip6hdr->ip6_plen + sizeof(sv_dest_addr6) + sizeof(dest_port));
        orig_dest_port            = (uint16_t *) (mbufc + sizeof(struct ip6_hdr) + 2);
        memcpy(sv_dest_addr6, &ip6hdr->ip6_dst, sizeof(struct in6_addr));
        memcpy(&ip6hdr->ip6_dst, &peer_addr6.sin6_addr, sizeof(struct in6_addr));
        ip6hdr->ip6_plen        = ip6hdr->ip6_plen + sizeof(sv_dest_addr6) + sizeof(dest_port) + 2;
        mbuf->len                = ip6hdr->ip6_plen;
    } else {
        iphdr                   = (struct ip *) mbufc;
        if ((iphdr->ip_p != IPPROTO_TCP) && (iphdr->ip_p != IPPROTO_UDP)) {
            nf_stats.nf_dropped_pkts_proto[mbuf->nfq_index]++;
            return nfq_set_verdict(qh, pkt_id, NF_DROP, 0, NULL);
        }
        nf_stats.nf_rx_bytes[mbuf->nfq_index] += iphdr->ip_len;
        sv_dest_addr            = (struct in_addr *) (mbufc + sizeof(struct ip) + iphdr->ip_len);
        dest_port                = (uint16_t *) (mbufc + sizeof(struct ip)  + iphdr->ip_len + sizeof(sv_dest_addr));
        if_ratios               = (uint8_t *) (mbufc + sizeof(struct ip) + iphdr->ip_len + sizeof(sv_dest_addr) + sizeof(dest_port));
        orig_dest_port            = (uint16_t *) (mbufc + sizeof(struct ip) + 2);
        memcpy(sv_dest_addr, &iphdr->ip_dst, sizeof(struct in_addr));
        iphdr->ip_dst.s_addr    = peer_addr.sin_addr.s_addr;
        iphdr->ip_len           = iphdr->ip_len + sizeof(sv_dest_addr) + sizeof(dest_port) + 2;
        iphdr->ip_sum           = iphdr_checksum((unsigned short*) mbufc, (sizeof(struct iphdr)/2));
        mbuf->len                = iphdr->ip_len;
    }
    if_ratios[0]            = if_config[0].if_ratio;
    if_ratios[1]            = if_config[1].if_ratio;
    *dest_port                = *orig_dest_port;
    *orig_dest_port              = if_config[active_if].if_port;
    rc                         = nfq_set_verdict2(qh, pkt_id, NF_ACCEPT, if_config[active_if].if_fwmark, mbuf->len, (char *) mbuf);
     active_if               = (active_if+1) % NUM_EGRESS_INTERFACES;
    nf_stats.nf_rx_pkts[mbuf->nfq_index]++;
     return rc;
}


//// +----------------------------------------------------------------------------
//// | Drain the reorder buf until a gap is found.
//// +----------------------------------------------------------------------------
//static void drain_reorder_buf(bool *reorder_active)
//{
//    int     i=0, j;
//
//    while ((reorder_buf[i] != NULL) && (i<REORDER_BUF_SZ)) {
//        circular_buffer_push(if_config[INGRESS_IF].if_txq.if_pkts, reorder_buf[i]);
//        sem_post(&if_config[INGRESS_IF].if_txq.if_ready);
//        pkt_seq_no++;
//        reorder_buf[i] = NULL;
//        i++;
//    }
//    *reorder_active = false;
//    reorder_if_cnt[0] = reorder_if_cnt[1] = 0;
//    if (i<REORDER_BUF_SZ) {
//        for (i=i+1, j=0; i<REORDER_BUF_SZ; i++, j++) {
//            reorder_buf[j] = reorder_buf[i];
//            if (reorder_buf[i] != NULL) {
//                *reorder_active = true;
//                reorder_if_cnt[reorder_buf[j]->if_index]++;
//            }
//            reorder_buf[i] = NULL;
//        }
//    }
//    if (!reorder_active) disarm_reorder_buf_timer();
//}
//
//
//// +----------------------------------------------------------------------------
//// | Completely drain the reorder buf.
//// +----------------------------------------------------------------------------
//static void force_drain_reorder_buf(void)
//{
//    int i;
//
//    if_config[0].if_ratio = reorder_if_cnt[0];
//    if_config[1].if_ratio = reorder_if_cnt[1];
//    for (i=0; i<REORDER_BUF_SZ; i++) {
//        if (reorder_buf[i] != NULL) {
//            circular_buffer_push(if_config[INGRESS_IF].if_txq.if_pkts, reorder_buf[i]);
//            sem_post(&if_config[INGRESS_IF].if_txq.if_ready);
//            reorder_buf[i] = NULL;
//        }
//    }
//    reorder_if_cnt[0] = reorder_if_cnt[1] = 0;
//}
//
//
//// +----------------------------------------------------------------------------
//// | Do the packet mangling on the home gateway between the vps and the home network.
//// +----------------------------------------------------------------------------
//static void *home_from_vps_pkt_mangler_thread(void * arg)
//{
//    struct mbuf_s   *mbuf;
//    uint8_t         *seq_no;
//    int             seq_diff;
//    unsigned char   *mbufc;
//    unsigned int    i;
//    bool            reorder_active=false;
//    struct in6_addr *sv_dest_addr6;
//    struct ip6_hdr  *ip6hdr;
//    struct in_addr  *sv_dest_addr;
//    struct ip       *iphdr;
//
//    for (i=0; i<REORDER_BUF_SZ; i++) reorder_buf[i] = NULL;
//    while (dsl_threads[HOME_FROM_VPS_PKT_MANGLER_THREADNO].keep_going) {
//        sem_wait(&if_config[EGRESS_IF].if_rxq.if_ready);
//        if ((mbuf = circular_buffer_pop(if_config[EGRESS_IF].if_rxq.if_pkts)) == NULL) continue;
//        mbufc                   = (unsigned char *) mbuf;
//        if (mbuf->ipv6) {
//            ip6hdr                  = (struct ip6_hdr *) (mbufc + sizeof(struct ether_header));
//            sv_dest_addr6           = (struct in6_addr *) (mbufc + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + ip6hdr->ip6_plen);
//            seq_no                  = (uint8_t *) (mbufc + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + ip6hdr->ip6_plen + sizeof(struct in6_addr));
//            memcpy(ip6hdr->ip6_dst.s6_addr, sv_dest_addr6, sizeof(struct in6_addr));
//            ip6hdr->ip6_plen        = ip6hdr->ip6_plen - sizeof(struct in6_addr) - 1;
//        } else {
//        iphdr                   = (struct ip *) (mbufc + sizeof(struct ether_header));
//            sv_dest_addr            = (struct in_addr *) (mbufc + sizeof(struct ether_header) + iphdr->ip_len);
//            seq_no                  = (uint8_t *) (mbufc + sizeof(struct ether_header) + iphdr->ip_len + sizeof(struct in_addr));
//            memcpy(&iphdr->ip_dst, sv_dest_addr, sizeof(struct in_addr));
//            iphdr->ip_len           = iphdr->ip_len - sizeof(struct in_addr) - 1;
//            iphdr->ip_sum           = iphdr_checksum((unsigned short*)(mbufc + sizeof(struct ether_header)), (sizeof(struct iphdr)/2));
//        }
//        seq_diff                = *seq_no - pkt_seq_no;
//        if (seq_diff < 0) seq_diff = (255 - pkt_seq_no) + *seq_no + 1;
//        if (seq_diff > 0) {
//            if (seq_diff > REORDER_BUF_SZ) {
//                // Packet we are waiting for is late, drain reorder buffer and let the tcp
//                // layer deal with it.
//                pkt_seq_no++;
//                drain_reorder_buf(&reorder_active);
//                seq_diff        = *seq_no - pkt_seq_no;
//                if (seq_diff < 0) seq_diff = (255 - pkt_seq_no) + *seq_no + 1;
//                if (seq_diff > 0) {
//                    // There are multiple packets that are late, force drain the reorder
//                    // buffer and let the tcp layer deal with it.
//                    force_drain_reorder_buf();
//                    pkt_seq_no = *seq_no;
//                    reorder_active  = false;
//                    disarm_reorder_buf_timer();
//                    nf_stats.reorder_failures++;
//                }
//            } else {
//                if (!reorder_active) {
//                    // Start a timer to clear packets from reorder buffer if they have been
//                    // there too long.
//                    arm_reorder_buf_timer();
//                }
//                reorder_buf[seq_diff-1] = mbuf;
//                reorder_active          = true;
//                reorder_if_cnt[mbuf->if_index]++;
//                nf_stats.reorders++;
//                continue;
//            }
//        }
//        circular_buffer_push(if_config[INGRESS_IF].if_txq.if_pkts, mbuf);
//        sem_post(&if_config[INGRESS_IF].if_txq.if_ready);
//        pkt_seq_no++;
//        // Send any additional packets that were accumulating in the reorder buffer
//        if (reorder_active) drain_reorder_buf(&reorder_active);
//    }
//
//    thread_exit_rc = 0;
//    pthread_exit(&thread_exit_rc);
//    return &thread_exit_rc;  // for compiler warnings
//}


// +----------------------------------------------------------------------------
// | Create all the client threads
// +----------------------------------------------------------------------------
static int create_threads(void)
{
    int rc;

    snprintf(nfq_config[INGRESS_NFQ].nf_thread.thread_name, 16, "rx_thread%2u", nfq_config[0].nfq_q_no);
    if ((rc = create_thread(&nfq_config[INGRESS_NFQ].nf_thread.thread_id, rx_thread, RXPRIO, nfq_config[INGRESS_NFQ].nf_thread.thread_name, (void *) &nfq_config[INGRESS_NFQ])) != 0) {
        log_msg(LOG_ERR, "%s-%d: Can not create rx thread for ingress netfilter queue - %s.\n", __FUNCTION__, __LINE__, strerror(rc));
        return rc;
    }
    return 0;
}

// +----------------------------------------------------------------------------
// | Handle a query on the comms socket
// +----------------------------------------------------------------------------
static void handle_client_command(struct comms_packet_s *query, struct comms_packet_s *reply,
        int comms_client_fd, bool *connection_active)
{

//    log_debug_msg(LOG_INFO, "Received request %02x.\n", query->cmd);
	switch (query->cmd){
		case COMMS_GETSTATS:
			memcpy(&reply->pyld.rply.stats, &nf_stats, sizeof(struct statistics_s));
			reply->pyld.rply.rc    = 0;
			break;
		case COMMS_KILL:
			reply->pyld.rply.rc        = 0;
			reply->pyld.rply.is_client = true;
			send(comms_client_fd, reply, sizeof(struct comms_packet_s), 0);
			exit_level1_cleanup();
			exit(EXIT_SUCCESS);
			break;
		case COMMS_EXIT:
			*connection_active  = false;
			break;
		case COMMS_SET_QCONTROL:
			if (query->pyld.qry.q_control_cnt == -1) {
				nfq_config[query->pyld.qry.q_control_index].q_control      = false;
			} else {
				nfq_config[query->pyld.qry.q_control_index].q_control_cnt  = query->pyld.qry.q_control_cnt;
				nfq_config[query->pyld.qry.q_control_index].q_control      = true;
			}
			reply->pyld.rply.rc            = 0;
			break;
		default:
			log_debug_msg(LOG_INFO, "Received invalid request.\n");
			reply->pyld.rply.rc    = -1;
	}
	reply->pyld.rply.is_client = true;
}


// +----------------------------------------------------------------------------
// | Read the config file and set all the appropriate variables from the values.
// +----------------------------------------------------------------------------
static void read_config_file(void)
{
    config_t                cfg;
    const config_setting_t  *config_list;
    const char              *config_string=NULL;
    int                     i;

    config_init(&cfg);

    if (!config_read_file(&cfg, config_file_name)) {
        log_msg(LOG_ERR, "%s-%d: Error reading config file, all parameters revert to defaults.\n", __FUNCTION__, __LINE__);
        return;
    }

    if (config_lookup_int(&cfg, "comms_port", &cc_port))
        log_msg(LOG_INFO, "Configured for comms port on %d.\n", cc_port);
    if (config_lookup_int(&cfg, "ipversion", &i)) {
        if (i == 6) ipv6_mode = true;
        log_msg(LOG_INFO, "Configured for %s.\n", ipv6_mode ? "ipv6" : "ipv4");
    }
    if (config_lookup_bool(&cfg, "qcontrol", &i)) {
        q_control_on = i;
        log_msg(LOG_INFO, "Configured for debugging queue control %s.\n", q_control_on ? "on" : "off");
    }
    config_list = config_lookup(&cfg, "data_port");
    for (i=0; i<config_setting_length(config_list); i++) {
        if (i == NUM_NETFILTER_QUEUES) break;
        if_config[i].if_port = config_setting_get_int_elem(config_list, i);
        log_msg(LOG_INFO, "Configured for data port on %u.\n", if_config[i].if_port);
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
    if (config_lookup_string(&cfg, "client.server_name", &config_string)) {
        if ((remote_name = malloc(strlen(config_string)+1)) == NULL) {
            log_msg(LOG_ERR, "%s-%d: Out of memory.\n", __FUNCTION__, __LINE__);
            exit(ENOMEM);
        }
        strcpy(remote_name, config_string);
        log_msg(LOG_INFO, "Configured for server name %s.\n", remote_name);
    }
    config_list = config_lookup(&cfg, "client.egress.interface");
    for (i=0; i<config_setting_length(config_list); i++) {
        if (i == NUM_EGRESS_INTERFACES) break;
        egresscnt++;
        strcpy(if_config[i].if_name, config_setting_get_string_elem(config_list, i));
        log_msg(LOG_INFO, "Configured for client egress interface on %s.\n", if_config[i].if_name);
    }
    config_list = config_lookup(&cfg, "client.egress.ratio");
    for (i=0; i<config_setting_length(config_list); i++) {
        if (i == egresscnt) break;
        if_config[i].if_ratio = config_setting_get_int_elem(config_list, i);
        log_msg(LOG_INFO, "Configured for client egress interface ratio of %u on %s.\n", if_config[i].if_ratio, if_config[i].if_name);
    }
    config_list = config_lookup(&cfg, "client.egress.fwmark");
    for (i=0; i<config_setting_length(config_list); i++) {
        if (i == egresscnt) break;
        if_config[i].if_fwmark = config_setting_get_int_elem(config_list, i);
        log_msg(LOG_INFO, "Configured for client egress interface fwmark of %u on %s.\n", if_config[i].if_fwmark, if_config[i].if_name);
    }
    if (config_lookup_int(&cfg, "client.egress.nf_q_no", &nfq_config[EGRESS_NFQ].nfq_q_no)) {
        log_msg(LOG_INFO, "Configured for egress netfilter queue on %u.\n", nfq_config[EGRESS_NFQ].nfq_q_no);
    }
    if (config_lookup_int(&cfg, "client.ingress.nf_q_no", &nfq_config[INGRESS_NFQ].nfq_q_no)) {
        log_msg(LOG_INFO, "Configured for ingress netfilter queue on %u.\n", nfq_config[INGRESS_NFQ].nfq_q_no);
    }

    config_destroy(&cfg);
}


// +----------------------------------------------------------------------------
// | Process packets from server received on the two data port connections. This
// | function calculates the transmission times on each of the egress interfaces.
// +----------------------------------------------------------------------------
static bool process_data_port_packet(int fd, int ifindex)
{
    struct data_port_ping_s        data_port_ping;
    int                            rc;

    while (((rc = recv(fd, &data_port_ping, sizeof(data_port_ping), 0)) == -1) && (errno == EINTR));
    if (rc == 0) {
        log_msg(LOG_WARNING, "Closing data port connections.\n");
        close(if_config[EGRESS_IF].if_peer_fd);
        close(if_config[EGRESS_IF+1].if_peer_fd);
        return false;
    }
    if (rc > 0) {
        if (rc != sizeof(data_port_ping)) {
            log_msg(LOG_INFO, "Data port packet dropped - invalid size %d.\n", rc);
        } else {
            log_msg(LOG_INFO, "Received data port packet from port %u.\n", if_config[ifindex].if_port);
        }
    } else {
        log_msg(LOG_WARNING, "Data port receive returns %s.\n", strerror(errno));
    }
    return true;
}


// +----------------------------------------------------------------------------
// | Open a socket and connect to peer
// +----------------------------------------------------------------------------
static int connect_to_server(struct sockaddr_storage *addr, socklen_t addr_sz, sa_family_t ip_family) {
    int            rc, fd;

    if ((fd = socket(ip_family, SOCK_STREAM, 0)) < 0) {
        rc = -1*errno;
        log_msg(LOG_ERR, "%s-%d: Can not create socket - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
        return rc;
    }

    if (connect(fd, (struct sockaddr *) addr, addr_sz) < 0) {
        rc = -1*errno;
        log_msg(LOG_ERR, "%s-%d: Not connected - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
        return rc;
    }

    return fd;
}

// +----------------------------------------------------------------------------
// | Connect to the server on the comms port
// +----------------------------------------------------------------------------
static int reconnect_comms_to_server(void)
{

    log_debug_msg(LOG_INFO, "%s-%d\n", __FUNCTION__, __LINE__);
    if (comms_peer_fd > -1) close(comms_peer_fd);

    // Convert server name to server ip address
    if (ipv6_mode) {
        if ((name_to_ip(comms_name, (struct sockaddr_storage *) &comms_addr6, AF_INET6)) != 0)
        {
            log_msg(LOG_ERR, "%s-%d: Could not translate hostname %s into ip address.\n", __FUNCTION__, __LINE__, comms_name);
            return -EINVAL;
        }
        comms_addr6.sin6_port       = htons((unsigned short)cc_port);
        log_msg(LOG_INFO, "Waiting for connection to server %s on port %u...", comms_name, cc_port);
        if ((comms_peer_fd = connect_to_server((struct sockaddr_storage *) &comms_addr6, sizeof(comms_addr6), AF_INET6)) < 0) {
            log_msg(LOG_INFO, "Not connected.\n");
            return comms_peer_fd;
        }
    } else {
        if ((name_to_ip(comms_name, (struct sockaddr_storage *) &comms_addr, AF_INET)) != 0)
        {
            log_msg(LOG_ERR, "%s-%d: Could not translate hostname %s into ip address.\n", __FUNCTION__, __LINE__, comms_name);
            return -EINVAL;
        }
        comms_addr.sin_port        = htons((unsigned short)cc_port);
        log_msg(LOG_INFO, "Waiting for connection to server %s on port %u...", comms_name, cc_port);
        if ((comms_peer_fd = connect_to_server((struct sockaddr_storage *) &comms_addr, sizeof(comms_addr), AF_INET)) < 0) {
            log_msg(LOG_INFO, "Not connected.\n");
            return comms_peer_fd;
        }
    }
    log_msg(LOG_INFO, "Connected.\n");

    comms_addr_valid = true;
    return 0;
}


// +----------------------------------------------------------------------------
// | Main processing.
// +----------------------------------------------------------------------------
int main(int argc, char *argv[])
{
    int                         option, i, j, rc, readset_fd;
    bool                        daemonize=true, keep_going=true;
    pid_t                       pid, sid;
    struct sigaction            sigact;
    struct sched_param          sparam;
//    struct sigevent             se;
    struct comms_packet_s       client_query;
    struct comms_packet_s       client_response;
    char                        ipaddr[INET6_ADDRSTRLEN];
    fd_set                      readset;

    i=0;
    if (argv[0][0] == '.' || argv[0][0] == '/') i++;
    if (argv[0][1] == '.' || argv[0][1] == '/') i++;
    progname = &argv[0][i];

    memset(config_file_name, 0, PATH_MAX);
    strcpy(config_file_name, DEFAULT_CONFIG_FILE_NAME);

    for (i=0; i<NUM_EGRESS_INTERFACES; i++) {
        memset(&if_config[i], 0, sizeof(struct if_config_s));
    }
    for (i=0; i<NUM_NETFILTER_QUEUES; i++) {
        memset(&nfq_config[i], 0, sizeof(struct nf_queue_config_s));
    }
    memset(&nf_stats, 0, sizeof(struct statistics_s));

    // Setup the client exit cleanup function
    exit_level2_cleanup = client_level2_cleanup;

    // Setup the comms packet command handler
    handle_comms_command = handle_client_command;

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

    // Get ip addresses of all the egress interfaces
    //get_ip_addrs();

    // Create timer to handle reorder buffer timeouts
//    se.sigev_notify             = SIGEV_THREAD;
//    se.sigev_value.sival_ptr    = &reorder_buf_timerid;
//    se.sigev_notify_function    = reorder_buf_timer;
//    se.sigev_notify_attributes  = NULL;
//    if (timer_create(CLOCK_MONOTONIC, &se, &reorder_buf_timerid) == -1) {
//        rc = errno;
//        log_msg(LOG_ERR, "%s-%d: Failure to create reorder buffer timer - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
//        exit_level1_cleanup();
//        exit(rc);
//    }
//    reorder_buf_intvl.it_interval.tv_sec    = 0;
//    reorder_buf_intvl.it_interval.tv_nsec   = 200 * ONE_MS;
//    reorder_buf_intvl.it_value.tv_sec       = 0;
//    reorder_buf_intvl.it_value.tv_nsec      = 200 * ONE_MS;

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
    //process_comms();

    while ((rc = reconnect_comms_to_server()) != 0) sleep(5);

    // Initialize netfilter queue config
    nfq_config[INGRESS_NFQ].nfq_cb                    = &home_to_vps_pkt_mangler_cb;
    nfq_config[INGRESS_NFQ].nf_index                = INGRESS_NFQ;
    nfq_config[INGRESS_NFQ].nf_thread.keep_going    = true;
    if (q_control_on) {
        nfq_config[INGRESS_NFQ].q_control            = true;
        nfq_config[INGRESS_NFQ].q_control_cnt        = 0;
    }
    else {
        nfq_config[INGRESS_NFQ].q_control            = false;
    }
    if ((nfq_config[INGRESS_NFQ].h = nfq_open()) == NULL) {
        rc = errno;
        log_msg(LOG_ERR, "%s-%d: Error opening netfilter queue - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
        exit_level1_cleanup();
        exit(rc);
    }

    if (ipv6_mode) {
        if (nfq_unbind_pf(nfq_config[INGRESS_NFQ].h, AF_INET6) < 0) {
            rc = errno;
            log_msg(LOG_ERR, "%s-%d: Error unbinding from netfilter queue - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
            exit_level1_cleanup();
            exit(rc);
        }
        if (nfq_bind_pf(nfq_config[INGRESS_NFQ].h, AF_INET6) < 0) {
            rc = errno;
            log_msg(LOG_ERR, "%s-%d: Error binding to netfilter queue - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
            exit_level1_cleanup();
            exit(rc);
        }
    } else {
        if (nfq_unbind_pf(nfq_config[INGRESS_NFQ].h, AF_INET) < 0) {
            rc = errno;
            log_msg(LOG_ERR, "%s-%d: Error unbinding from netfilter queue - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
            exit_level1_cleanup();
            exit(rc);
        }
        if (nfq_bind_pf(nfq_config[INGRESS_NFQ].h, AF_INET) < 0) {
            rc = errno;
            log_msg(LOG_ERR, "%s-%d: Error binding to netfilter queue - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
            exit_level1_cleanup();
            exit(rc);
        }
    }

//    nfq_config[EGRESS_NFQ].nfq_cb                    = &home_to_vps_pkt_mangler_cb;
//    nfq_config[EGRESS_NFQ].nf_index                    = EGRESS_NFQ;
//    nfq_config[EGRESS_NFQ].nf_thread.keep_going        = true;
    nfq_config[EGRESS_NFQ].h                        = nfq_config[INGRESS_NFQ].h;
    if (q_control_on) {
        nfq_config[EGRESS_NFQ].q_control            = true;
        nfq_config[EGRESS_NFQ].q_control_cnt        = 0;
    }
    else {
        nfq_config[EGRESS_NFQ].q_control            = false;
    }

    // Handshake with server, send helo message and wait for ack.
    if (ipv6_mode) {
        memcpy(&client_query.pyld.qry.helo_data.egress_addr[0], &if_config[0].if_ipaddr, sizeof(struct sockaddr_in6));
        memcpy(&client_query.pyld.qry.helo_data.egress_addr[1], &if_config[1].if_ipaddr, sizeof(struct sockaddr_in6));
    } else {
        memcpy(&client_query.pyld.qry.helo_data.egress_addr[0], &if_config[0].if_ipaddr, sizeof(struct sockaddr_in));
        memcpy(&client_query.pyld.qry.helo_data.egress_addr[1], &if_config[1].if_ipaddr, sizeof(struct sockaddr_in));
    }
    client_query.pyld.qry.helo_data.if_ratio[0] = if_config[0].if_ratio;
    client_query.pyld.qry.helo_data.if_ratio[1] = if_config[1].if_ratio;
    client_query.pyld.qry.helo_data.cc_port     = cc_port;
    client_query.pyld.qry.for_peer              = false;
    client_query.pyld.qry.helo_data.ipv6_mode   = ipv6_mode;
    client_query.cmd                        	= COMMS_HELO;
    send_comms_pkt(comms_peer_fd, &client_query, sizeof(struct comms_packet_s));
    while((rc = recv(comms_peer_fd, &client_response, sizeof(struct comms_reply_s), 0) == -1) && (errno == EINTR));
    if (rc == -1) {
        rc = errno;
        log_msg(LOG_ERR, "%s-%d: Did not receive helo ack - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
        exit_level1_cleanup();
        exit(rc);
    }
    if (client_response.pyld.rply.rc != 0) {
        log_msg(LOG_ERR, "%s-%d: Did not receive helo ack - rc=%d.\n", __FUNCTION__, __LINE__, client_response.pyld.rply.rc);
    } else {
        log_msg(LOG_INFO, "Received HELO ack - rc=%d.\n", client_response.pyld.rply.rc);
    }
    nf_stats.ipv6_mode      = ipv6_mode;

    // Start up the client threads
    if (create_threads()) {
        exit_level1_cleanup();
        exit(EFAULT);
    }

    for (;;) {
        log_msg(LOG_INFO, "Waiting for data port connections.\n");
        // Accept the data port connections
        for (i=0; i<NUM_EGRESS_INTERFACES; i++) {
            if (ipv6_mode) {
                if_config[i].if_sin_size = sizeof(if_config[i].if_peer_client_addr6);
                if ((if_config[i].if_peer_fd = accept(if_config[i].if_fd, (struct sockaddr *)&if_config[i].if_peer_client_addr6, &if_config[i].if_sin_size)) < 0) {
                    log_msg(LOG_ERR, "%s-%d: Error accepting peer data connection - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
                    continue;
                }
                inet_ntop(AF_INET6, get_in_addr((struct sockaddr *)&if_config[i].if_peer_client_addr6), ipaddr, sizeof ipaddr);
                if (memcmp(&if_config[i].if_peer_client_addr6.sin6_addr, &peer_addr6.sin6_addr, sizeof(struct in6_addr)) != 0) {
                    log_msg(LOG_INFO, "Closing connection from unknown host %s.\n", ipaddr);
                    close(if_config[i].if_peer_fd);
                    continue;
                }
                log_msg(LOG_INFO, "Accepted peer data connection from %s on port %u.\n", ipaddr, if_config[i].if_port);
                if_config[i].if_peer_client_addr6.sin6_port = if_config[i].if_port;
                for (j=0; j<5; j++) {
                    if ((if_config[i].if_peer_fd = connect_to_server((struct sockaddr_storage *)&if_config[i].if_peer_client_addr6, sizeof(struct sockaddr_in6), AF_INET6)) < 0) {
                        sleep(2);
                        log_msg(LOG_INFO, "Retrying data connection to server.\n");
                    }
                    else break;
                }
            } else {
                if_config[i].if_sin_size = sizeof(if_config[i].if_peer_client_addr);
                if ((if_config[i].if_peer_fd = accept(if_config[i].if_fd, (struct sockaddr *)&if_config[i].if_peer_client_addr, &if_config[i].if_sin_size)) < 0) {
                    log_msg(LOG_ERR, "%s-%d: Error accepting peer data connection - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
                    continue;
                }
                inet_ntop(AF_INET6, get_in_addr((struct sockaddr *)&if_config[i].if_peer_client_addr), ipaddr, sizeof ipaddr);
                if (if_config[i].if_peer_client_addr.sin_addr.s_addr != peer_addr.sin_addr.s_addr) {
                    log_msg(LOG_INFO, "Closing connection from unknown host %s.\n", ipaddr);
                    close(if_config[i].if_peer_fd);
                    continue;
                }
                log_msg(LOG_INFO, "Accepted peer data connection from %s on port %u.\n", ipaddr, if_config[i].if_port);
                if_config[i].if_peer_client_addr.sin_port = if_config[i].if_port;
                for (j=0; j<5; j++) {
                    if ((if_config[i].if_peer_fd = connect_to_server((struct sockaddr_storage *)&if_config[i].if_peer_client_addr, sizeof(struct sockaddr_in), AF_INET)) < 0) {
                        sleep(2);
                        log_msg(LOG_INFO, "Retrying data connection to server.\n");
                    }
                    else break;
                }
            }
        }

        if (if_config[EGRESS_IF].if_peer_fd < 0 || if_config[EGRESS_IF+1].if_peer_fd < 0) {
            log_msg(LOG_ERR, "Can not establish data connections to server.\n");
            exit_level1_cleanup();
            exit(EFAULT);
        }

        if (if_config[EGRESS_IF].if_peer_fd > if_config[EGRESS_IF+1].if_peer_fd) readset_fd = if_config[EGRESS_IF].if_peer_fd;
        else                                                                     readset_fd = if_config[EGRESS_IF+1].if_peer_fd;

        log_msg(LOG_INFO, "%s daemon started.\n", progname);

        // Process data connection ping packets
        while (keep_going) {
            FD_ZERO(&readset);
            FD_SET(if_config[EGRESS_IF].if_peer_fd, &readset);
            FD_SET(if_config[EGRESS_IF+1].if_peer_fd, &readset);
            while (((rc = select(readset_fd + 1, &readset, NULL, NULL, NULL)) == -1) && (errno == EINTR));
            if (rc == -1) {
                log_msg(LOG_WARNING, "Select returns %s.\n", strerror(errno));
                continue;
            }
            if (FD_ISSET(if_config[EGRESS_IF].if_peer_fd, &readset)) {
                keep_going = process_data_port_packet(if_config[EGRESS_IF].if_peer_fd, EGRESS_IF);
            }
            if (FD_ISSET(if_config[EGRESS_IF+1].if_peer_fd, &readset)) {
                keep_going = process_data_port_packet(if_config[EGRESS_IF+1].if_peer_fd, EGRESS_IF+1);
            }
        }
        keep_going = true;
    }

    exit_level1_cleanup();
    exit(EFAULT);
}
