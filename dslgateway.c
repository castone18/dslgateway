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
// |    This file implements a dsl gateway that splits outgoing IP traffic between
// | two DSL lines. This program is used in rural settings where DSL speeds are low.
// | It allows two DSL lines of differing speeds to be bonded into a single internet
// | connection, providing the sum of the two lines internet bandwidth minus a small
// | overhead. The normal scenario is that this program is run on an internet gateway
// | computer in the home and it connects to a VPS running the same program. In this code,
// | the copy on the home gateway is called the client, and the copy on the VPS
// | is called the server. This code implements the server, see dslgateway_client.c
// | for the client.
// |
// | This program has a few features that make it better suited than the standard
// | ethernet bonding driver in the Linux kernel. Those features are:
// |     1. The bonding adjusts in real time for DSL lines with changing bit rates.
// |        DSL bit rates with some providers can vary up to 3k throughout the day,
// |        and this program will adjust for that by automatically sending more bits
// |        over the faster line and constantly adapting to line rate.
// |     2. This program will automatically disable and re-enable packet transfer
// |        over DSL links when they drop and come back.
// |     3. Traffic to configurable sites can be routed directly to the ISP
// |        instead of the VPS server. This is useful for Netflix, for instance,
// |        because Netflix will not allow traffic from VPS servers in the cloud.
// |        Since the home gateway computer will have two ppp connections to the
// |        ISP, this program can route traffic through the ISP instead of the
// |        cloud, with the caveat that traffic routed directly to the ISP can only
// |        use the speed of one of the DSL lines. This feature is better than using
// |        iptables and routing configuration in the kernel, because the program will
// |        automatically adjust the amount of other traffic going over the line that Netflix
// |        is using. For instance, with two 6Mbs DSL connections, if Netflix is
// |        routed over one of them, it will consume almost all the bandwidth on
// |        that connection. This program will adjust by routing all other traffic
// |        over the other line. Then when Netflix traffic ends, both lines are
// |        used again.
// |     4. This program does not encapsulate tcp packets inside other tcp packets.
// |        The overhead of this program is only 6 bytes per packet with IPv4, compared
// |        to 40 bytes when tcp is encapsulated in tcp. Due to the size of the
// |        IPv6 address, the overhead for IPv6 is 18 bytes, but that is still much
// |        lower than 60 bytes for tcp encapsulated in tcp with IPv6.
// |
// +----------------------------------------------------------------------------


//  log_msg(LOG_INFO, "%s-%d\n", __FUNCTION__, __LINE__);

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
extern mempool                  mPool;
extern bool                     wipebufs;
extern int                      comms_peer_fd;
extern struct statistics_s      if_stats;
extern unsigned int             cc_port, rmt_port;
extern struct thread_list_s     dsl_threads[((NUM_INGRESS_INTERFACES+NUM_EGRESS_INTERFACES)*2)+2];
extern int                      thread_exit_rc;
extern bool                     comms_addr_valid;
extern unsigned int             n_mbufs;
static bool                     is_daemon;
extern char                     *comms_name;
extern bool                     ipv6_mode;
extern bool                     q_control_on;

static uint8_t                  pkt_seq_no=0;
static unsigned int             num_threads;
static struct sockaddr_storage  client_addr[NUM_EGRESS_INTERFACES];
static struct sockaddr_in6      *client_addr6[NUM_EGRESS_INTERFACES] = {(struct sockaddr_in6 *) &client_addr[0], (struct sockaddr_in6 *) &client_addr[1]};
static struct sockaddr_in       *client_addr4[NUM_EGRESS_INTERFACES] = {(struct sockaddr_in *) &client_addr[0], (struct sockaddr_in *) &client_addr[1]};
static bool                     client_addr_valid=false;
static bool                     debug=false;
static char                     config_file_name[PATH_MAX];


// +----------------------------------------------------------------------------
// | Server interface receive thread.
// +----------------------------------------------------------------------------
static void *rx_thread(void * arg)
{
    struct if_queue_s   *rxq = (struct if_queue_s *) arg;
    struct mbuf_s       *mbuf=NULL;
    unsigned char       *mbufc;
    ssize_t             rxSz;
    struct ether_header *ethhdr;
    uint8_t             broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    struct ip6_hdr      *ip6hdr;
    int                 i;
    struct ip           *iphdr;

    while (rxq->if_thread->keep_going) {
        if (mbuf == NULL) mbuf = (struct mbuf_s*) mempool_alloc(mPool);
        if (mbuf == NULL) {
            log_msg(LOG_WARNING, "%s-%d: Out of mbufs, will wait and try again.\n", __FUNCTION__, __LINE__);
            sleep(1);
            continue;
        }
        // TODO: deal with partial packet receipt
        while (((rxSz = read(if_config[rxq->if_index].if_rx_fd, (void *) mbuf, sizeof(union mbuf_u))) < 0) && (errno == EINTR));
        if (rxSz < 0) {
            log_msg(LOG_ERR, "%s-%d: Error reading raw packets from interface %s - %s",
                    __FUNCTION__, __LINE__, if_config[rxq->if_index].if_name, strerror(errno));
            continue;
        }
        mbuf->if_index = rxq->if_index;
        switch (mbuf->pkt.tcp_pkt.eth_hdr.ether_type) {
            case ETHERTYPE_IPV6:
                if (!ipv6_mode) {
                    // not ipv6 mode so drop the packet
                    if_stats.if_dropped_pkts[rxq->if_index]++;
                    continue;
                }
                mbuf->ipv6 = true;
                break;
            case ETHERTYPE_IP:
                if (ipv6_mode) {
                    // not ipv4 mode so drop the packet
                    if_stats.if_dropped_pkts[rxq->if_index]++;
                    continue;
                }
                mbuf->ipv6 = false;
                break;
            default:
                if_stats.if_dropped_pkts[rxq->if_index]++;
                continue;
        }
        mbufc = (unsigned char *) mbuf;
        clock_gettime(CLOCK_MONOTONIC, &mbuf->rx_time);

        // ignore packets from egress interfaces with if_ratio = 0
        if ((rxq->if_index == EGRESS_IF || rxq->if_index == EGRESS_IF+1) && if_config[rxq->if_index].if_ratio == 0) {
            if_stats.if_dropped_pkts[rxq->if_index]++;
            continue;
        }

        // ignore broadcast packets
        ethhdr = (struct ether_header *) mbufc;
        if (memcmp(ethhdr->ether_dhost, broadcast_mac, 6) == 0) {
            if_stats.if_dropped_pkts[rxq->if_index]++;
            continue;
        }


        if (mbuf->ipv6) {
            ip6hdr = (struct ip6_hdr *) (mbufc + sizeof(struct ether_header));
            if (!client_addr_valid) {
                if_stats.if_dropped_pkts[rxq->if_index]++;
                continue;
            }
            if (ip6hdr->ip6_src.s6_addr[11] == 0xFF && ip6hdr->ip6_src.s6_addr[12] == 0xFE) {
                // this packet came from home gateway
                mbuf->for_home = false;
            } else {
                mbuf->for_home = true;
            }
        } else {
            iphdr = (struct ip *) (mbufc + sizeof(struct ether_header));
            for (i=0; i<3; i++) {
                mbuf->for_home = false;
                if (!client_addr_valid) {
                    if_stats.if_dropped_pkts[rxq->if_index]++;
                    continue;
                }
                if ((iphdr->ip_dst.s_addr == client_addr4[i]->sin_addr.s_addr) || (iphdr->ip_dst.s_addr == client_addr4[i]->sin_addr.s_addr)) mbuf->for_home = true;
            }
        }

        // For debugging purposes, we have queue control that will only let a set number
        // of packets through
        if (rxq->q_control) {
            if (!rxq->q_control_cnt) {
                if_stats.if_dropped_pkts[rxq->if_index]++;
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
}


// +----------------------------------------------------------------------------
// | Do the packet mangling on the vps between the rx and tx
// +----------------------------------------------------------------------------
static void *vps_pkt_mangler_thread(void * arg)
{
    struct mbuf_s   *mbuf;
    uint8_t         *seq_no, *if_ratios;
    unsigned char   *mbufc;
    unsigned int    active_if=0;
    unsigned int    active_if_cnt[NUM_EGRESS_INTERFACES];
    struct in6_addr *sv_dest_addr6;
    struct ip6_hdr  *ip6hdr;
    struct in_addr  *sv_dest_addr;
    struct ip       *iphdr;

    active_if_cnt[0] = active_if_cnt[1] = 0;
    while (dsl_threads[VPS_PKT_MANGLER_THREADNO].keep_going) {
        sem_wait(&if_config[EGRESS_IF].if_rxq.if_ready);
        if ((mbuf = circular_buffer_pop(if_config[EGRESS_IF].if_rxq.if_pkts)) == NULL) continue;
        mbufc                       = (unsigned char *) mbuf;
        if (mbuf->ipv6) {
            ip6hdr                  = (struct ip6_hdr *) (mbufc + sizeof(struct ether_header));
            sv_dest_addr6           = (struct in6_addr *) (mbufc + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + ip6hdr->ip6_plen);
            seq_no                  = (uint8_t *) (mbufc + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + ip6hdr->ip6_plen + sizeof(struct in6_addr));
        } else {
            iphdr                   = (struct ip *) (mbufc + sizeof(struct ether_header));
            sv_dest_addr            = (struct in_addr *) (mbufc + sizeof(struct ether_header) + iphdr->ip_len);
            seq_no                  = (uint8_t *) (mbufc + sizeof(struct ether_header) + iphdr->ip_len + sizeof(struct in_addr));
        }
        if (mbuf->for_home) {
            // This packet is from the internet, send it to the home gateway
            if (mbuf->ipv6) {
                memcpy(sv_dest_addr6, ip6hdr->ip6_dst.s6_addr, sizeof(struct in6_addr));
                memcpy(ip6hdr->ip6_dst.s6_addr, &client_addr6[active_if]->sin6_addr, sizeof(struct in6_addr));
                ip6hdr->ip6_plen        = ip6hdr->ip6_plen + sizeof(struct in6_addr) + 1;
            } else {
                memcpy(sv_dest_addr, &iphdr->ip_dst, sizeof(struct in_addr));
                iphdr->ip_dst.s_addr    = client_addr4[active_if]->sin_addr.s_addr;
                iphdr->ip_len           = iphdr->ip_len + sizeof(struct in_addr) + 1;
                iphdr->ip_sum           = iphdr_checksum((unsigned short*)(mbufc + sizeof(struct ether_header)), (sizeof(struct iphdr)/2));
            }
            *seq_no                 = pkt_seq_no++;
            active_if_cnt[active_if]++;
            active_if               = (active_if + 1) % 2;
            if (active_if_cnt[active_if] == if_config[active_if].if_ratio) {
                active_if           = (active_if + 1) % 2;
                if (active_if_cnt[active_if] == if_config[active_if].if_ratio) {
                    active_if_cnt[0] = active_if_cnt[1] = 0;
                    active_if       = (active_if + 1) % 2;
                }
            }
        } else {
            // This packet is from the client, replace the destination address from the
            // saved one, and send it to the internet. Also update the if_ratios we
            // received from the client. When we send to internet their must be iptables
            // source nat in place so that source destination is replaced and reply
            // comes back to vps.
            if_ratios               = seq_no;
            if (mbuf->ipv6) {
                memcpy(ip6hdr->ip6_dst.s6_addr, sv_dest_addr6, sizeof(struct in6_addr));
                ip6hdr->ip6_plen         = ip6hdr->ip6_plen - sizeof(struct in6_addr) - 1;
            } else {
                memcpy(&iphdr->ip_dst, sv_dest_addr, sizeof(struct in_addr));
                iphdr->ip_len           = iphdr->ip_len - sizeof(struct in_addr) - 1;
                iphdr->ip_sum           = iphdr_checksum((unsigned short*)(mbufc + sizeof(struct ether_header)), (sizeof(struct iphdr)/2));
            }
            if_config[0].if_ratio   = if_ratios[0];
            if_config[1].if_ratio   = if_ratios[1];
        }
        circular_buffer_push(if_config[EGRESS_IF].if_txq.if_pkts, mbuf);
        sem_post(&if_config[EGRESS_IF].if_txq.if_ready);
    }

    thread_exit_rc = 0;
    pthread_exit(&thread_exit_rc);
}


// +----------------------------------------------------------------------------
// | Create all the server threads
// +----------------------------------------------------------------------------
static int create_threads(void)
{
    int     rc;
    
    snprintf(dsl_threads[0].thread_name, 16, "rx_thread");
    if ((rc = create_thread(&dsl_threads[0].thread_id, rx_thread, RXPRIO, dsl_threads[0].thread_name, (void *) &if_config[EGRESS_IF].if_rxq)) != 0) {
        log_msg(LOG_ERR, "%s-%d: Can not create rx thread for interface %s - %s.\n", __FUNCTION__, __LINE__, if_config[EGRESS_IF].if_name, strerror(rc));
        exit_level1_cleanup();
        exit(rc);
    }
    snprintf(dsl_threads[1].thread_name, 16, "tx_thread");
    if ((rc = create_thread(&dsl_threads[1].thread_id, tx_thread, TXPRIO, dsl_threads[1].thread_name, (void *) &if_config[EGRESS_IF].if_txq)) != 0) {
        log_msg(LOG_ERR, "%s-%d: Can not create tx thread for interface %s - %s.\n", __FUNCTION__, __LINE__, if_config[EGRESS_IF].if_name, strerror(rc));
        exit_level1_cleanup();
        exit(rc);
    }
    snprintf(dsl_threads[VPS_PKT_MANGLER_THREADNO].thread_name, 16, "vps_pkt_mangler");
    if ((rc = create_thread(&dsl_threads[VPS_PKT_MANGLER_THREADNO].thread_id, vps_pkt_mangler_thread, VPS_PKT_MANGLER_PRIO, dsl_threads[VPS_PKT_MANGLER_THREADNO].thread_name, NULL)) != 0) {
        log_msg(LOG_ERR, "%s-%d: Can not create vps packet mangler thread - %s.\n", __FUNCTION__, __LINE__, strerror(rc));
        exit_level1_cleanup();
        exit(rc);
    }

    num_threads = 3;
}


// +----------------------------------------------------------------------------
// | Handle a query on the comms socket
// +----------------------------------------------------------------------------
int handle_client_query(struct comms_query_s *query, int comms_client_fd, bool *connection_active)
{
    int                     rc, i;
    struct comms_reply_s    reply;
    char                    client_ip_str[2][INET6_ADDRSTRLEN];

    if (query->for_peer) {
        if (comms_addr_valid) {
            query->for_peer = false;
            while(((rc=send(comms_peer_fd, query, sizeof(struct comms_query_s), 0)) == -1) && (errno == EINTR));
                if (rc == -1) {
                log_msg(LOG_WARNING, "%s-%d: Could net send message to peer - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
            } else {
                while(((rc = recv(comms_peer_fd, &reply, sizeof(struct comms_reply_s), 0)) == -1) && (errno == EINTR));
                }
            if (rc == -1) reply.rc = errno;
            else reply.rc = 0;
        } else {
            reply.rc    = 1;
        }
    } else {
        switch (query->cmd){
            case COMMS_HELO:
                if (ipv6_mode) {
                    memcpy(&client_addr[0], &query->helo_data.egress_addr[0], sizeof(struct sockaddr_in6));
                    memcpy(&client_addr[1], &query->helo_data.egress_addr[1], sizeof(struct sockaddr_in6));
                    memcpy(&if_stats.client_sa[0], &query->helo_data.egress_addr[0], sizeof(struct sockaddr_in6));
                    memcpy(&if_stats.client_sa[1], &query->helo_data.egress_addr[1], sizeof(struct sockaddr_in6));
                    inet_ntop(AF_INET6, get_in_addr((struct sockaddr *)&client_addr[0]), client_ip_str[0], INET6_ADDRSTRLEN);
                    inet_ntop(AF_INET6, get_in_addr((struct sockaddr *)&client_addr[1]), client_ip_str[1], INET6_ADDRSTRLEN);
                } else {
                    memcpy(&client_addr[0], &query->helo_data.egress_addr[0], sizeof(struct sockaddr_in));
                    memcpy(&client_addr[1], &query->helo_data.egress_addr[1], sizeof(struct sockaddr_in));
                    memcpy(&if_stats.client_sa[0], &query->helo_data.egress_addr[0], sizeof(struct sockaddr_in));
                    memcpy(&if_stats.client_sa[1], &query->helo_data.egress_addr[1], sizeof(struct sockaddr_in));
                    inet_ntop(AF_INET, get_in_addr((struct sockaddr *)&client_addr[0]), client_ip_str[0], INET6_ADDRSTRLEN);
                    inet_ntop(AF_INET, get_in_addr((struct sockaddr *)&client_addr[1]), client_ip_str[1], INET6_ADDRSTRLEN);
                }
                client_addr_valid           = true;
                if_stats.client_connected   = true;
                if_config[0].if_ratio       = query->helo_data.if_ratio[0];
                if_config[1].if_ratio       = query->helo_data.if_ratio[1];
                cc_port                     = query->helo_data.cc_port;
                reply.rc                    = 0;
                log_msg(LOG_INFO, "HELO received.");
                log_msg(LOG_INFO, "Client address1: %s  Client address2: %s.\n", client_ip_str[0], client_ip_str[1]);
                log_msg(LOG_INFO, "IF ratio1: %u  IF ratio2: %u  Port: %u", if_config[0].if_ratio, if_config[1].if_ratio, cc_port);
                reconnect_comms_to_server();
                break;
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
                reply.rc    = -1;
        }
    }

    reply.is_client = false;
    send(comms_client_fd, &reply, sizeof(struct comms_reply_s), 0);
}


// +----------------------------------------------------------------------------
// | Read the config file and set all the appropriate variables from the values.
// +----------------------------------------------------------------------------
static void read_config_file(void)
{
    config_t                cfg;
    const char              *config_string=NULL;
    int                     i;

    config_init(&cfg);

    if (!config_read_file(&cfg, config_file_name)) {
        log_msg(LOG_ERR, "%s-%d: Error reading config file, all parameters revert to defaults.\n", __FUNCTION__, __LINE__);
        return;
    }

    if (config_lookup_int(&cfg, "port", &cc_port))
        log_msg(LOG_INFO, "Configured for comms port on %d.\n", cc_port);
    if (config_lookup_int(&cfg, "remote_port", &rmt_port))
        log_msg(LOG_INFO, "Configured for remote comms port on %d.\n", rmt_port);
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
    if (config_lookup_string(&cfg, "server.interface", &config_string)) {
        strcpy(if_config[EGRESS_IF].if_name, config_string);
        log_msg(LOG_INFO, "Configured for server interface on %s.\n", if_config[EGRESS_IF].if_name);
        egresscnt = 1;
    }

    config_destroy(&cfg);
}


// +----------------------------------------------------------------------------
// | Main processing.
// +----------------------------------------------------------------------------
int main(int argc, char *argv[])
{
    int                         option, i;
    bool                        daemonize = true;
    pid_t                       pid, sid;
    struct sigaction            sigact;
    struct sched_param          sparam;

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

    // do some sanity checks
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

    if_stats.num_interfaces = 1;
    if_stats.ipv6_mode      = ipv6_mode;
    for (i=0; i<if_stats.num_interfaces; i++) {
        strncpy(if_stats.if_name[i], if_config[i].if_name, IFNAMSIZ);
    }

    // Start up the server threads
    create_threads();

    // Process comms until killed
    process_remote_comms();
    process_comms();

    exit_level1_cleanup();
    exit(EXIT_SUCCESS);
}
