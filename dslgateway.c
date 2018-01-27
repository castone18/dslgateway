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

#include "log.h"
#include "comms.h"
#include "util.h"
#include "dslgateway.h"


extern char                     *progname;
extern struct if_config_s       if_config[NUM_EGRESS_INTERFACES];
extern struct nf_queue_config_s nfq_config[NUM_NETFILTER_QUEUES];
extern unsigned int             egresscnt;
extern struct statistics_s      nf_stats;
//extern int                      thread_exit_rc;
static bool                     is_daemon;
extern bool                     ipv6_mode;
extern int                      comms_peer_fd;
extern bool                     comms_addr_valid;
extern void                     (*handle_comms_command)(struct comms_packet_s *query, struct comms_packet_s *reply,
                                    int comms_client_fd, bool *connection_active);


//static uint8_t                  pkt_seq_no=0;
static struct sockaddr_storage  client_addr[NUM_EGRESS_INTERFACES];
static struct sockaddr_in6      *client_addr6[NUM_EGRESS_INTERFACES] = {(struct sockaddr_in6 *) &client_addr[0], (struct sockaddr_in6 *) &client_addr[1]};
static struct sockaddr_in       *client_addr4[NUM_EGRESS_INTERFACES] = {(struct sockaddr_in *) &client_addr[0], (struct sockaddr_in *) &client_addr[1]};
static bool                     debug=false;
static char                     config_file_name[PATH_MAX];
static bool                     q_control_on=false;
static unsigned int             cc_port=PORT;
static unsigned int             data_port_cnt=0;


//// +----------------------------------------------------------------------------
//// | Server interface receive thread.
//// +----------------------------------------------------------------------------
//static void *rx_thread(void * arg)
//{
//    struct if_queue_s   *rxq = (struct if_queue_s *) arg;
//    struct mbuf_s       *mbuf=NULL;
//    unsigned char       *mbufc;
//    ssize_t             rxSz;
//    struct ether_header *ethhdr;
//    uint8_t             broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
//    struct ip6_hdr      *ip6hdr;
//    int                 i;
//    struct ip           *iphdr;
//
//    while (rxq->if_thread->keep_going) {
//        if (mbuf == NULL) mbuf = (struct mbuf_s*) mempool_alloc(mPool);
//        if (mbuf == NULL) {
//            log_msg(LOG_WARNING, "%s-%d: Out of mbufs, will wait and try again.\n", __FUNCTION__, __LINE__);
//            sleep(1);
//            continue;
//        }
//        // TODO: deal with partial packet receipt
//        while (((rxSz = recv(if_config[rxq->if_index].if_rx_fd, (void *) mbuf, sizeof(union mbuf_u), 0)) < 0) && (errno == EINTR));
//        if (rxSz < 0) {
//            log_msg(LOG_ERR, "%s-%d: Error reading raw packets from interface %s - %s",
//                    __FUNCTION__, __LINE__, if_config[rxq->if_index].if_rxname, strerror(errno));
//            continue;
//        }
//        mbuf->if_index = rxq->if_index;
//        switch (mbuf->pkt.tcp_pkt.eth_hdr.ether_type) {
//            case ETHERTYPE_IPV6:
//                if (!ipv6_mode) {
//                    // not ipv6 mode so drop the packet
//                    nf_stats.if_dropped_pkts[rxq->if_index]++;
//                    continue;
//                }
//                mbuf->ipv6 = true;
//                break;
//            case ETHERTYPE_IP:
//                if (ipv6_mode) {
//                    // not ipv4 mode so drop the packet
//                    nf_stats.if_dropped_pkts[rxq->if_index]++;
//                    continue;
//                }
//                mbuf->ipv6 = false;
//                break;
//            default:
//                nf_stats.if_dropped_pkts[rxq->if_index]++;
//                continue;
//        }
//        mbufc = (unsigned char *) mbuf;
//        clock_gettime(CLOCK_MONOTONIC, &mbuf->rx_time);
//
//        // ignore packets from egress interfaces with if_ratio = 0
//        if ((rxq->if_index == EGRESS_IF || rxq->if_index == EGRESS_IF+1) && if_config[rxq->if_index].if_ratio == 0) {
//            nf_stats.if_dropped_pkts[rxq->if_index]++;
//            continue;
//        }
//
//        // ignore broadcast packets
//        ethhdr = (struct ether_header *) mbufc;
//        if (memcmp(ethhdr->ether_dhost, broadcast_mac, 6) == 0) {
//            nf_stats.if_dropped_pkts[rxq->if_index]++;
//            continue;
//        }
//
//
//        if (mbuf->ipv6) {
//            ip6hdr = (struct ip6_hdr *) (mbufc + sizeof(struct ether_header));
//            if (!client_addr_valid) {
//                nf_stats.if_dropped_pkts[rxq->if_index]++;
//                continue;
//            }
//            if (ip6hdr->ip6_src.s6_addr[11] == 0xFF && ip6hdr->ip6_src.s6_addr[12] == 0xFE) {
//                // this packet came from home gateway
//                mbuf->for_home = false;
//            } else {
//                mbuf->for_home = true;
//            }
//        } else {
//            iphdr = (struct ip *) (mbufc + sizeof(struct ether_header));
//            for (i=0; i<3; i++) {
//                mbuf->for_home = false;
//                if (!client_addr_valid) {
//                    nf_stats.if_dropped_pkts[rxq->if_index]++;
//                    continue;
//                }
//                if ((iphdr->ip_dst.s_addr == client_addr4[i]->sin_addr.s_addr) || (iphdr->ip_dst.s_addr == client_addr4[i]->sin_addr.s_addr)) mbuf->for_home = true;
//            }
//        }
//
//        // For debugging purposes, we have queue control that will only let a set number
//        // of packets through
//        if (rxq->q_control) {
//            if (!rxq->q_control_cnt) {
//                nf_stats.if_dropped_pkts[rxq->if_index]++;
//                continue;
//            }
//            rxq->q_control_cnt--;
//        }
//
//        // Accept the packet
//        circular_buffer_push(rxq->if_pkts, (void *) mbuf);
//        sem_post(&rxq->if_ready);
//        mbuf = NULL;
//        nf_stats.if_rx_pkts[rxq->if_index]++;
//        nf_stats.if_rx_bytes[rxq->if_index] += rxSz;
//    }
//
//    thread_exit_rc = 0;
//    pthread_exit(&thread_exit_rc);
//    return &thread_exit_rc; // for compiler warnings
//}
//
//
//// +----------------------------------------------------------------------------
//// | Do the packet mangling on the vps between the rx and tx
//// +----------------------------------------------------------------------------
//static void *vps_pkt_mangler_thread(void * arg)
//{
//    struct mbuf_s   *mbuf;
//    uint8_t         *seq_no, *if_ratios;
//    unsigned char   *mbufc;
//    unsigned int    active_if=0;
//    unsigned int    active_if_cnt[NUM_EGRESS_INTERFACES];
//    struct in6_addr *sv_dest_addr6;
//    struct ip6_hdr  *ip6hdr;
//    struct in_addr  *sv_dest_addr;
//    struct ip       *iphdr;
//
//    active_if_cnt[0] = active_if_cnt[1] = 0;
//    while (dsl_threads[VPS_PKT_MANGLER_THREADNO].keep_going) {
//        sem_wait(&if_config[EGRESS_IF].if_rxq.if_ready);
//        if ((mbuf = circular_buffer_pop(if_config[EGRESS_IF].if_rxq.if_pkts)) == NULL) continue;
//        mbufc                       = (unsigned char *) mbuf;
//        if (mbuf->ipv6) {
//            ip6hdr                  = (struct ip6_hdr *) (mbufc + sizeof(struct ether_header));
//            sv_dest_addr6           = (struct in6_addr *) (mbufc + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + ip6hdr->ip6_plen);
//            seq_no                  = (uint8_t *) (mbufc + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + ip6hdr->ip6_plen + sizeof(struct in6_addr));
//        } else {
//            iphdr                   = (struct ip *) (mbufc + sizeof(struct ether_header));
//            sv_dest_addr            = (struct in_addr *) (mbufc + sizeof(struct ether_header) + iphdr->ip_len);
//            seq_no                  = (uint8_t *) (mbufc + sizeof(struct ether_header) + iphdr->ip_len + sizeof(struct in_addr));
//        }
//        if (mbuf->for_home) {
//            // This packet is from the internet, send it to the home gateway
//            if (mbuf->ipv6) {
//                memcpy(sv_dest_addr6, ip6hdr->ip6_dst.s6_addr, sizeof(struct in6_addr));
//                memcpy(ip6hdr->ip6_dst.s6_addr, &client_addr6[active_if]->sin6_addr, sizeof(struct in6_addr));
//                ip6hdr->ip6_plen        = ip6hdr->ip6_plen + sizeof(struct in6_addr) + 1;
//            } else {
//                memcpy(sv_dest_addr, &iphdr->ip_dst, sizeof(struct in_addr));
//                iphdr->ip_dst.s_addr    = client_addr4[active_if]->sin_addr.s_addr;
//                iphdr->ip_len           = iphdr->ip_len + sizeof(struct in_addr) + 1;
//                iphdr->ip_sum           = iphdr_checksum((unsigned short*)(mbufc + sizeof(struct ether_header)), (sizeof(struct iphdr)/2));
//            }
//            *seq_no                 = pkt_seq_no++;
//            active_if_cnt[active_if]++;
//            active_if               = (active_if + 1) % 2;
//            if (active_if_cnt[active_if] == if_config[active_if].if_ratio) {
//                active_if           = (active_if + 1) % 2;
//                if (active_if_cnt[active_if] == if_config[active_if].if_ratio) {
//                    active_if_cnt[0] = active_if_cnt[1] = 0;
//                    active_if       = (active_if + 1) % 2;
//                }
//            }
//        } else {
//            // This packet is from the client, replace the destination address from the
//            // saved one, and send it to the internet. Also update the if_ratios we
//            // received from the client. When we send to internet their must be iptables
//            // source nat in place so that source destination is replaced and reply
//            // comes back to vps.
//            if_ratios               = seq_no;
//            if (mbuf->ipv6) {
//                memcpy(ip6hdr->ip6_dst.s6_addr, sv_dest_addr6, sizeof(struct in6_addr));
//                ip6hdr->ip6_plen         = ip6hdr->ip6_plen - sizeof(struct in6_addr) - 1;
//            } else {
//                memcpy(&iphdr->ip_dst, sv_dest_addr, sizeof(struct in_addr));
//                iphdr->ip_len           = iphdr->ip_len - sizeof(struct in_addr) - 1;
//                iphdr->ip_sum           = iphdr_checksum((unsigned short*)(mbufc + sizeof(struct ether_header)), (sizeof(struct iphdr)/2));
//            }
//            if_config[0].if_ratio   = if_ratios[0];
//            if_config[1].if_ratio   = if_ratios[1];
//        }
//        circular_buffer_push(if_config[EGRESS_IF].if_txq.if_pkts, mbuf);
//        sem_post(&if_config[EGRESS_IF].if_txq.if_ready);
//    }
//
//    thread_exit_rc = 0;
//    pthread_exit(&thread_exit_rc);
//    return &thread_exit_rc; // for compiler warnings
//}


// +----------------------------------------------------------------------------
// | Create all the server threads
// +----------------------------------------------------------------------------
static int create_threads(void)
{
//    int     rc;
//
//    snprintf(dsl_threads[0].thread_name, 16, "rx_thread");
//    if ((rc = create_thread(&dsl_threads[0].thread_id, rx_thread, RXPRIO, dsl_threads[0].thread_name, (void *) &if_config[EGRESS_IF].if_rxq)) != 0) {
//        log_msg(LOG_ERR, "%s-%d: Can not create rx thread for interface %s - %s.\n", __FUNCTION__, __LINE__, if_config[EGRESS_IF].if_rxname, strerror(rc));
//        return rc;
//    }
//    snprintf(dsl_threads[1].thread_name, 16, "tx_thread");
//    if ((rc = create_thread(&dsl_threads[1].thread_id, tx_thread, TXPRIO, dsl_threads[1].thread_name, (void *) &if_config[EGRESS_IF].if_txq)) != 0) {
//        log_msg(LOG_ERR, "%s-%d: Can not create tx thread for interface %s - %s.\n", __FUNCTION__, __LINE__, if_config[EGRESS_IF].if_txname, strerror(rc));
//        return rc;
//    }
//    snprintf(dsl_threads[VPS_PKT_MANGLER_THREADNO].thread_name, 16, "vps_pkt_mangler");
//    if ((rc = create_thread(&dsl_threads[VPS_PKT_MANGLER_THREADNO].thread_id, vps_pkt_mangler_thread, VPS_PKT_MANGLER_PRIO, dsl_threads[VPS_PKT_MANGLER_THREADNO].thread_name, NULL)) != 0) {
//        log_msg(LOG_ERR, "%s-%d: Can not create vps packet mangler thread - %s.\n", __FUNCTION__, __LINE__, strerror(rc));
//        return rc;
//    }

    return 0;
}


// +----------------------------------------------------------------------------
// | Handle a query on the comms socket
// +----------------------------------------------------------------------------
static void handle_server_command(struct comms_packet_s *query, struct comms_packet_s *reply,
        int comms_client_fd, bool *connection_active)
{
    char    client_ip_str[2][INET6_ADDRSTRLEN];

    switch (query->cmd){
        case COMMS_HELO:
            if (!comms_addr_valid) {
                if (ipv6_mode) {
                    memcpy(&client_addr[0], &query->pyld.qry.helo_data.egress_addr[0], sizeof(struct sockaddr_in6));
                    memcpy(&client_addr[1], &query->pyld.qry.helo_data.egress_addr[1], sizeof(struct sockaddr_in6));
                    memcpy(&nf_stats.client_sa[0], &query->pyld.qry.helo_data.egress_addr[0], sizeof(struct sockaddr_in6));
                    memcpy(&nf_stats.client_sa[1], &query->pyld.qry.helo_data.egress_addr[1], sizeof(struct sockaddr_in6));
                    inet_ntop(AF_INET6, get_in_addr((struct sockaddr *)&client_addr[0]), client_ip_str[0], INET6_ADDRSTRLEN);
                    inet_ntop(AF_INET6, get_in_addr((struct sockaddr *)&client_addr[1]), client_ip_str[1], INET6_ADDRSTRLEN);
                } else {
                    memcpy(&client_addr[0], &query->pyld.qry.helo_data.egress_addr[0], sizeof(struct sockaddr_in));
                    memcpy(&client_addr[1], &query->pyld.qry.helo_data.egress_addr[1], sizeof(struct sockaddr_in));
                    memcpy(&nf_stats.client_sa[0], &query->pyld.qry.helo_data.egress_addr[0], sizeof(struct sockaddr_in));
                    memcpy(&nf_stats.client_sa[1], &query->pyld.qry.helo_data.egress_addr[1], sizeof(struct sockaddr_in));
                    inet_ntop(AF_INET, get_in_addr((struct sockaddr *)&client_addr[0]), client_ip_str[0], INET6_ADDRSTRLEN);
                    inet_ntop(AF_INET, get_in_addr((struct sockaddr *)&client_addr[1]), client_ip_str[1], INET6_ADDRSTRLEN);
                }
                comms_addr_valid            = true;
                nf_stats.client_connected   = true;
                if_config[0].if_ratio       = query->pyld.qry.helo_data.if_ratio[0];
                if_config[1].if_ratio       = query->pyld.qry.helo_data.if_ratio[1];
                cc_port                     = query->pyld.qry.helo_data.cc_port;
                comms_peer_fd               = comms_client_fd;
                reply->pyld.rply.rc                   = 0;
                log_msg(LOG_INFO, "HELO received.");
                log_msg(LOG_INFO, "Client address1: %s  Client address2: %s.\n", client_ip_str[0], client_ip_str[1]);
                log_msg(LOG_INFO, "IF ratio1: %u  IF ratio2: %u  Port: %u", if_config[0].if_ratio, if_config[1].if_ratio, cc_port);
            } else {
                log_msg(LOG_WARNING, "Received duplicate HELO, discarded.");
                reply->pyld.rply.rc                   = 1;
            }
            break;
        case COMMS_CYA:
            comms_peer_fd       = -1;
            comms_addr_valid    = false;
            *connection_active  = false;
            break;
        case COMMS_GETSTATS:
            memcpy(&reply->pyld.rply.stats, &nf_stats, sizeof(struct statistics_s));
            reply->pyld.rply.rc    = 0;
            break;
        case COMMS_KILL:
            reply->pyld.rply.rc        = 0;
            reply->pyld.rply.is_client = false;
            send(comms_client_fd, &reply, sizeof(struct comms_reply_s), 0);
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
            reply->pyld.rply.rc    = 0;
            break;
        default:
            reply->pyld.rply.rc    = -1;
    }
    reply->pyld.rply.is_client = false;
}


// +----------------------------------------------------------------------------
// | Read the config file and set all the appropriate variables from the values.
// +----------------------------------------------------------------------------
static void read_config_file(void)
{
    config_t                cfg;
    const char              *config_string=NULL;
    const config_setting_t  *config_list;
    int                     i;

    config_init(&cfg);

    if (!config_read_file(&cfg, config_file_name)) {
        log_msg(LOG_ERR, "%s-%d: Error reading config file, all parameters revert to defaults.\n", __FUNCTION__, __LINE__);
        return;
    }

    if (config_lookup_int(&cfg, "port", &cc_port))
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
    data_port_cnt = config_setting_length(config_list);
    for (i=0; i<config_setting_length(config_list); i++) {
        if (i == NUM_NETFILTER_QUEUES) break;
        if_config[i].if_port = config_setting_get_int_elem(config_list, i);
        log_msg(LOG_INFO, "Configured for data port on %u.\n", if_config[i].if_port);
    }
    if (config_lookup_int(&cfg, "server.egress.nf_q_no", &nfq_config[EGRESS_NFQ].nfq_q_no)) {
        log_msg(LOG_INFO, "Configured for egress netfilter queue on %u.\n", nfq_config[EGRESS_NFQ].nfq_q_no);
    }
    if (config_lookup_int(&cfg, "server.ingress.nf_q_no", &nfq_config[INGRESS_NFQ].nfq_q_no)) {
        log_msg(LOG_INFO, "Configured for ingress netfilter queue on %u.\n", nfq_config[INGRESS_NFQ].nfq_q_no);
    }
    config_string = NULL;
    if (config_lookup_string(&cfg, "server.interface", &config_string)) {
        strcpy(if_config[EGRESS_IF].if_name, config_string);
        egresscnt++;
        log_msg(LOG_INFO, "Configured for ingress/egress interface on %s.\n", if_config[EGRESS_IF].if_name);
    }

    config_destroy(&cfg);
}


// +----------------------------------------------------------------------------
// | Process packets from server received on the two data port connections.
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
// | Create channel
// +----------------------------------------------------------------------------
static int create_channel(unsigned int port)
{
    int                         rc, fd;
    struct sockaddr_in6         bind_addr6;
    struct sockaddr_in          bind_addr;

    bzero((char *) &bind_addr, sizeof(bind_addr));
    bzero((char *) &bind_addr6, sizeof(bind_addr6));
    if (ipv6_mode) {
        if ((fd = socket(AF_INET6, SOCK_STREAM, 0)) == -1) {
            rc = errno;
            log_msg(LOG_ERR, "%s-%d: Error creating socket - %s.\n", __FUNCTION__, __LINE__, strerror(rc));
            return -1*rc;
        }
        bind_addr6.sin6_family   = AF_INET6;
        bind_addr6.sin6_addr     = in6addr_any;
        bind_addr6.sin6_port     = htons((unsigned short)port);
    } else {
        if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
            rc = errno;
            log_msg(LOG_ERR, "%s-%d: Error creating socket - %s.\n", __FUNCTION__, __LINE__, strerror(rc));
            close(fd);
            return -1*rc;
        }
        bind_addr.sin_family        = AF_INET;
        bind_addr.sin_addr.s_addr   = htonl(INADDR_ANY);
        bind_addr.sin_port          = htons((unsigned short)port);
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) == -1) {
        log_msg(LOG_WARNING, "%s-%d: Error setting reuse address on socket.\n", __FUNCTION__, __LINE__);
    }
    if (ipv6_mode) {
        if (bind(fd, (struct sockaddr *) &bind_addr6, sizeof(bind_addr6)) == -1) {
            rc = errno;
            log_msg(LOG_ERR, "%s-%d: Can not bind socket - %s.\n", __FUNCTION__, __LINE__, strerror(rc));
            close(fd);
            return -1*rc;
        }
    } else {
        if (bind(fd, (struct sockaddr *) &bind_addr, sizeof(bind_addr)) == -1) {
            rc = errno;
            log_msg(LOG_ERR, "%s-%d: Can not bind socket - %s.\n", __FUNCTION__, __LINE__, strerror(rc));
            close(fd);
            return -1*rc;
        }
    }

    if (listen(fd, 1) == -1) {
        rc = errno;
        log_msg(LOG_ERR, "%s-%d: Can not listen on socket - %s.\n", __FUNCTION__, __LINE__, rc);
        close(fd);
        return -1*rc;
    }
    return fd;
}


// +----------------------------------------------------------------------------
// | Open egress interfaces, open sockets and listen on the data ports.
// +----------------------------------------------------------------------------
static void open_data_ports(void)
{
    int             i, rc;
    struct ifreq    ifr;

    for (i=0; i<data_port_cnt; i++) {
        // Open socket for egress tx interface.
        if ((if_config[i].if_fd = create_channel(if_config[i].if_port)) < 0) {
            exit_level1_cleanup();
            exit(-1*if_config[i].if_fd);
        }
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, if_config[EGRESS_IF].if_name, sizeof(ifr.ifr_name));
        // Get interface if index
        if (ioctl (if_config[i].if_fd, SIOCGIFINDEX, &ifr) < 0) {
            rc = errno;
            log_msg(LOG_ERR, "%s-%d: Can not get interface index for %s - %s.\n", __FUNCTION__, __LINE__, ifr.ifr_name, strerror(errno));
            exit_level1_cleanup();
            exit(rc);
        }
        if_config[i].if_index = ifr.ifr_ifindex;
        // Bind socket to a particular interface name (eg: ppp0 or ppp1)
        if (setsockopt(if_config[i].if_fd, SOL_SOCKET, SO_BINDTODEVICE, (void *) &ifr, sizeof(ifr)) < 0) {
            rc = errno;
            log_msg(LOG_ERR, "%s-%d: Can not bind socket to %s - %s.\n", __FUNCTION__, __LINE__, ifr.ifr_name, strerror(errno));
            exit_level1_cleanup();
            exit(rc);
        }
        log_debug_msg(LOG_INFO, "%s-%d: Interface %d bound to %s.\n", __FUNCTION__, __LINE__, i, ifr.ifr_name);
    }
}


// +----------------------------------------------------------------------------
// | Thread to handle remote communication channel
// +----------------------------------------------------------------------------
static void *accept_comms_thread(void *arg)
{
    struct comms_thread_parms_s *thread_parms  = (struct comms_thread_parms_s *) arg;
    char                        ipaddr[INET6_ADDRSTRLEN];
    struct comms_thread_parms_s *comms_thread_parms;
    socklen_t                   sin_size;
    int                         rc;
    struct sockaddr_in6         comms_client_addr6;
    struct sockaddr_in          comms_client_addr;

    for(;;) {
        if ((comms_thread_parms = (struct comms_thread_parms_s *) malloc(sizeof(struct comms_thread_parms_s))) == NULL) {
            log_msg(LOG_ERR, "%s-%d: Out of memory.\n", __FUNCTION__, __LINE__);
            sleep(1);
            continue;
        }
        if (ipv6_mode) {
            sin_size = sizeof(comms_client_addr6);
            if ((comms_thread_parms->peer_fd = accept(thread_parms->peer_fd, (struct sockaddr *)&comms_client_addr6, &sin_size)) < 0) {
                log_msg(LOG_ERR, "%s-%d: Error accepting comms connection - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
                continue;
            }
            inet_ntop(AF_INET6, get_in_addr((struct sockaddr *)&comms_client_addr6), ipaddr, sizeof ipaddr);
        } else {
            sin_size = sizeof(comms_client_addr);
            if ((comms_thread_parms->peer_fd = accept(thread_parms->peer_fd, (struct sockaddr *)&comms_client_addr, &sin_size)) < 0) {
                log_msg(LOG_ERR, "%s-%d: Error accepting comms connection - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
                continue;
            }
            inet_ntop(AF_INET, get_in_addr((struct sockaddr *)&comms_client_addr), ipaddr, sizeof ipaddr);
        }
        log_msg(LOG_INFO, "Accepted connection from %s.\n", ipaddr);
        if ((rc = create_thread(&comms_thread_parms->thread_id, comms_thread, 1, "comms_thread", (void *) comms_thread_parms)) != 0) {
            log_msg(LOG_ERR, "%s-%d: Can not create comms thread for connection from %s - %s.\n", __FUNCTION__, __LINE__, ipaddr, strerror(rc));
        }
    }
    pthread_exit(NULL);
    return NULL; // for compiler warnings
}


// +----------------------------------------------------------------------------
// | Process local comms port
// +----------------------------------------------------------------------------
static void process_comms(void)
{
    int                         rc;
    struct comms_thread_parms_s *comms_thread_parms;

    if ((comms_thread_parms = (struct comms_thread_parms_s *) malloc(sizeof(struct comms_thread_parms_s))) == NULL) {
        log_msg(LOG_ERR, "%s-%d: Out of memory.\n", __FUNCTION__, __LINE__);
        exit_level1_cleanup();
        exit(ENOMEM);
    }

    // Open local communication channel
    if ((comms_thread_parms->peer_fd = create_channel(cc_port)) < 0) {
        exit_level1_cleanup();
        exit(-1*comms_thread_parms->peer_fd);
    }

    if ((rc = create_thread(&comms_thread_parms->thread_id, accept_comms_thread, 1, "comms_thread", (void *) comms_thread_parms)) != 0) {
        log_msg(LOG_ERR, "%s-%d: Can not create comms thread for connection request - %s.\n", __FUNCTION__, __LINE__, strerror(rc));
    }
}


// +----------------------------------------------------------------------------
// | Main processing.
// +----------------------------------------------------------------------------
int main(int argc, char *argv[])
{
    int                         option, i, rc, readset_fd;
    bool                        daemonize = true;
    pid_t                       pid, sid;
    struct sigaction            sigact;
    struct sched_param          sparam;
    char                        ipaddr[INET6_ADDRSTRLEN];
    fd_set                      readset;
    bool                        keep_going=true;

    i=0;
    if (argv[0][0] == '.' || argv[0][0] == '/') i++;
    if (argv[0][1] == '.' || argv[0][1] == '/') i++;
    progname = &argv[0][i];

    memset(config_file_name, 0, PATH_MAX);
    strcpy(config_file_name, DEFAULT_CONFIG_FILE_NAME);

    for (i=0; i<NUM_EGRESS_INTERFACES; i++) {
        memset(&if_config[i], 0, sizeof(struct if_config_s));
    }
    memset(&nf_stats, 0, sizeof(struct statistics_s));

    // Hook the sigterm and sigint signals
    memset(&sigact, 0, sizeof(sigact));
    sigact.sa_handler = &signal_handler;
    sigaction(SIGTERM, &sigact, NULL);
    sigaction(SIGINT, &sigact, NULL);

    handle_comms_command = handle_server_command;

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

    if (egresscnt == 0) {
        log_msg(LOG_ERR, "You must provide an ingress/egress interface name in the config file.\n\n");
        exit(EINVAL);
    }

    // Switch to real time scheduler
    sparam.sched_priority = sched_get_priority_min(SCHED_RR);
    if (sched_setscheduler(getpid(), SCHED_RR, &sparam) == -1) {
        log_msg(LOG_WARNING, "%s-%d: Set scheduler returns %s, continuing on SCHED_OTHER.\n",
                __FUNCTION__, __LINE__, strerror(errno));
    }

    // Listen on the data ports.
    open_data_ports();

    // Get ip addresses of all the interfaces
    get_ip_addrs();


    // Initialize netfilter queue config
//    nfq_config[INGRESS_NFQ].nfq_cb                    = &home_to_vps_pkt_mangler_cb;
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
    if (q_control_on) {
        nfq_config[EGRESS_NFQ].q_control            = true;
        nfq_config[EGRESS_NFQ].q_control_cnt        = 0;
    }
    else {
        nfq_config[EGRESS_NFQ].q_control            = false;
    }

    nf_stats.ipv6_mode      = ipv6_mode;

    // Start up the server threads
    if (create_threads()) {
        exit_level1_cleanup();
        exit(EFAULT);
    }

    // Start comms thread
    process_comms();

    for (;;) {
        log_msg(LOG_INFO, "Waiting for data port connections.\n");
        // Accept the data port connections
        if_config[EGRESS_IF].if_peer_fd = -1;
        if_config[EGRESS_IF+1].if_peer_fd = -1;
        for (i=0; i<NUM_EGRESS_INTERFACES; i++) {
            while (if_config[i].if_peer_fd < 0) {
                if (ipv6_mode) {
                    if_config[i].if_sin_size = sizeof(if_config[i].if_peer_client_addr6);
                    if ((if_config[i].if_peer_fd = accept(if_config[i].if_fd, (struct sockaddr *)&if_config[i].if_peer_client_addr6, &if_config[i].if_sin_size)) < 0) {
                        log_msg(LOG_ERR, "%s-%d: Error accepting peer data connection - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
                        continue;
                    }
                    inet_ntop(AF_INET6, get_in_addr((struct sockaddr *)&if_config[i].if_peer_client_addr6), ipaddr, sizeof ipaddr);
                    if (memcmp(&if_config[i].if_peer_client_addr6.sin6_addr, &client_addr6[i]->sin6_addr, sizeof(struct in6_addr)) != 0) {
                        log_msg(LOG_INFO, "Closing connection from unknown host %s.\n", ipaddr);
                        close(if_config[i].if_peer_fd);
                        if_config[i].if_peer_fd = -1;
                        continue;
                    }
                    log_msg(LOG_INFO, "Accepted peer data connection from %s on port %u.\n", ipaddr, if_config[i].if_port);
                } else {
                    if_config[i].if_sin_size = sizeof(if_config[i].if_peer_client_addr);
                    if ((if_config[i].if_peer_fd = accept(if_config[i].if_fd, (struct sockaddr *)&if_config[i].if_peer_client_addr, &if_config[i].if_sin_size)) < 0) {
                        log_msg(LOG_ERR, "%s-%d: Error accepting peer data connection - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
                        continue;
                    }
                    inet_ntop(AF_INET6, get_in_addr((struct sockaddr *)&if_config[i].if_peer_client_addr), ipaddr, sizeof ipaddr);
                    if (if_config[i].if_peer_client_addr.sin_addr.s_addr != client_addr4[i]->sin_addr.s_addr) {
                        log_msg(LOG_INFO, "Closing connection from unknown host %s.\n", ipaddr);
                        close(if_config[i].if_peer_fd);
                        if_config[i].if_peer_fd = -1;
                        continue;
                    }
                    log_msg(LOG_INFO, "Accepted peer data connection from %s on port %u.\n", ipaddr, if_config[i].if_port);
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
