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
// | is called the server. 
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

#define CLIENT                              0
#define SERVER                              1
#define DEFAULT_NUM_MBUFS                   12288
#define RXPRIO                              50
#define TXPRIO                              60
#define HOME_TO_VPS_PRIO                    40
#define HOME_FROM_VPS_PRIO                  40
#define VPS_PKT_MANGLER_PRIO                40
#define IFRATIO_CHANGE_PRIO                 20
#define INGRESS_IF                          2
#define EGRESS_IF                           0
#define REORDER_BUF_SZ                      8
#define ONE_MS                              1000000
#define REORDER_BUF_TIMEOUT                 200*ONE_MS
#define SLOW_CNT_MAX                        5
#define HOME_TO_VPS_PKT_MANGLER_THREADNO    6
#define HOME_FROM_VPS_PKT_MANGLER_THREADNO  7
#define VPS_PKT_MANGLER_THREADNO            2
#define DEFAULT_CONFIG_FILE_NAME            "/etc/dslgateway.cfg"

struct tcp_mbuf_s {
    struct ether_header eth_hdr;
    struct ip           ip_hdr;
    struct tcphdr       tcp_hdr;
    unsigned char       payload[ETHERMTU];
};

struct udp_mbuf_s {
    struct ether_header eth_hdr;
    struct ip           ip_hdr;
    struct udphdr       udp_hdr;
    unsigned char       payload[ETHERMTU];
};

union mbuf_u {
    struct tcp_mbuf_s   tcp_pkt;
    struct udp_mbuf_s   udp_pkt;
};

struct mbuf_s {
    union mbuf_u        pkt;
    unsigned int        if_index;
    struct timespec     rx_time;
    uint8_t             seq_no;
    bool                for_home;
};

struct thread_list_s {
    pthread_t   thread_id;
    char        thread_name[17];
    bool        keep_going;
};

struct if_queue_s {
    unsigned int            if_index;
    circular_buffer         if_pkts;
    sem_t                   if_ready;
    struct thread_list_s    *if_thread;
};

struct comms_thread_parms_s {
    int         peer_fd;
    pthread_t   thread_id;
};

struct if_config_s {
    int                 if_rx_fd;
    int                 if_tx_fd;
    char                if_name[IFNAMSIZ];
    char                if_brname[IFNAMSIZ];
    struct if_queue_s   if_rxq;
    struct if_queue_s   if_txq;
    uint8_t             if_ratio;
#ifdef IPV6
    struct sockaddr_in6 if_ipaddr;
#else
    struct sockaddr_in  if_ipaddr;
#endif
};

static char                 *progname;
static struct if_config_s   if_config[NUM_INGRESS_INTERFACES+NUM_EGRESS_INTERFACES];
static unsigned int         egresscnt=0, ingresscnt=0;
static bool                 is_daemon=false;
static mempool              mPool;
static bool                 wipebufs=false;
static uint8_t              pkt_seq_no=0;
static int                  cliserv=-1;
static int                  comms_peer_fd;
static struct statistics_s  if_stats;
static unsigned int         cc_port=PORT, rmt_port=PORT;
static struct thread_list_s dsl_threads[((NUM_INGRESS_INTERFACES+NUM_EGRESS_INTERFACES)*2)+2];
static unsigned int         num_threads;
static int                  thread_exit_rc;
static struct mbuf_s        *reorder_buf[REORDER_BUF_SZ];
static timer_t              reorder_buf_timerid;
static struct itimerspec    reorder_buf_intvl;
static unsigned int         reorder_if_cnt[2] = {0, 0};
#if defined(IPV6)
static struct sockaddr_in6  peer_addr, client_addr[NUM_EGRESS_INTERFACES];
#else
static struct sockaddr_in   peer_addr, client_addr[NUM_EGRESS_INTERFACES];
#endif
static bool                 peer_addr_valid=false;
static bool                 debug=false;
static char                 config_file_name[PATH_MAX];
static unsigned int         n_mbufs=DEFAULT_NUM_MBUFS;
static char                 *remote_name;



// +----------------------------------------------------------------------------
// | Deletes a tuntap interface.
// +----------------------------------------------------------------------------
static void tuntap_exit(char *dev, int fd)
{
    if (ioctl(fd, TUNSETPERSIST, 0) < 0) {
        log_msg(LOG_ERR, "%s-%d: Error deleting tuntap device %s - %s\n", __FUNCTION__, __LINE__, dev, strerror(errno));
    }
    close(fd);
}


// +----------------------------------------------------------------------------
// | Opens a tap interface. Returns fd of tap interface.
// +----------------------------------------------------------------------------
static int tuntap_init(char *ifname)
{
    struct ifreq    ifr;
    int             fd, rc;

    if (ifname == NULL) return -1*EINVAL;

    if (debug)
        log_msg(LOG_INFO, "%s-%d: Opening %s device.\n", __FUNCTION__, __LINE__, ifname);

    if( (fd = open("/dev/net/tun" , O_RDWR)) < 0 ) {
        log_msg(LOG_ERR, "%s-%d: Error opening /dev/net/tun - %s\n", __FUNCTION__, __LINE__, strerror(errno));
        return -1*errno;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP;

    if (strlen(ifname) > 0) {
        strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    }

    if((rc = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        rc = -1*errno;
        log_msg(LOG_ERR, "%s-%d: Error with ioctl(TUNSETIFF) - %s\n", __FUNCTION__, __LINE__, strerror(errno));
        close(fd);
        return rc;
    }
    if (strcmp(ifname, ifr.ifr_name) != 0)
        strncpy(ifname, ifr.ifr_name, IFNAMSIZ);
    if (debug) log_msg(LOG_INFO, "%s-%d: Opened %s device.\n", __FUNCTION__, __LINE__, ifr.ifr_name);

    return fd;
}


// +----------------------------------------------------------------------------
// | Do some more cleanup
// +----------------------------------------------------------------------------
static void exit_level1_cleanup(void)
{
    if (if_config[INGRESS_IF].if_rx_fd > 0)
        tuntap_exit(if_config[INGRESS_IF].if_name, if_config[INGRESS_IF].if_rx_fd);
    log_msg(LOG_INFO, "%s daemon ends.\n", progname);
}


// +----------------------------------------------------------------------------
// | Handles signals
// +----------------------------------------------------------------------------
static void signal_handler(int sig)
{

    switch (sig) {
        case SIGINT:
        case SIGTERM:
            exit_level1_cleanup();
            exit(EXIT_SUCCESS);
            break;
        default:
            exit(EXIT_FAILURE);
    }
}


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
// | Prints usage and exits.
// +----------------------------------------------------------------------------
static void usage(char *progname)
{
  printf("Usage:\n");
  printf("%s [-c <config filename>] [-d] [-f]\n", progname);
  printf("%s -h\n\n", progname);
  printf("-c <config filename>: full path to config file. Defaults to /etc/dslgateway.cfg.\n");
  printf("-d:                   outputs debug information while running.\n");
  printf("-f:                   stay in foreground instead of daemonizing.\n");
  printf("-h:                   prints this help text.\n");
  exit(1);
}


// +----------------------------------------------------------------------------
// | Receive thread, one is started on each interface, three on the home gateway
// | one on the vps. Note that the rx threads for both egress interfaces on the
// | home gateway, feed mbufs into the same circular buffer.
// +----------------------------------------------------------------------------
static void *rx_thread(void * arg)
{
    struct if_queue_s   *rxq = (struct if_queue_s *) arg;
    struct mbuf_s       *mbuf=NULL;
    unsigned char       *mbufc;
    ssize_t             rxSz;
    struct ether_header *ethhdr;
    uint8_t             broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
#ifdef IPV6
    struct ip6_hdr      *iphdr;
#else
    int                 i;
    struct ip           *iphdr;
    uint32_t            private_start[3], private_end[3];

    inet_pton(AF_INET, "10.0.0.0", &private_start[0]);
    inet_pton(AF_INET, "172.16.0.0", &private_start[1]);
    inet_pton(AF_INET, "192.168.0.0", &private_start[2]);
    private_end[0]  = private_start[0] | 0x00FFFFFF;
    private_end[1]  = private_start[1] | 0x00000FFF;
    private_end[2]  = private_start[2] | 0x0000FFFF;
#endif

    while (rxq->if_thread->keep_going) {
        if (mbuf == NULL) mbuf = (struct mbuf_s*) mempool_alloc(mPool);
        if (mbuf == NULL) {
            sleep(1);
            continue;
        }
        mbufc = (unsigned char *) mbuf;
        // TODO: deal with partial packet receipt
        while (((rxSz = read(if_config[rxq->if_index].if_rx_fd, (void *) mbuf, sizeof(union mbuf_u))) < 0) && (errno == EINTR));
        if (rxSz < 0) {
            log_msg(LOG_ERR, "%s-%d: Error reading raw packets from interface %s - %s",
                    __FUNCTION__, __LINE__, if_config[rxq->if_index].if_name, strerror(errno));
            continue;
        }
        mbuf->if_index = rxq->if_index;
        clock_gettime(CLOCK_MONOTONIC, &mbuf->rx_time);

        // ignore broadcast packets
        ethhdr = (struct ether_header *) mbufc;
        if (memcmp(ethhdr->ether_dhost, broadcast_mac, 6) == 0) {
            if_stats.if_dropped_pkts[rxq->if_index]++;
            continue;
        }


#ifdef IPV6
        iphdr = (struct ip6_hdr *) (mbufc + sizeof(struct ether_header));
        if (cliserv == CLIENT) {
            if (iphdr->ip6_src.s6_addr[11] == 0xFF && iphdr->ip6_src.s6_addr[12] == 0xFE) {
                // This packet is destined for a device in the home, so drop it
                if_stats.if_dropped_pkts[rxq->if_index]++;
                continue;
            }
        } else {  //server
            if (iphdr->ip6_src.s6_addr[11] == 0xFF && iphdr->ip6_src.s6_addr[12] == 0xFE) {
                // this packet came from home gateway
                mbuf->for_home = false;
            } else {
                mbuf->for_home = true;
            }
        }
#else
        iphdr = (struct ip *) (mbufc + sizeof(struct ether_header));
        for (i=0; i<3; i++) {
            // ignore packets whose destination is in the private address range on the client
            if ((cliserv == CLIENT) && (iphdr->ip_dst.s_addr >= private_start[i]) && (iphdr->ip_dst.s_addr <= private_end[i])) {
                if_stats.if_dropped_pkts[rxq->if_index]++;
                continue;
            }
            mbuf->for_home = false;
            if ((cliserv == SERVER) && (iphdr->ip_dst.s_addr == client_addr[i].sin_addr.s_addr) || (iphdr->ip_dst.s_addr == client_addr[i].sin_addr.s_addr)) mbuf->for_home = true;
        }
#endif

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
// | Transmit thread, one is started on each interface, three on the home gateway
// | one on the vps. Note that, unlike the rx interfaces on the home gateway,
// | each tx interface has it's own circular buffer.
// +----------------------------------------------------------------------------
static void *tx_thread(void * arg)
{
    struct if_queue_s   *txq = (struct if_queue_s *) arg;
    struct mbuf_s       *mbuf=NULL;
    unsigned char       *mbufc;
    ssize_t             txSz;
#ifdef IPV6
    struct ip6_hdr      *iphdr;
#else
    struct ip           *iphdr;
#endif

    while (txq->if_thread->keep_going) {
        while ((sem_wait(&txq->if_ready) == -1) && (errno == EINTR));
        if ((mbuf = (struct mbuf_s*) circular_buffer_pop(txq->if_pkts)) == NULL) continue;
        mbufc   = (unsigned char *) mbuf;
#ifdef IPV6
        iphdr   = (struct ip6_hdr *) mbufc;
        // TODO: deal with partial packet send
        while (((txSz = write(if_config[txq->if_index].if_tx_fd, (const void *) mbuf, iphdr->ip6_plen+sizeof(struct ip6_hdr))) == -1) && (errno==EINTR));
#else
        iphdr   = (struct ip *) mbufc;
        // TODO: deal with partial packet send
        while (((txSz = write(if_config[txq->if_index].if_tx_fd, (const void *) mbuf, iphdr->ip_len+sizeof(struct ip))) == -1) && (errno==EINTR));
#endif        
        if (txSz == -1) {
            log_msg(LOG_ERR, "%s-%d: Error sending ip packet on interface %s - %s.\n",
                    __FUNCTION__, __LINE__, if_config[txq->if_index].if_name, strerror(errno));
        }
        mempool_free(mPool, mbuf, wipebufs);
        if_stats.if_tx_pkts[txq->if_index]++;
        if_stats.if_tx_bytes[txq->if_index] += txSz;
    }

    thread_exit_rc = 0;
    pthread_exit(&thread_exit_rc);
}


// +----------------------------------------------------------------------------
// | Recalculate the ip header checksum.
// +----------------------------------------------------------------------------
unsigned short iphdr_checksum(unsigned short* buff, int _16bitword)
{
    unsigned long sum;
    for(sum=0;_16bitword>0;_16bitword--)
        sum += htons(*(buff)++);
    sum  = ((sum >> 16) + (sum & 0xFFFF));
    sum += (sum>>16);
    return (unsigned short)(~sum);
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
#ifdef IPV6
    struct in6_addr *sv_dest_addr;
    struct ip6_hdr  *iphdr;
#else
    struct in_addr  *sv_dest_addr;
    struct ip       *iphdr;
#endif

    while (dsl_threads[HOME_TO_VPS_PKT_MANGLER_THREADNO].keep_going) {
        sem_wait(&if_config[INGRESS_IF].if_rxq.if_ready);
        if ((mbuf = circular_buffer_pop(if_config[INGRESS_IF].if_rxq.if_pkts)) == NULL) continue;
        mbufc                   = (unsigned char *) mbuf;
        // Save the destination address at the end of the packet. Also save the if_ratios
        // in one byte at the end of the packet. Increase packet length by the length
        // of the destination address plus 1 byte for if_ratios. Replace destination
        // address with vps ip address, so packet will go to the vps.
#ifdef IPV6
        iphdr                   = (struct ip6_hdr *) (mbufc + sizeof(struct ether_header));
        sv_dest_addr            = (struct in6_addr *) (mbufc + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + iphdr->ip6_plen);
        memcpy(sv_dest_addr, &iphdr->ip6_dst, sizeof(struct in6_addr));
        if_ratios               = (uint8_t *) (mbufc + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + iphdr->ip6_plen + sizeof(struct in6_addr));
        memcpy(&iphdr->ip6_dst, &peer_addr.sin6_addr, sizeof(struct in6_addr));
        iphdr->ip6_plen         = iphdr->ip6_plen + sizeof(struct in6_addr) + 2;
#else
        iphdr                   = (struct ip *) (mbufc + sizeof(struct ether_header));
        sv_dest_addr            = (struct in_addr *) (mbufc + sizeof(struct ether_header) + iphdr->ip_len);
        memcpy(sv_dest_addr, &iphdr->ip_dst, sizeof(struct in_addr));
        if_ratios               = (uint8_t *) (mbufc + sizeof(struct ether_header) + iphdr->ip_len + sizeof(struct in_addr));
        iphdr->ip_dst.s_addr    = peer_addr.sin_addr.s_addr;
        iphdr->ip_len           = iphdr->ip_len + sizeof(struct in_addr) + 2;
        iphdr->ip_sum           = iphdr_checksum((unsigned short*)(mbufc + sizeof(struct ether_header)), (sizeof(struct iphdr)/2));
#endif
        if_ratios[0]            = if_config[0].if_ratio;
        if_ratios[1]            = if_config[1].if_ratio;
        circular_buffer_push(if_config[active_if].if_txq.if_pkts, mbuf);
        sem_post(&if_config[active_if].if_txq.if_ready);
        active_if               = (active_if+1) % NUM_EGRESS_INTERFACES;
    }

    thread_exit_rc = 0;
    pthread_exit(&thread_exit_rc);
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
#ifdef IPV6
    struct in6_addr *sv_dest_addr;
    struct ip6_hdr  *iphdr;
#else
    struct in_addr  *sv_dest_addr;
    struct ip       *iphdr;
#endif

    for (i=0; i<REORDER_BUF_SZ; i++) reorder_buf[i] = NULL;
    while (dsl_threads[HOME_FROM_VPS_PKT_MANGLER_THREADNO].keep_going) {
        sem_wait(&if_config[EGRESS_IF].if_rxq.if_ready);
        if ((mbuf = circular_buffer_pop(if_config[EGRESS_IF].if_rxq.if_pkts)) == NULL) continue;
        mbufc                   = (unsigned char *) mbuf;
#ifdef IPV6
        iphdr                   = (struct ip6_hdr *) (mbufc + sizeof(struct ether_header));
        sv_dest_addr            = (struct in6_addr *) (mbufc + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + iphdr->ip6_plen);
        seq_no                  = (uint8_t *) (mbufc + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + iphdr->ip6_plen + sizeof(struct in6_addr));
        memcpy(iphdr->ip6_dst.s6_addr, sv_dest_addr, sizeof(struct in6_addr));
        iphdr->ip6_plen         = iphdr->ip6_plen - sizeof(struct in6_addr) - 1;
#else
        iphdr                   = (struct ip *) (mbufc + sizeof(struct ether_header));
        sv_dest_addr            = (struct in_addr *) (mbufc + sizeof(struct ether_header) + iphdr->ip_len);
        seq_no                  = (uint8_t *) (mbufc + sizeof(struct ether_header) + iphdr->ip_len + sizeof(struct in_addr));
        memcpy(&iphdr->ip_dst, sv_dest_addr, sizeof(struct in_addr));
        iphdr->ip_len           = iphdr->ip_len - sizeof(struct in_addr) - 1;
        iphdr->ip_sum           = iphdr_checksum((unsigned short*)(mbufc + sizeof(struct ether_header)), (sizeof(struct iphdr)/2));
#endif
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
#ifdef IPV6
    struct in6_addr *sv_dest_addr;
    struct ip6_hdr  *iphdr;
#else
    struct in_addr  *sv_dest_addr;
    struct ip       *iphdr;
#endif

    active_if_cnt[0] = active_if_cnt[1] = 0;
    while (dsl_threads[VPS_PKT_MANGLER_THREADNO].keep_going) {
        sem_wait(&if_config[EGRESS_IF].if_rxq.if_ready);
        if ((mbuf = circular_buffer_pop(if_config[EGRESS_IF].if_rxq.if_pkts)) == NULL) continue;
        mbufc                       = (unsigned char *) mbuf;
#ifdef IPV6
        iphdr                   = (struct ip6_hdr *) (mbufc + sizeof(struct ether_header));
        sv_dest_addr            = (struct in6_addr *) (mbufc + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + iphdr->ip6_plen);
        seq_no                  = (uint8_t *) (mbufc + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + iphdr->ip6_plen + sizeof(struct in6_addr));
#else
        iphdr                   = (struct ip *) (mbufc + sizeof(struct ether_header));
        sv_dest_addr            = (struct in_addr *) (mbufc + sizeof(struct ether_header) + iphdr->ip_len);
        seq_no                  = (uint8_t *) (mbufc + sizeof(struct ether_header) + iphdr->ip_len + sizeof(struct in_addr));
#endif
        if (mbuf->for_home) {
            // This packet is from the internet, send it to the home gateway
#ifdef IPV6
            memcpy(sv_dest_addr, iphdr->ip6_dst.s6_addr, sizeof(struct in6_addr));
            memcpy(iphdr->ip6_dst.s6_addr, &client_addr[active_if].sin6_addr, sizeof(struct in6_addr));
            iphdr->ip6_plen         = iphdr->ip6_plen + sizeof(struct in6_addr) + 1;
#else
            memcpy(sv_dest_addr, &iphdr->ip_dst, sizeof(struct in_addr));
            iphdr->ip_dst.s_addr    = client_addr[active_if].sin_addr.s_addr;
            iphdr->ip_len           = iphdr->ip_len + sizeof(struct in_addr) + 1;
            iphdr->ip_sum           = iphdr_checksum((unsigned short*)(mbufc + sizeof(struct ether_header)), (sizeof(struct iphdr)/2));
#endif            
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
#ifdef IPV6
            memcpy(iphdr->ip6_dst.s6_addr, sv_dest_addr, sizeof(struct in6_addr));
            iphdr->ip6_plen         = iphdr->ip6_plen - sizeof(struct in6_addr) - 1;
#else
            memcpy(&iphdr->ip_dst, sv_dest_addr, sizeof(struct in_addr));
            iphdr->ip_len           = iphdr->ip_len - sizeof(struct in_addr) - 1;
            iphdr->ip_sum           = iphdr_checksum((unsigned short*)(mbufc + sizeof(struct ether_header)), (sizeof(struct iphdr)/2));
#endif            
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
// | Create one of the threads
// +----------------------------------------------------------------------------
static void create_one_thread(int thread_idx)
{
    int rc;

    if (cliserv == CLIENT) {
        switch (thread_idx) {
            case 0:
            case 1:
            case 2:
                snprintf(dsl_threads[thread_idx].thread_name, 16, "rx_thread%02d", thread_idx);
                if ((rc = create_thread(&dsl_threads[thread_idx].thread_id, rx_thread, RXPRIO, dsl_threads[thread_idx].thread_name, (void *) &if_config[thread_idx].if_rxq)) != 0) {
                    log_msg(LOG_ERR, "%s-%d: Can not create rx thread for interface %s - %s.\n", __FUNCTION__, __LINE__, if_config[thread_idx].if_name, strerror(rc));
                    exit_level1_cleanup();
                    exit(rc);
                }
                break;
            case 3:
            case 4:
            case 5:
                snprintf(dsl_threads[thread_idx].thread_name, 16, "tx_thread%02d", thread_idx);
                if ((rc = create_thread(&dsl_threads[thread_idx].thread_id, tx_thread, TXPRIO, dsl_threads[thread_idx].thread_name, (void *) &if_config[thread_idx-3].if_txq)) != 0) {
                    log_msg(LOG_ERR, "%s-%d: Can not create tx thread for interface %s - %s.\n", __FUNCTION__, __LINE__, if_config[thread_idx-3].if_name, strerror(rc));
                    exit_level1_cleanup();
                    exit(rc);
                }
                break;
            case 6:
                snprintf(dsl_threads[HOME_TO_VPS_PKT_MANGLER_THREADNO].thread_name, 16, "home_to_vps");
                if ((rc = create_thread(&dsl_threads[HOME_TO_VPS_PKT_MANGLER_THREADNO].thread_id, home_to_vps_pkt_mangler_thread, HOME_TO_VPS_PRIO, dsl_threads[HOME_TO_VPS_PKT_MANGLER_THREADNO].thread_name, NULL)) != 0) {
                    log_msg(LOG_ERR, "%s-%d: Can not create home to vps thread - %s.\n", __FUNCTION__, __LINE__, strerror(rc));
                    exit_level1_cleanup();
                    exit(rc);
                }
                break;
            case 7:
                snprintf(dsl_threads[HOME_FROM_VPS_PKT_MANGLER_THREADNO].thread_name, 16, "home_from_vps");
                if ((rc = create_thread(&dsl_threads[HOME_FROM_VPS_PKT_MANGLER_THREADNO].thread_id, home_from_vps_pkt_mangler_thread, HOME_FROM_VPS_PRIO, dsl_threads[HOME_FROM_VPS_PKT_MANGLER_THREADNO].thread_name, NULL)) != 0) {
                    log_msg(LOG_ERR, "%s-%d: Can not create home from vps thread - %s.\n", __FUNCTION__, __LINE__, strerror(rc));
                    exit_level1_cleanup();
                    exit(rc);
                }
                break;
        }
    } else {
        switch (thread_idx) {
            case 0:
                snprintf(dsl_threads[0].thread_name, 16, "rx_thread");
                if ((rc = create_thread(&dsl_threads[0].thread_id, rx_thread, RXPRIO, dsl_threads[0].thread_name, (void *) &if_config[EGRESS_IF].if_rxq)) != 0) {
                    log_msg(LOG_ERR, "%s-%d: Can not create rx thread for interface %s - %s.\n", __FUNCTION__, __LINE__, if_config[EGRESS_IF].if_name, strerror(rc));
                    exit_level1_cleanup();
                    exit(rc);
                }
                break;
            case 1:
                snprintf(dsl_threads[1].thread_name, 16, "tx_thread");
                if ((rc = create_thread(&dsl_threads[1].thread_id, tx_thread, TXPRIO, dsl_threads[1].thread_name, (void *) &if_config[EGRESS_IF].if_txq)) != 0) {
                    log_msg(LOG_ERR, "%s-%d: Can not create tx thread for interface %s - %s.\n", __FUNCTION__, __LINE__, if_config[EGRESS_IF].if_name, strerror(rc));
                    exit_level1_cleanup();
                    exit(rc);
                }
                break;
            case 2:
                snprintf(dsl_threads[VPS_PKT_MANGLER_THREADNO].thread_name, 16, "vps_pkt_mangler");
                if ((rc = create_thread(&dsl_threads[VPS_PKT_MANGLER_THREADNO].thread_id, vps_pkt_mangler_thread, VPS_PKT_MANGLER_PRIO, dsl_threads[VPS_PKT_MANGLER_THREADNO].thread_name, NULL)) != 0) {
                    log_msg(LOG_ERR, "%s-%d: Can not create vps packet mangler thread - %s.\n", __FUNCTION__, __LINE__, strerror(rc));
                    exit_level1_cleanup();
                    exit(rc);
                }
                break;
        }
    }
}

// +----------------------------------------------------------------------------
// | Create all the client threads
// +----------------------------------------------------------------------------
static int create_threads(int thread_cnt)
{
    int     i;

    for (i=0; i<thread_cnt; i++) create_one_thread(i);

    num_threads = thread_cnt;
}


// +----------------------------------------------------------------------------
// | Connect to the server on the comms port
// +----------------------------------------------------------------------------
static int reconnect_comms_to_server(void)
{
    char            s[INET6_ADDRSTRLEN];
    struct ifreq    ifr;
    int             rc;

    if (debug) log_msg(LOG_INFO, "%s-%d\n", __FUNCTION__, __LINE__);
    close(comms_peer_fd);
    memset(&ifr, 0, sizeof(ifr));
#ifdef IPV6
    if ((comms_peer_fd = socket(AF_INET6, SOCK_STREAM, 0)) == -1) {
        log_msg(LOG_ERR, "%s-%d: Can not create socket for server connection - %s\n", __FUNCTION__, __LINE__, strerror(errno));
        return errno;
    }
    peer_addr.sin6_port     = htons((unsigned short)rmt_port);
    ifr.ifr_addr.sa_family  = peer_addr.sin6_family;
    inet_ntop(AF_INET6, get_in_addr((struct sockaddr *)&peer_addr), s, sizeof s);
#else    
    if ((comms_peer_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        log_msg(LOG_ERR, "%s-&d: Can not create socket for server connection - %s\n", __FUNCTION__, __LINE__, strerror(errno));
        return errno;
        }
    peer_addr.sin_port      = htons((unsigned short)rmt_port);
    ifr.ifr_addr.sa_family  = peer_addr.sin_family;
    inet_ntop(AF_INET, get_in_addr((struct sockaddr *)&peer_addr), s, sizeof s);
#endif
    strncpy(ifr.ifr_name, if_config[EGRESS_IF].if_name, sizeof(ifr.ifr_name));
    // Bind raw socket to the primary egress interface (eg: ppp0)
    if (setsockopt(comms_peer_fd, SOL_SOCKET, SO_BINDTODEVICE, (void *) &ifr, sizeof(ifr)) < 0) {
        rc = errno;
        log_msg(LOG_ERR, "%s-%d: Can not bind comms peer socket to %s - %s.\n", __FUNCTION__, __LINE__, ifr.ifr_name, strerror(errno));
        exit_level1_cleanup();
        exit(rc);
        }
    log_msg(LOG_INFO, "Waiting for connection to server at %s...\n", s);
    if (connect(comms_peer_fd, (struct sockaddr *) &peer_addr, sizeof(peer_addr)) == -1) {
        log_msg(LOG_INFO, "Not connected - %s.\n", strerror(errno));
        return errno;
    }
    log_msg(LOG_INFO, "Connected to %s.\n", s);
    peer_addr_valid = true;
    return 0;
}

// +----------------------------------------------------------------------------
// | Handle a query on the comms socket
// +----------------------------------------------------------------------------
static int handle_client_query(struct comms_query_s *query, int comms_client_fd, bool *connection_active)
{
    int                     rc, i;
    struct comms_reply_s    reply;
    void                    *thread_rc;
    char                    client_ip_str[2][INET6_ADDRSTRLEN];

    if (query->for_peer) {
        if (peer_addr_valid) {
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
#ifdef IPV6
                memcpy(&client_addr[0], &query->helo_data.egress_addr[0], sizeof(struct sockaddr_in6));
                memcpy(&client_addr[1], &query->helo_data.egress_addr[1], sizeof(struct sockaddr_in6));
                memcpy(&if_stats.client_sa[0], &query->helo_data.egress_addr[0], sizeof(struct sockaddr_in6));
                memcpy(&if_stats.client_sa[1], &query->helo_data.egress_addr[1], sizeof(struct sockaddr_in6));
#else
                memcpy(&client_addr[0], &query->helo_data.egress_addr[0], sizeof(struct sockaddr_in));
                memcpy(&client_addr[1], &query->helo_data.egress_addr[1], sizeof(struct sockaddr_in));
                memcpy(&if_stats.client_sa[0], &query->helo_data.egress_addr[0], sizeof(struct sockaddr_in));
                memcpy(&if_stats.client_sa[1], &query->helo_data.egress_addr[1], sizeof(struct sockaddr_in));
#endif
                if_stats.client_connected   = true;
                if_config[0].if_ratio       = query->helo_data.if_ratio[0];
                if_config[1].if_ratio       = query->helo_data.if_ratio[1];
                cc_port                     = query->helo_data.cc_port;
                reply.rc                    = 0;
#ifdef IPV6
                inet_ntop(AF_INET6, get_in_addr((struct sockaddr *)&client_addr[0]), client_ip_str[0], INET6_ADDRSTRLEN);
                inet_ntop(AF_INET6, get_in_addr((struct sockaddr *)&client_addr[1]), client_ip_str[1], INET6_ADDRSTRLEN);
#else
                inet_ntop(AF_INET, get_in_addr((struct sockaddr *)&client_addr[0]), client_ip_str[0], INET6_ADDRSTRLEN);
                inet_ntop(AF_INET, get_in_addr((struct sockaddr *)&client_addr[1]), client_ip_str[1], INET6_ADDRSTRLEN);
#endif
                log_msg(LOG_INFO, "HELO received.");
                log_msg(LOG_INFO, "Client address1: %s  Client address2: %s.\n", client_ip_str[0], client_ip_str[1]);
                log_msg(LOG_INFO, "IF ratio1: %u  IF ratio2: %u  Port: %u", if_config[0].if_ratio, if_config[1].if_ratio, cc_port);
                if ((cliserv == SERVER) && (!peer_addr_valid)) {
                    memcpy(&peer_addr, &client_addr[0], sizeof(peer_addr));
                    reconnect_comms_to_server();
                }
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
            case COMMS_STARTTHREAD:
                if (dsl_threads[query->num_thread].keep_going == false) create_one_thread(query->num_thread);
                reply.rc    = 0;
                break;
            case COMMS_STOPTHREAD:
                if (dsl_threads[query->num_thread].keep_going) {
                    dsl_threads[query->num_thread].keep_going = false;
                    pthread_join(dsl_threads[query->num_thread].thread_id, &thread_rc);
                    free(thread_rc);
                }
                reply.rc    = 0;
                break;
            case COMMS_LISTTHREADS:
                for (i=0; i<num_threads; i++) {
                    memcpy(reply.thread_names[i], dsl_threads[i].thread_name, 17);
                    reply.thread_status[i] = dsl_threads[i].keep_going;
                }
                reply.num_threads   = num_threads;
                reply.rc            = 0;
                break;
            case COMMS_KILL:
                exit_level1_cleanup();
                exit(EXIT_SUCCESS);
                break;
            case COMMS_EXIT:
                *connection_active  = false;
                break;
            default:
                reply.rc    = -1;
        }
    }

    if (cliserv == CLIENT) reply.is_client = true;
    else reply.is_client = false;
    send(comms_client_fd, &reply, sizeof(struct comms_reply_s), 0);
}


// +----------------------------------------------------------------------------
// | Thread to handle communication channel, one spawned for each connection
// +----------------------------------------------------------------------------
static void *comms_thread(void *arg)
{
    struct comms_thread_parms_s *thread_parms  = (struct comms_thread_parms_s *) arg;
    bool                        connection_active;
    struct comms_query_s        client_query;
    int                         rc;
    
    connection_active = true;
    while(connection_active) {
        if ((rc = recv(thread_parms->peer_fd, &client_query, sizeof(struct comms_query_s), 0)) > 0) {
            handle_client_query(&client_query, thread_parms->peer_fd, &connection_active);
        } else if (rc == 0) {
            connection_active = false;
        } else if (errno == EINTR) {
            continue;
        } else {
            log_msg(LOG_WARNING, "%s-%d: Error receiving comms message from client - %s", __FUNCTION__, __LINE__, strerror(errno));
        }
    }
    close(thread_parms->peer_fd);
    pthread_exit(NULL);
}


// +----------------------------------------------------------------------------
// | Create comms channel
// +----------------------------------------------------------------------------
static void create_comms_channel(unsigned int port, int *commsfd)
{
    int                         rc;
#ifdef IPV6
    struct sockaddr_in6         bind_addr;
#else
    struct sockaddr_in          bind_addr;
#endif
    
    bzero((char *) &bind_addr, sizeof(bind_addr));
#ifdef IPV6
    if ((*commsfd = socket(AF_INET6, SOCK_STREAM, 0)) == -1) {
        rc = errno;
        log_msg(LOG_ERR, "%s-%d: Error creating comms socket - %s.\n", __FUNCTION__, __LINE__, strerror(rc));
        exit_level1_cleanup();
        exit(rc);
    }
    bind_addr.sin6_family   = AF_INET6;
    bind_addr.sin6_addr     = in6addr_any;
    bind_addr.sin6_port     = htons((unsigned short)port);
#else    
    if ((*commsfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        rc = errno;
        log_msg(LOG_ERR, "%s-%d: Error creating comms socket - %s.\n", __FUNCTION__, __LINE__, strerror(rc));
        close(*commsfd);
        exit_level1_cleanup();
        exit(rc);
    }
    bind_addr.sin_family        = AF_INET;
    bind_addr.sin_addr.s_addr   = htonl(INADDR_ANY);
    bind_addr.sin_port          = htons((unsigned short)port);
#endif
    if (setsockopt(*commsfd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) == -1) {
        log_msg(LOG_WARNING, "%s-%d: Error setting reuse address on comms socket.\n", __FUNCTION__, __LINE__);
    }
    if (bind(*commsfd, (struct sockaddr *) &bind_addr, sizeof(bind_addr)) == -1) {
        rc = errno;
        log_msg(LOG_ERR, "%s-%d: Can not bind comms socket - %s.\n", __FUNCTION__, __LINE__, strerror(rc));
        close(*commsfd);
        exit_level1_cleanup();
        exit(rc);
    }

    if (listen(*commsfd, 5) == -1) {
        rc = errno;
        log_msg(LOG_ERR, "%s-%d: Can not listen on comms socket - %s.\n", __FUNCTION__, __LINE__, rc);
        close(*commsfd);
        exit_level1_cleanup();
        exit(rc);
    }
}

// +----------------------------------------------------------------------------
// | Thread to handle remote communication channel
// +----------------------------------------------------------------------------
static void *remote_comms_thread(void *arg)
{
    struct comms_thread_parms_s *thread_parms  = (struct comms_thread_parms_s *) arg;
    int                         comms_client_fd;
    char                        ipaddr[INET6_ADDRSTRLEN];
    struct comms_thread_parms_s *comms_thread_parms;
    socklen_t                   sin_size;
    int                         rc;
#ifdef IPV6
    struct sockaddr_in6         comms_client_addr;
#else
    struct sockaddr_in          comms_client_addr;
#endif

    for(;;) {
        if ((comms_client_fd = accept(thread_parms->peer_fd, (struct sockaddr *)&comms_client_addr, &sin_size)) < 0) {
            log_msg(LOG_ERR, "%s-%d: Error accepting comms connection - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
            continue;
        }
#ifdef IPV6
        inet_ntop(AF_INET6, get_in_addr((struct sockaddr *)&comms_client_addr), ipaddr, sizeof ipaddr);
#else
        inet_ntop(AF_INET, get_in_addr((struct sockaddr *)&comms_client_addr), ipaddr, sizeof ipaddr);
#endif
        log_msg(LOG_INFO, "Accepted connection from %s.\n", ipaddr);
        if ((comms_thread_parms = (struct comms_thread_parms_s *) malloc(sizeof(struct comms_thread_parms_s))) == NULL) {
            log_msg(LOG_ERR, "%s-%d: Out of memory.\n", __FUNCTION__, __LINE__);
            close(comms_client_fd);
            continue;
        }
        comms_thread_parms->peer_fd = comms_client_fd;
        if ((rc = create_thread(&comms_thread_parms->thread_id, comms_thread, 1, "comms_thread", (void *) comms_thread_parms)) != 0) {
            log_msg(LOG_ERR, "%s-%d: Can not create comms thread for connection from %s - %s.\n", __FUNCTION__, __LINE__, ipaddr, strerror(rc));
        }
    }
    pthread_exit(NULL);
}


// +----------------------------------------------------------------------------
// | Read the config file and set all the appropriate variables from the values.
// +----------------------------------------------------------------------------
static void read_config_file(void)
{
    config_t                cfg;
    const config_setting_t  *config_egress_list;
    const char              *config_string;
    
    config_init(&cfg);
    
    if (!config_read_file(&cfg, config_file_name)) {
        log_msg(LOG_ERR, "%s-%d: Error reading config file, all parameters revert to defaults.\n", __FUNCTION__, __LINE__);
        return;
    }
    
    if (config_lookup_int(&cfg, "is_server", &cliserv))
        log_msg(LOG_INFO, "Configured for %s mode.\n", cliserv == SERVER ? "server" : "client");
    else {
        cliserv = CLIENT;
        log_msg(LOG_INFO, "Configured for client mode.\n");
    }
    if (config_lookup_int(&cfg, "port", &cc_port))
        log_msg(LOG_INFO, "Configured for comms port on %d.\n", cc_port);
    if (config_lookup_int(&cfg, "remote_port", &rmt_port))
        log_msg(LOG_INFO, "Configured for remote comms port on %d.\n", rmt_port);
    if (config_lookup_int(&cfg, "mbufs", &n_mbufs))
        log_msg(LOG_INFO, "Configured for %d mbufs.\n", n_mbufs);
    if (cliserv == CLIENT) {
        if (config_lookup_string(&cfg, "client.ingress.tap", &config_string)) {
            ingresscnt = 1;
            strcpy(if_config[INGRESS_IF].if_name, config_string);
            log_msg(LOG_INFO, "Configured for client ingress tap on %s.\n", if_config[INGRESS_IF].if_name);
        }
        if (config_lookup_string(&cfg, "client.ingress.bridge", &config_string)) {
            strcpy(if_config[INGRESS_IF].if_brname, config_string);
            log_msg(LOG_INFO, "Configured for client ingress bridge on %s.\n", if_config[INGRESS_IF].if_brname);
        } else ingresscnt = 0;
        if (config_lookup_string(&cfg, "client.server_name", &config_string)) {
            strcpy(remote_name, config_string);
            log_msg(LOG_INFO, "Configured for server name %s.\n", remote_name);
        }
        config_egress_list = config_lookup(&cfg, "client.egress.interface");
        if (config_setting_length(config_egress_list) == 2) {
            egresscnt = 2;
            strcpy(if_config[EGRESS_IF].if_name, config_setting_get_string_elem(config_egress_list, 0));
            strcpy(if_config[EGRESS_IF+1].if_name, config_setting_get_string_elem(config_egress_list, 1));
            log_msg(LOG_INFO, "Configured for client egress interfaces on %s and %s.\n", if_config[EGRESS_IF].if_name, if_config[EGRESS_IF+1].if_name);
        }
    } else {
        if (config_lookup_string(&cfg, "server.interface", &config_string)) {
            strcpy(if_config[EGRESS_IF].if_name, config_string);
            egresscnt = 1;
            log_msg(LOG_INFO, "Configured for server interface on %s.\n", if_config[EGRESS_IF].if_name);
        }
    }
    
    config_destroy(&cfg);
}


// +----------------------------------------------------------------------------
// | Main processing.
// +----------------------------------------------------------------------------
int main(int argc, char *argv[])
{
    int                         option, i, rc, commsfd, rmt_commsfd, comms_client_fd;
    bool                        daemonize = true;
    pid_t                       pid, sid;
    struct sigaction            sigact;
    struct sched_param          sparam;
#ifdef IPV6
    struct sockaddr_in6         comms_client_addr;
#else
    struct sockaddr_in          comms_client_addr;
#endif
    struct sigevent             se;
    socklen_t                   sin_size;
    struct ifaddrs              *ifa, *ifa_p;
    char                        ipaddr[INET6_ADDRSTRLEN];
    struct comms_thread_parms_s *comms_thread_parms;
    struct comms_query_s        client_query;
    struct comms_reply_s        client_response;
    struct ifreq                ifr;

    i=0;
    if (argv[0][0] == '.' || argv[0][0] == '/') i++;
    if (argv[0][1] == '.' || argv[0][1] == '/') i++;
    progname = &argv[0][i];
    
    memset(config_file_name, 0, PATH_MAX);
    strcpy(config_file_name, DEFAULT_CONFIG_FILE_NAME);

    for (i=0; i<NUM_INGRESS_INTERFACES+NUM_EGRESS_INTERFACES; i++) {
        memset(&if_config[i], 0, sizeof(struct if_config_s));
        if_config[i].if_ratio     = 1;
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
    if (cliserv == -1) {
        log_msg(LOG_ERR, "You must define server or client mode in config file.\n\n");
        exit(EINVAL);
    }

    if (cliserv == CLIENT && strlen(remote_name) == 0) {
        log_msg(LOG_ERR, "You must provide a server ip or name in config file.\n\n");
        exit(EINVAL);
    }

    if (cliserv == CLIENT && ingresscnt == 0) {
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
    for (i=0; i<egresscnt; i++) {
        // Open raw socket for egress interface
#ifdef IPV6
        if ((if_config[i].if_tx_fd = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW)) < 0) {
#else
        if ((if_config[i].if_tx_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
#endif
            rc = errno;
            log_msg(LOG_ERR, "%s-%d: Can not create socket for egress interface %d - %s.\n", __FUNCTION__, __LINE__, i, strerror(errno));
            exit_level1_cleanup();
            exit(rc);
        } else if_config[i].if_rx_fd = if_config[i].if_tx_fd;
        memset(&ifr, 0, sizeof(ifr));
#ifdef IPV6
        ifr.ifr_addr.sa_family = AF_INET6;
#else        
        ifr.ifr_addr.sa_family = AF_INET;
#endif
        strncpy(ifr.ifr_name, if_config[i].if_name, sizeof(ifr.ifr_name));
        // Bind raw socket to a particular interface name (eg: ppp0 or ppp1)
        if (setsockopt(if_config[i].if_tx_fd, SOL_SOCKET, SO_BINDTODEVICE, (void *) &ifr, sizeof(ifr)) < 0) {
            rc = errno;
            log_msg(LOG_ERR, "%s-%d: Can not bind socket to %s - %s.\n", __FUNCTION__, __LINE__, ifr.ifr_name, strerror(errno));
            exit_level1_cleanup();
            exit(rc);
        }
        // Setup the rx queue
        if_config[i].if_rxq.if_index  = i;
        if_config[i].if_rxq.if_thread = &dsl_threads[i*2];
        if (i == 0) {
            // Only create one circular buffer and semaphore for both rx queues
            if ((if_config[i].if_rxq.if_pkts = circular_buffer_create(n_mbufs/(ingresscnt+egresscnt), mPool)) == CIRCULAR_BUFFER_INVALID) {
                log_msg(LOG_ERR, "%s-%d: Failure to create rx circular buffer for index %d.\n", __FUNCTION__, __LINE__, i);
                exit_level1_cleanup();
                exit(ENOMEM);
            }
            if (sem_init(&if_config[i].if_rxq.if_ready, 0, 0) == -1) {
                rc = errno;
                log_msg(LOG_ERR, "%s-%d: Failure to create rx queue semaphore for index %d - %s.\n", __FUNCTION__, __LINE__, i, strerror(errno));
                exit_level1_cleanup();
                exit(rc);
            }
        } else {
            if_config[i].if_rxq.if_pkts   = if_config[0].if_rxq.if_pkts;
            if_config[i].if_rxq.if_ready  = if_config[0].if_rxq.if_ready;
        }
        // Set up the tx queue
        if_config[i].if_txq.if_index  = i;
        if_config[i].if_txq.if_thread = &dsl_threads[(i*2)+1];
        // Each tx interface has it's own circular buffer and semaphore, unlike the rx interfaces
        if ((if_config[i].if_txq.if_pkts = circular_buffer_create(n_mbufs/(ingresscnt+egresscnt), mPool)) == CIRCULAR_BUFFER_INVALID) {
            log_msg(LOG_ERR, "%s-%d: Failure to create tx circular buffer for index %d.\n", __FUNCTION__, __LINE__, i);
            exit_level1_cleanup();
            exit(ENOMEM);
        }
        if (sem_init(&if_config[i].if_txq.if_ready, 0, 0) == -1) {
            rc = errno;
            log_msg(LOG_ERR, "%s-%d: Failure to create tx queue semaphore for index %d - %s.\n", __FUNCTION__, __LINE__, i, strerror(errno));
            exit_level1_cleanup();
            exit(rc);
        }
    }

    // Get ip addrs of all interfaces
    if (getifaddrs(&ifa) == -1) {
            rc = errno;
        log_msg(LOG_ERR, "%s-%d: Failure to get interface ip addresses - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
            exit_level1_cleanup();
            exit(rc);
        }
    ifa_p = ifa;
    while (ifa_p) {
        if ((ifa_p->ifa_addr) && ((ifa_p->ifa_addr->sa_family == AF_INET) ||
                                  (ifa_p->ifa_addr->sa_family == AF_INET6))) {
#ifdef IPV6
            if (ifa_p->ifa_addr->sa_family == AF_INET6) {
                for (i=0; i<egresscnt+ingresscnt; i++) {
                    if (i == INGRESS_IF) {
                        if (strcmp(if_config[i].if_brname, ifa_p->ifa_name) == 0) {
                            memcpy(&if_config[i].if_ipaddr, ifa_p->ifa_addr, sizeof(struct sockaddr_in6));
                            inet_ntop(AF_INET6, get_in_addr((struct sockaddr *)&if_config[i].if_ipaddr), ipaddr, sizeof(ipaddr));
                            log_msg(LOG_INFO, "Interface %s has ip address %s\n", if_config[i].if_brname, ipaddr);
                        }
                    } else {
                        if (strcmp(if_config[i].if_name, ifa_p->ifa_name) == 0) {
                            memcpy(&if_config[i].if_ipaddr, ifa_p->ifa_addr, sizeof(struct sockaddr_in6));
                            inet_ntop(AF_INET6, get_in_addr((struct sockaddr *)&if_config[i].if_ipaddr), ipaddr, sizeof(ipaddr));
                            log_msg(LOG_INFO, "Interface %s has ip address %s\n", if_config[i].if_name, ipaddr);
                        }
                    }
                }
            }
#else
            if (ifa_p->ifa_addr->sa_family == AF_INET) {
                for (i=0; i<egresscnt+ingresscnt; i++) {
                    if (i == INGRESS_IF) {
                        if (strcmp(if_config[i].if_brname, ifa_p->ifa_name) == 0) {
                            memcpy(&if_config[i].if_ipaddr, ifa_p->ifa_addr, sizeof(struct sockaddr_in));
                            inet_ntop(AF_INET, get_in_addr((struct sockaddr *)&if_config[i].if_ipaddr), ipaddr, sizeof(ipaddr));
                            log_msg(LOG_INFO, "Interface %s has ip address %s\n", if_config[i].if_brname, ipaddr);
                        }
                    } else {
                        if (strcmp(if_config[i].if_name, ifa_p->ifa_name) == 0) {
                            memcpy(&if_config[i].if_ipaddr, ifa_p->ifa_addr, sizeof(struct sockaddr_in));
                            inet_ntop(AF_INET, get_in_addr((struct sockaddr *)&if_config[i].if_ipaddr), ipaddr, sizeof(ipaddr));
                            log_msg(LOG_INFO, "Interface %s has ip address %s\n", if_config[i].if_name, ipaddr);
                        }
                    }
                }
            }
#endif
        }
        ifa_p = ifa_p->ifa_next;
    }

    if (cliserv == CLIENT) {
        // Open ingress rx tap interface
        if ((if_config[INGRESS_IF].if_rx_fd = tuntap_init(if_config[INGRESS_IF].if_name)) < 0) {
            exit_level1_cleanup();
            exit(-1*if_config[INGRESS_IF].if_rx_fd);
        }
        // Open raw socket for ingress tx interface
#ifdef IPV6
        if ((if_config[INGRESS_IF].if_tx_fd = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW)) < 0)
#else
        if ((if_config[INGRESS_IF].if_tx_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
#endif
        {
            rc = errno;
            log_msg(LOG_ERR, "%s-%d: Can not create socket for ingress interface - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
            exit_level1_cleanup();
            exit(rc);
        }
        memset(&ifr, 0, sizeof(ifr));
#ifdef IPV6
        ifr.ifr_addr.sa_family = AF_INET6;
#else        
        ifr.ifr_addr.sa_family = AF_INET;
#endif
        strncpy(ifr.ifr_name, if_config[INGRESS_IF].if_brname, sizeof(ifr.ifr_name));
        // Bind raw socket to the ingress bridge
        if (setsockopt(if_config[INGRESS_IF].if_tx_fd, SOL_SOCKET, SO_BINDTODEVICE, (void *) &ifr, sizeof(ifr)) < 0) {
            rc = errno;
            log_msg(LOG_ERR, "%s-%d: Can not bind socket to %s - %s.\n", __FUNCTION__, __LINE__, ifr.ifr_name, strerror(errno));
            exit_level1_cleanup();
            exit(rc);
        }

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
#ifdef IPV6
        if ((name_to_ip(remote_name, (struct sockaddr_storage *) &peer_addr, AF_INET6)) != 0)
#else        
        if ((name_to_ip(remote_name, (struct sockaddr_storage *) &peer_addr, AF_INET)) != 0)
#endif
        {
            log_msg(LOG_ERR, "%s-%d: Could not translate hostname %s into ip address.\n", __FUNCTION__, __LINE__, remote_name);
            exit_level1_cleanup();
            exit(EINVAL);
        }

        if ((rc = reconnect_comms_to_server()) != 0) {
            exit_level1_cleanup();
            exit(rc);
        }

        // Handshake with server, send helo message and wait for ack.
#ifdef IPV6
        memcpy(&client_query.helo_data.egress_addr[0], &if_config[0].if_ipaddr, sizeof(struct sockaddr_in6));
        memcpy(&client_query.helo_data.egress_addr[1], &if_config[1].if_ipaddr, sizeof(struct sockaddr_in6));
#else
        memcpy(&client_query.helo_data.egress_addr[0], &if_config[0].if_ipaddr, sizeof(struct sockaddr_in));
        memcpy(&client_query.helo_data.egress_addr[1], &if_config[1].if_ipaddr, sizeof(struct sockaddr_in));
#endif
        client_query.helo_data.if_ratio[0]      = 1;
        client_query.helo_data.if_ratio[1]      = 1;
        client_query.helo_data.cc_port          = cc_port;
        client_query.for_peer                   = false;
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
            log_msg(LOG_INFO, "Received helo ack - rc=%d.\n", client_response.rc);
        }
        if_stats.num_interfaces = 3;

        // Start up the client threads
        create_threads(8);
    } else {  // server
        if_stats.num_interfaces = 1;
        // Start up the server threads
        create_threads(3);
    }

    // Open local and remote communication channels
    create_comms_channel(cc_port, &commsfd);
    create_comms_channel(rmt_port, &rmt_commsfd);
    if ((comms_thread_parms = (struct comms_thread_parms_s *) malloc(sizeof(struct comms_thread_parms_s))) == NULL) {
        log_msg(LOG_ERR, "%s-%d: Out of memory.\n", __FUNCTION__, __LINE__);
        exit_level1_cleanup();
        exit(ENOMEM);
    }
    comms_thread_parms->peer_fd = rmt_commsfd;
    if ((rc = create_thread(&comms_thread_parms->thread_id, remote_comms_thread, 1, "rmt_comms_thread", (void *) comms_thread_parms)) != 0) {
        log_msg(LOG_ERR, "%s-%d: Can not create remote comms thread - %s.\n", __FUNCTION__, __LINE__, strerror(rc));
    }

    log_msg(LOG_INFO, "%s daemon started.\n", progname);
    
    sin_size = sizeof(comms_client_addr);
    for(;;) {
        if ((comms_client_fd = accept(commsfd, (struct sockaddr *)&comms_client_addr, &sin_size)) < 0) {
            log_msg(LOG_ERR, "%s-%d: Error accepting comms connection - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
            continue;
        }
#ifdef IPV6
        inet_ntop(AF_INET6, get_in_addr((struct sockaddr *)&comms_client_addr), ipaddr, sizeof ipaddr);
#else
        inet_ntop(AF_INET, get_in_addr((struct sockaddr *)&comms_client_addr), ipaddr, sizeof ipaddr);
#endif
        log_msg(LOG_INFO, "Accepted connection from %s.\n", ipaddr);
        if ((comms_thread_parms = (struct comms_thread_parms_s *) malloc(sizeof(struct comms_thread_parms_s))) == NULL) {
            log_msg(LOG_ERR, "%s-%d: Out of memory.\n", __FUNCTION__, __LINE__);
            close(comms_client_fd);
            continue;
        }
        comms_thread_parms->peer_fd = comms_client_fd;
        if ((rc = create_thread(&comms_thread_parms->thread_id, comms_thread, 1, "comms_thread", (void *) comms_thread_parms)) != 0) {
            log_msg(LOG_ERR, "%s-%d: Can not create comms thread for connection from %s - %s.\n", __FUNCTION__, __LINE__, ipaddr, strerror(rc));
        }
    }

    exit_level1_cleanup();
    exit(EXIT_SUCCESS);
}
