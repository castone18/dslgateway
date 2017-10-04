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
// | dslgateway.h
// |
// |    Common functionality between client and server.
// |
// +----------------------------------------------------------------------------

#ifndef DSLGATEWAY_H
#define DSLGATEWAY_H

#ifdef __cplusplus
extern "C" {
#endif

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
    bool                ipv6;
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
    unsigned int            q_control_cnt;
    bool                    q_control;
};

struct comms_thread_parms_s {
    int         peer_fd;
    pthread_t   thread_id;
};

struct if_config_s {
    int                     if_rx_fd;
    int                     if_tx_fd;
    char                    if_name[IFNAMSIZ];
    struct if_queue_s       if_rxq;
    struct if_queue_s       if_txq;
    uint8_t                 if_ratio;
    struct sockaddr_storage if_ipaddr;
};


void exit_level1_cleanup(void);
void signal_handler(int sig);
void *tx_thread(void * arg);
int reconnect_comms_to_server(void);
void open_egress_interfaces(void);
void get_ip_addrs(void);
void process_comms(void);
void usage(char *progname);
int handle_client_query(struct comms_query_s *query, int comms_client_fd, bool *connection_active);
unsigned short iphdr_checksum(unsigned short* buff, int _16bitword);
void process_remote_comms(void);

#ifdef __cplusplus
}
#endif

#endif /* DSLGATEWAY_H */

