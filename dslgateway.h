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

#include "mempool.h"
#include "circular_buffer.h"

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
#define EGRESS_IF                           0
#define REORDER_BUF_SZ                      8
#define ONE_MS                              1000000
#define REORDER_BUF_TIMEOUT                 200*ONE_MS
#define SLOW_CNT_MAX                        5
#define HOME_TO_VPS_PKT_MANGLER_THREADNO    6
#define HOME_FROM_VPS_PKT_MANGLER_THREADNO  7
#define VPS_PKT_MANGLER_THREADNO            2
#define DEFAULT_CONFIG_FILE_NAME            "/etc/dslgateway.cfg"
#define EGRESS_NFQ							1
#define INGRESS_NFQ							0
#define PING_TRAINING_CNT					10

struct tcp_mbuf_s {
    struct ip           ip_hdr;
    struct tcphdr       tcp_hdr;
    unsigned char       payload[ETHERMTU];
};

struct udp_mbuf_s {
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
    uint32_t        	nfq_index;
    ssize_t				len;
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

struct comms_thread_parms_s {
    int         peer_fd;
    pthread_t   thread_id;
};

struct if_config_s {
    int                     if_fd;                 // fd of the file descriptor for the data port
    int						if_peer_fd;            // when client connects to data port, this is the fd
    uint32_t				if_port;               // data port number
    char                    if_name[IFNAMSIZ];     // name of ingress/egress interface(s)
    struct sockaddr_storage if_ipaddr;             // ip address of client
    uint8_t                 if_ratio;              // speed weighting of this interface
    int						if_index;              // kernel if index of this interfacxe
    uint32_t				if_fwmark;             // netfilter fwmark for this interface
    struct sockaddr_in6     if_peer_client_addr6;  // ip address of peer
    struct sockaddr_in      if_peer_client_addr;   // ip address of peer
    socklen_t               if_sin_size;
    uint32_t				if_train_cnt;
    struct timespec			if_diff;
    bool					if_trained;
    bool					if_peer_ts_greater;
};

struct nf_queue_config_s {
	uint32_t				nfq_q_no;
    int 					(*nfq_cb)(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
    	      	  	  	  	  	  struct nfq_data *nfa, void *data);
    struct nfq_handle 		*h;
    struct nfq_q_handle 	*qh;
    uint32_t                nf_index;
    struct thread_list_s    nf_thread;
    unsigned int            q_control_cnt;
    bool                    q_control;
};

struct data_port_ping_s {
	struct timespec		ts;
	struct timespec		ts_diff;
};

void exit_level1_cleanup(void);
void signal_handler(int sig);
void get_ip_addrs(void);
void usage(char *progname);
unsigned short iphdr_checksum(unsigned short* buff, int _16bitword);
void *comms_thread(void *arg);
int send_comms_pkt(int fd, const void *buf, size_t len);
int recv_comms_pkt(int fd, void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* DSLGATEWAY_H */
