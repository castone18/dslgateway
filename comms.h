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
// | comms.h
// |    An API for communication with the dsl gateway.
// |
// +----------------------------------------------------------------------------

#ifndef COMMS_H
#define COMMS_H

#ifdef __cplusplus
extern "C" {
#endif

#define NUM_NETFILTER_QUEUES	2
#define NUM_EGRESS_INTERFACES	2
#define PORT 					1058

// Comms commands
#define COMMS_HELO              0
#define COMMS_GETSTATS          1
#define COMMS_CYA				2
#define COMMS_REPLY				3
#define COMMS_SET_QCONTROL      4
#define COMMS_KILL              5
#define COMMS_EXIT              6

#pragma pack(1)
struct statistics_s {
    unsigned long long      nf_rx_pkts[NUM_NETFILTER_QUEUES];
    unsigned long long      nf_tx_pkts[NUM_NETFILTER_QUEUES];
    unsigned long long      nf_rx_bytes[NUM_NETFILTER_QUEUES];
    unsigned long long      nf_tx_bytes[NUM_NETFILTER_QUEUES];
    unsigned long long      nf_dropped_pkts_ratio[NUM_NETFILTER_QUEUES];
    unsigned long long      nf_dropped_pkts_proto[NUM_NETFILTER_QUEUES];
    unsigned long long      nf_dropped_pkts_qcontrol[NUM_NETFILTER_QUEUES];
    unsigned long long      nf_dropped_pkts_space[NUM_NETFILTER_QUEUES];
    unsigned long long      nf_dropped_pkts[NUM_NETFILTER_QUEUES];
    unsigned long long      reorders;
    unsigned long long      reorder_failures;
    struct sockaddr_storage client_sa[2];
    bool                    client_connected;
    bool                    ipv6_mode;
};

struct comms_helo_data_s {
    struct sockaddr_storage egress_addr[NUM_EGRESS_INTERFACES];
    uint32_t                if_ratio[NUM_EGRESS_INTERFACES];
    uint32_t                cc_port;
    bool                    ipv6_mode;
};

struct comms_query_s {
    bool                        for_peer;
    struct comms_helo_data_s    helo_data;
    unsigned int                num_thread;
    int                         q_control_cnt;
    int                         q_control_index;
};

struct comms_reply_s {
    unsigned int		qcmd;
    int                 rc;
    struct statistics_s stats;
    char                thread_names[8][17];
    bool                thread_status[8];
    unsigned int        num_threads;
    bool                is_client;
};

struct comms_packet_s {
    unsigned int        cmd;
    union {
    	struct comms_query_s	qry;
    	struct comms_reply_s	rply;
    } pyld;
};
#pragma pack()



#ifdef __cplusplus
}
#endif

#endif /* COMMS_H */

