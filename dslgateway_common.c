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
// | dslgateway_common.c
// |
// |    This file is part of a dsl gateway that splits outgoing IP traffic between
// | two DSL lines. See dslgateway.c for an explanation of the features and intent
// | of the program. This file provides functions that are common to the client
// | and server implementations.
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

#include "log.h"
#include "comms.h"
#include "util.h"
#include "dslgateway.h"

char                        *progname;
struct if_config_s          if_config[NUM_EGRESS_INTERFACES];
unsigned int                egresscnt=0;
bool                        wipebufs=false;
struct statistics_s         nf_stats;
int                         thread_exit_rc;
bool                        ipv6_mode=false;
struct nf_queue_config_s    nfq_config[NUM_NETFILTER_QUEUES];
int                         comms_peer_fd=-1;
bool                        comms_addr_valid=false;
unsigned int                cc_port=PORT;
void                        (*exit_level2_cleanup)(void) = NULL;
void                      	(*handle_comms_command)(struct comms_packet_s *query, struct comms_packet_s *reply,
        						int comms_client_fd, bool *connection_active) = NULL;

static int                  comms_socket_fd;

// +----------------------------------------------------------------------------
// | Do some cleanup
// +----------------------------------------------------------------------------
void exit_level1_cleanup(void)
{
    if (nfq_config[INGRESS_NFQ].qh != NULL) nfq_destroy_queue(nfq_config[INGRESS_NFQ].qh);
    if (nfq_config[EGRESS_NFQ].qh != NULL) nfq_destroy_queue(nfq_config[EGRESS_NFQ].qh);
    if (nfq_config[INGRESS_NFQ].h != NULL) nfq_close(nfq_config[INGRESS_NFQ].h);
    if (exit_level2_cleanup) exit_level2_cleanup();
    log_msg(LOG_INFO, "%s daemon ends.\n", progname);
}


// +----------------------------------------------------------------------------
// | Handles signals
// +----------------------------------------------------------------------------
void signal_handler(int sig)
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


//// +----------------------------------------------------------------------------
//// | Transmit thread, one is started on each interface, three on the home gateway
//// | one on the vps. Note that, unlike the rx interfaces on the home gateway,
//// | each tx interface has it's own circular buffer.
//// +----------------------------------------------------------------------------
//void *tx_thread(void * arg)
//{
//    struct if_queue_s   *txq = (struct if_queue_s *) arg;
//    struct mbuf_s       *mbuf=NULL;
//    unsigned char       *mbufc;
//    ssize_t             txSz;
//    struct ip6_hdr      *ip6hdr;
//    struct ip           *iphdr;
//
//    while (txq->if_thread->keep_going) {
//        while ((sem_wait(&txq->if_ready) == -1) && (errno == EINTR));
//        if ((mbuf = (struct mbuf_s*) circular_buffer_pop(txq->if_pkts)) == NULL) continue;
//        mbufc   = (unsigned char *) mbuf;
//        if (mbuf->ipv6) {
//            ip6hdr   = (struct ip6_hdr *) (mbufc + sizeof (struct ether_header));
//            // TODO: deal with partial packet send
//            while (((txSz = write(if_config[txq->if_index].if_tx_fd, (const void *) mbuf, ip6hdr->ip6_plen+sizeof(struct ip6_hdr))) == -1) && (errno==EINTR));
//        } else {
//            iphdr   = (struct ip *) (mbufc + sizeof(struct ether_header));
//            // TODO: deal with partial packet send
//            while (((txSz = write(if_config[txq->if_index].if_tx_fd, (const void *) mbuf, iphdr->ip_len+sizeof(struct ip))) == -1) && (errno==EINTR));
//        }
//        if (txSz == -1) {
//            log_msg(LOG_ERR, "%s-%d: Error sending ip packet on interface %s - %s.\n",
//                    __FUNCTION__, __LINE__, if_config[txq->if_index].if_txname, strerror(errno));
//        }
//        mempool_free(mPool, mbuf, wipebufs);
//        if_stats.if_tx_pkts[txq->if_index]++;
//        if_stats.if_tx_bytes[txq->if_index] += txSz;
//    }
//
//    thread_exit_rc = 0;
//    pthread_exit(&thread_exit_rc);
//    return &thread_exit_rc;  // for compiler warnings
//}


// +----------------------------------------------------------------------------
// | Send packets and account for partial sends
// +----------------------------------------------------------------------------
int send_pkt(int fd, const void *buf, size_t len)
{
    int             rc, bytecnt;
    uint8_t			*bufc = (uint8_t *) buf;

    bytecnt = 0;
    do {
        if ((rc = send(fd, &bufc[bytecnt], len-bytecnt, 0)) == -1) {
        	rc = -1*errno;
            log_msg(LOG_ERR, "%s-%d: Error sending packet to remote peer - %s", __FUNCTION__, __LINE__, strerror(errno));
            return rc;
        } else if (rc == 0) return rc;
        bytecnt += rc;
    } while (bytecnt < len);
    return bytecnt;
}


// +----------------------------------------------------------------------------
// | Receive comms packets and account for partial receives
// +----------------------------------------------------------------------------
int recv_pkt(int fd, void *buf, size_t len, int flags)
{
    int             rc, bytecnt;
    uint8_t			*bufc = (uint8_t *) buf;

    bytecnt = 0;
    do {
        if ((rc = recv(fd, &bufc[bytecnt], len - bytecnt, flags)) == -1) {
            if ((flags & MSG_DONTWAIT) && ((errno == EAGAIN) || (errno == EWOULDBLOCK))) return -1 * errno; 
            if (errno != EINTR) {
                rc = -1 * errno;
                log_msg(LOG_ERR, "%s-%d: Error receiving packet from remote peer - %s", __FUNCTION__, __LINE__, strerror(errno));
                return rc;
            }
        } else if (rc == 0) return rc;
        bytecnt += rc;
    } while (bytecnt < len);
    return bytecnt;
}


// +----------------------------------------------------------------------------
// | Handle a query on the comms socket
// +----------------------------------------------------------------------------
static void handle_comms_query(struct comms_packet_s *query, int comms_client_fd, bool *connection_active)
{
    int                     rc;
    struct comms_packet_s   reply;

    memset(&reply, 0, sizeof(reply));
    reply.cmd				= COMMS_REPLY;
    reply.pyld.rply.qcmd	= query->cmd;
    if (query->pyld.qry.for_peer) {
        if (comms_addr_valid) {
            query->pyld.qry.for_peer = false;
            if ((rc = send_pkt(comms_peer_fd, query, sizeof(struct comms_packet_s))) < 0) {
            	reply.pyld.rply.rc = -1*rc;
                send_pkt(comms_client_fd, &reply, sizeof(struct comms_packet_s));
                return;
            }
        } else {
            reply.pyld.rply.rc = EHOSTUNREACH;
        }
    } else if (handle_comms_command) {
    	handle_comms_command(query, &reply, comms_client_fd, connection_active);
    } else {
        reply.pyld.rply.rc = EFAULT;
    }

    if ((rc = send_pkt(comms_client_fd, &reply, sizeof(struct comms_packet_s))) < 0) {
    	reply.pyld.rply.rc = -1*rc;
        send_pkt(comms_client_fd, &reply, sizeof(struct comms_packet_s));
        return;
    }
}


// +----------------------------------------------------------------------------
// | Thread to handle communication channel, one spawned for each connection
// +----------------------------------------------------------------------------
static void *comms_thread(void *arg)
{
    struct comms_thread_parms_s *thread_parms  = (struct comms_thread_parms_s *) arg;
    bool                        connection_active;
    struct comms_packet_s       pkt;
    int                         rc;

    connection_active = true;
    while(connection_active) {
        if ((rc = recv_pkt(thread_parms->connection_fd, &pkt, sizeof(struct comms_packet_s), MSG_WAITALL)) > 0) {
        	if (pkt.cmd != COMMS_REPLY) {
                handle_comms_query(&pkt, thread_parms->connection_fd, &connection_active);
        	}
        } else if (rc == 0) {
            connection_active = false;
            comms_addr_valid = false;
            log_msg(LOG_INFO, "Comms terminated by client.\n");
        } else if (errno == EINTR) {
            continue;
        } else {
            log_msg(LOG_WARNING, "%s-%d: Error receiving comms message from client - %s", __FUNCTION__, __LINE__, strerror(errno));
        }
    }
    close(thread_parms->connection_fd);
    free(thread_parms);
    pthread_exit(NULL);
    return NULL; // for compiler warnings
}


// +----------------------------------------------------------------------------
// | Create channel - open, bind, and listen on a socket
// +----------------------------------------------------------------------------
int create_channel(uint32_t port)
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
            exit_level1_cleanup();
            exit(ENOMEM);
        }
        if (ipv6_mode) {
            sin_size = sizeof(comms_client_addr6);
            if ((comms_thread_parms->connection_fd = accept(comms_socket_fd, (struct sockaddr *)&comms_client_addr6, &sin_size)) < 0) {
                log_msg(LOG_ERR, "%s-%d: Error accepting comms connection - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
                continue;
            }
            inet_ntop(AF_INET6, get_in_addr((struct sockaddr *)&comms_client_addr6), ipaddr, sizeof ipaddr);
        } else {
            sin_size = sizeof(comms_client_addr);
            if ((comms_thread_parms->connection_fd = accept(comms_socket_fd, (struct sockaddr *)&comms_client_addr, &sin_size)) < 0) {
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
    free(thread_parms);
    pthread_exit(NULL);
    return NULL; // for compiler warnings
}


// +----------------------------------------------------------------------------
// | Initialize comms on comms port
// +----------------------------------------------------------------------------
void start_comms(void)
{
    int                         rc;
    struct comms_thread_parms_s *comms_thread_parms;

    if ((comms_thread_parms = (struct comms_thread_parms_s *) malloc(sizeof(struct comms_thread_parms_s))) == NULL) {
        log_msg(LOG_ERR, "%s-%d: Out of memory.\n", __FUNCTION__, __LINE__);
        exit_level1_cleanup();
        exit(ENOMEM);
    }

    // Open local communication channel
    if ((comms_socket_fd = create_channel(cc_port)) < 0) {
        exit_level1_cleanup();
        exit(-1*comms_socket_fd);
    }

    if ((rc = create_thread(&comms_thread_parms->thread_id, accept_comms_thread, 1, "comms_thread", (void *) comms_thread_parms)) != 0) {
        log_msg(LOG_ERR, "%s-%d: Can not create comms thread for connection request - %s.\n", __FUNCTION__, __LINE__, strerror(rc));
    }
}


// +----------------------------------------------------------------------------
// | Get ip addresses of all the interfaces
// +----------------------------------------------------------------------------
void get_ip_addrs(void)
{
    struct ifaddrs  *ifa, *ifa_p;
    int             i, rc;
    char            ipaddr[INET6_ADDRSTRLEN];

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
            if (ipv6_mode) {
                if (ifa_p->ifa_addr->sa_family == AF_INET6) {
                    for (i=0; i<egresscnt; i++) {
                        if (strcmp(if_config[i].if_name, ifa_p->ifa_name) == 0) {
                            memcpy(&if_config[i].if_ipaddr, ifa_p->ifa_addr, sizeof(struct sockaddr_in6));
                            inet_ntop(AF_INET6, get_in_addr((struct sockaddr *)&if_config[i].if_ipaddr), ipaddr, sizeof(ipaddr));
                            log_msg(LOG_INFO, "Interface %s has ip address %s\n", if_config[i].if_name, ipaddr);
                        }
                    }
                }
            } else {
                if (ifa_p->ifa_addr->sa_family == AF_INET) {
                    for (i=0; i<egresscnt; i++) {
                        if (strcmp(if_config[i].if_name, ifa_p->ifa_name) == 0) {
                            memcpy(&if_config[i].if_ipaddr, ifa_p->ifa_addr, sizeof(struct sockaddr_in));
                            inet_ntop(AF_INET, get_in_addr((struct sockaddr *)&if_config[i].if_ipaddr), ipaddr, sizeof(ipaddr));
                            log_msg(LOG_INFO, "Interface %s has ip address %s\n", if_config[i].if_name, ipaddr);
                        }
                    }
                }
            }
        }
        ifa_p = ifa_p->ifa_next;
    }
}


// +----------------------------------------------------------------------------
// | Prints usage and exits.
// +----------------------------------------------------------------------------
void usage(char *progname)
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
// | Recalculate the ip header checksum.
// +----------------------------------------------------------------------------
uint16_t iphdr_checksum(uint16_t *buff, int _16bitword)
{
    unsigned long sum;
    for(sum=0;_16bitword>0;_16bitword--)
        sum += htons(*(buff)++);
    sum  = ((sum >> 16) + (sum & 0xFFFF));
    sum += (sum>>16);
    return (unsigned short)(~sum);
}
