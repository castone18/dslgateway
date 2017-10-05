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

char                        *progname;
struct if_config_s          if_config[NUM_INGRESS_INTERFACES+NUM_EGRESS_INTERFACES];
unsigned int                egresscnt=0, ingresscnt=0;
mempool                     mPool;
bool                        wipebufs=false;
int                         comms_peer_fd=-1;
struct statistics_s         if_stats;
unsigned int                cc_port=PORT, rmt_port=PORT;
struct thread_list_s        dsl_threads[((NUM_INGRESS_INTERFACES+NUM_EGRESS_INTERFACES)*2)+2];
int                         thread_exit_rc;
unsigned int                n_mbufs=DEFAULT_NUM_MBUFS;
bool                        ipv6_mode=false;
bool                        q_control_on=false;
bool                        comms_addr_valid=false;
char                        *comms_name=NULL;

static struct sockaddr_in6          comms_addr6;
static struct sockaddr_in           comms_addr;



// +----------------------------------------------------------------------------
// | Do some more cleanup
// +----------------------------------------------------------------------------
void exit_level1_cleanup(void)
{
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


// +----------------------------------------------------------------------------
// | Transmit thread, one is started on each interface, three on the home gateway
// | one on the vps. Note that, unlike the rx interfaces on the home gateway,
// | each tx interface has it's own circular buffer.
// +----------------------------------------------------------------------------
void *tx_thread(void * arg)
{
    struct if_queue_s   *txq = (struct if_queue_s *) arg;
    struct mbuf_s       *mbuf=NULL;
    unsigned char       *mbufc;
    ssize_t             txSz;
    struct ip6_hdr      *ip6hdr;
    struct ip           *iphdr;

    while (txq->if_thread->keep_going) {
        while ((sem_wait(&txq->if_ready) == -1) && (errno == EINTR));
        if ((mbuf = (struct mbuf_s*) circular_buffer_pop(txq->if_pkts)) == NULL) continue;
        mbufc   = (unsigned char *) mbuf;
        if (mbuf->ipv6) {
            ip6hdr   = (struct ip6_hdr *) (mbufc + sizeof (struct ether_header));
            // TODO: deal with partial packet send
            while (((txSz = write(if_config[txq->if_index].if_tx_fd, (const void *) mbuf, ip6hdr->ip6_plen+sizeof(struct ip6_hdr))) == -1) && (errno==EINTR));
        } else {
            iphdr   = (struct ip *) (mbufc + sizeof(struct ether_header));
            // TODO: deal with partial packet send
            while (((txSz = write(if_config[txq->if_index].if_tx_fd, (const void *) mbuf, iphdr->ip_len+sizeof(struct ip))) == -1) && (errno==EINTR));
        }
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
// | Connect to the server on the comms port
// +----------------------------------------------------------------------------
int reconnect_comms_to_server(void)
{
    int             rc;

    log_debug_msg(LOG_INFO, "%s-%d\n", __FUNCTION__, __LINE__);
    if (comms_peer_fd > -1) close(comms_peer_fd);

    // Convert server name to server ip address
    if (ipv6_mode) {
    } else {
    }
    if (ipv6_mode) {
        if ((name_to_ip(comms_name, (struct sockaddr_storage *) &comms_addr6, AF_INET6)) != 0)
        {
            log_msg(LOG_ERR, "%s-%d: Could not translate hostname %s into ip address.\n", __FUNCTION__, __LINE__, comms_name);
            exit_level1_cleanup();
            exit(EINVAL);
        }
        if ((comms_peer_fd = socket(AF_INET6, SOCK_STREAM, 0)) < 0) {
            rc = errno;
            log_msg(LOG_ERR, "%s-%d: Can not create comms socket - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
            exit_level1_cleanup();
            exit(rc);
        }
        comms_addr6.sin6_port       = htons((unsigned short)rmt_port);
    } else {
        if ((name_to_ip(comms_name, (struct sockaddr_storage *) &comms_addr, AF_INET)) != 0)
        {
            log_msg(LOG_ERR, "%s-%d: Could not translate hostname %s into ip address.\n", __FUNCTION__, __LINE__, comms_name);
            exit_level1_cleanup();
            exit(EINVAL);
        }
        if ((comms_peer_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            rc = errno;
            log_msg(LOG_ERR, "%s-%d: Can not create comms socket - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
            exit_level1_cleanup();
            exit(rc);
        }
        comms_addr.sin_port        = htons((unsigned short)rmt_port);
    }
    log_msg(LOG_INFO, "Waiting for connection to server %s on port %u...", comms_name, rmt_port);
    if (ipv6_mode) {
        if (connect(comms_peer_fd, (struct sockaddr *) &comms_addr6, sizeof(comms_addr6)) < 0) {
            rc = errno;
            log_msg(LOG_ERR, "%s-%d: Not connected - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
            exit_level1_cleanup();
            exit(rc);
        }
    } else {
        if (connect(comms_peer_fd, (struct sockaddr *) &comms_addr, sizeof(comms_addr)) < 0) {
            rc = errno;
            log_msg(LOG_ERR, "%s-%d: Not connected - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
            exit_level1_cleanup();
            exit(rc);
        }
    }
    log_msg(LOG_INFO, "Connected.\n");

    comms_addr_valid = true;
    return 0;
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
    free(thread_parms);
    pthread_exit(NULL);
}


// +----------------------------------------------------------------------------
// | Create comms channel
// +----------------------------------------------------------------------------
static void create_comms_channel(unsigned int port, int *commsfd)
{
    int                         rc;
    struct sockaddr_in6         bind_addr6;
    struct sockaddr_in          bind_addr;

    bzero((char *) &bind_addr, sizeof(bind_addr));
    bzero((char *) &bind_addr6, sizeof(bind_addr6));
    if (ipv6_mode) {
        if ((*commsfd = socket(AF_INET6, SOCK_STREAM, 0)) == -1) {
            rc = errno;
            log_msg(LOG_ERR, "%s-%d: Error creating comms socket - %s.\n", __FUNCTION__, __LINE__, strerror(rc));
            exit_level1_cleanup();
            exit(rc);
        }
        bind_addr6.sin6_family   = AF_INET6;
        bind_addr6.sin6_addr     = in6addr_any;
        bind_addr6.sin6_port     = htons((unsigned short)port);
    } else {
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
    }
    if (setsockopt(*commsfd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) == -1) {
        log_msg(LOG_WARNING, "%s-%d: Error setting reuse address on comms socket.\n", __FUNCTION__, __LINE__);
    }
    if (ipv6_mode) {
        if (bind(*commsfd, (struct sockaddr *) &bind_addr6, sizeof(bind_addr6)) == -1) {
            rc = errno;
            log_msg(LOG_ERR, "%s-%d: Can not bind comms socket - %s.\n", __FUNCTION__, __LINE__, strerror(rc));
            close(*commsfd);
            exit_level1_cleanup();
            exit(rc);
        }
    } else {
        if (bind(*commsfd, (struct sockaddr *) &bind_addr, sizeof(bind_addr)) == -1) {
            rc = errno;
            log_msg(LOG_ERR, "%s-%d: Can not bind comms socket - %s.\n", __FUNCTION__, __LINE__, strerror(rc));
            close(*commsfd);
            exit_level1_cleanup();
            exit(rc);
        }
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
    struct sockaddr_in6         comms_client_addr6;
    struct sockaddr_in          comms_client_addr;

    for(;;) {
        if (ipv6_mode) {
            if ((comms_client_fd = accept(thread_parms->peer_fd, (struct sockaddr *)&comms_client_addr6, &sin_size)) < 0) {
                log_msg(LOG_ERR, "%s-%d: Error accepting comms connection - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
                continue;
            }
            inet_ntop(AF_INET6, get_in_addr((struct sockaddr *)&comms_client_addr6), ipaddr, sizeof ipaddr);
        } else {
            if ((comms_client_fd = accept(thread_parms->peer_fd, (struct sockaddr *)&comms_client_addr, &sin_size)) < 0) {
                log_msg(LOG_ERR, "%s-%d: Error accepting comms connection - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
                continue;
            }
            inet_ntop(AF_INET, get_in_addr((struct sockaddr *)&comms_client_addr), ipaddr, sizeof ipaddr);
        }
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
// | Open egress interfaces, allocate rx and tx circular buffers for egress 
// | interfaces. Note there are two egress interfaces on the home gateway, and 
// | one on the vps
// +----------------------------------------------------------------------------
void open_egress_interfaces(void)
{
    int             i, rc;
    struct ifreq    ifr;
    
    for (i=0; i<egresscnt; i++) {
        // Open raw socket for egress tx interface, opened in IP mode so we don't have to
        // provide the ethernet header.
        if (ipv6_mode) {
            if ((if_config[i].if_tx_fd = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW)) < 0) {
                rc = errno;
                log_msg(LOG_ERR, "%s-%d: Can not create socket for egress interface %d - %s.\n", __FUNCTION__, __LINE__, i, strerror(errno));
                exit_level1_cleanup();
                exit(rc);
            }
        } else {
            if ((if_config[i].if_tx_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
                rc = errno;
                log_msg(LOG_ERR, "%s-%d: Can not create socket for egress interface %d - %s.\n", __FUNCTION__, __LINE__, i, strerror(errno));
                exit_level1_cleanup();
                exit(rc);
            }
        }
        // Set flag so socket expects us to provide IP header on egress tx socket.
        if (setsockopt (if_config[i].if_tx_fd, IPPROTO_IP, IP_HDRINCL, &(int){ 1 }, sizeof(int)) < 0) {
            rc = errno;
            log_msg(LOG_ERR, "%s-%d: Can not set ip header socket option for egress interface - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
            exit_level1_cleanup();
            exit(rc);
        }
        memset(&ifr, 0, sizeof(ifr));
        if (ipv6_mode)
            ifr.ifr_addr.sa_family = AF_INET6;
        else
            ifr.ifr_addr.sa_family = AF_INET;
        strncpy(ifr.ifr_name, if_config[i].if_name, sizeof(ifr.ifr_name));
        // Bind raw socket to a particular interface name (eg: ppp0 or ppp1)
        if (setsockopt(if_config[i].if_tx_fd, SOL_SOCKET, SO_BINDTODEVICE, (void *) &ifr, sizeof(ifr)) < 0) {
            rc = errno;
            log_msg(LOG_ERR, "%s-%d: Can not bind socket to %s - %s.\n", __FUNCTION__, __LINE__, ifr.ifr_name, strerror(errno));
            exit_level1_cleanup();
            exit(rc);
        }
        // Open egress rx socket interface, this socket is opened such that we get the ethernet
        // header as well as the ip header
        if (ipv6_mode) {
            if ((if_config[i].if_rx_fd = socket(AF_INET6, SOCK_RAW, ETH_P_ALL)) < 0) {
                rc = errno;
                log_msg(LOG_ERR, "%s-%d: Can not create socket for egress rx interface %d - %s.\n", __FUNCTION__, __LINE__, i, strerror(errno));
                exit_level1_cleanup();
                exit(rc);
            }
        } else {
            if ((if_config[i].if_rx_fd = socket(AF_INET, SOCK_RAW, ETH_P_ALL)) < 0) {
                rc = errno;
                log_msg(LOG_ERR, "%s-%d: Can not create socket for egress rx interface %d - %s.\n", __FUNCTION__, __LINE__, i, strerror(errno));
                exit_level1_cleanup();
                exit(rc);
            }
        }
        // Bind raw socket to a particular interface name (eg: ppp0 or ppp1)
        if (setsockopt(if_config[i].if_rx_fd, SOL_SOCKET, SO_BINDTODEVICE, (void *) &ifr, sizeof(ifr)) < 0) {
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
        if (q_control_on) {
            if_config[i].if_rxq.q_control       = true;
            if_config[i].if_rxq.q_control_cnt   = 0;
        } else if_config[i].if_rxq.q_control    = false;
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
        if (q_control_on) {
            if_config[i].if_txq.q_control       = true;
            if_config[i].if_txq.q_control_cnt   = 0;
        } else if_config[i].if_txq.q_control    = false;
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
                    for (i=0; i<egresscnt+ingresscnt; i++) {
                        if (strcmp(if_config[i].if_name, ifa_p->ifa_name) == 0) {
                            memcpy(&if_config[i].if_ipaddr, ifa_p->ifa_addr, sizeof(struct sockaddr_in6));
                            inet_ntop(AF_INET6, get_in_addr((struct sockaddr *)&if_config[i].if_ipaddr), ipaddr, sizeof(ipaddr));
                            log_msg(LOG_INFO, "Interface %s has ip address %s\n", if_config[i].if_name, ipaddr);
                        }
                    }
                }
            } else {
                if (ifa_p->ifa_addr->sa_family == AF_INET) {
                    for (i=0; i<egresscnt+ingresscnt; i++) {
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
// | Process remote comms port
// +----------------------------------------------------------------------------
void process_remote_comms(void)
{
    struct comms_thread_parms_s *comms_thread_parms;
    int                         rc;
    int                         rmt_commsfd;
    
    // Open remote communication channel
    create_comms_channel(rmt_port, &rmt_commsfd);
    // Create thread to handle remote comms requests
    if ((comms_thread_parms = (struct comms_thread_parms_s *) malloc(sizeof(struct comms_thread_parms_s))) == NULL) {
        log_msg(LOG_ERR, "%s-%d: Out of memory.\n", __FUNCTION__, __LINE__);
        exit_level1_cleanup();
        exit(ENOMEM);
    }
    comms_thread_parms->peer_fd = rmt_commsfd;
    if ((rc = create_thread(&comms_thread_parms->thread_id, remote_comms_thread, 1, "rmt_comms_thread", (void *) comms_thread_parms)) != 0) {
        log_msg(LOG_ERR, "%s-%d: Can not create remote comms thread - %s.\n", __FUNCTION__, __LINE__, strerror(rc));
    }
}


// +----------------------------------------------------------------------------
// | Process local comms port
// +----------------------------------------------------------------------------
void process_comms(void)
{
    int                         rc, comms_client_fd;
    socklen_t                   sin_size;
    struct sockaddr_in6         comms_client_addr6;
    struct sockaddr_in          comms_client_addr;
    char                        ipaddr[INET6_ADDRSTRLEN];
    struct comms_thread_parms_s *comms_thread_parms;
    int                         commsfd;
    
    // Open local communication channel
    create_comms_channel(cc_port, &commsfd);

    log_msg(LOG_INFO, "%s daemon started.\n", progname);

    for(;;) {
        if (ipv6_mode) {
            sin_size = sizeof(comms_client_addr6);
            if ((comms_client_fd = accept(commsfd, (struct sockaddr *)&comms_client_addr6, &sin_size)) < 0) {
                log_msg(LOG_ERR, "%s-%d: Error accepting comms connection - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
                continue;
            }
            inet_ntop(AF_INET6, get_in_addr((struct sockaddr *)&comms_client_addr6), ipaddr, sizeof ipaddr);
        } else {
            sin_size = sizeof(comms_client_addr);
            if ((comms_client_fd = accept(commsfd, (struct sockaddr *)&comms_client_addr, &sin_size)) < 0) {
                log_msg(LOG_ERR, "%s-%d: Error accepting comms connection - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
                continue;
            }
            inet_ntop(AF_INET, get_in_addr((struct sockaddr *)&comms_client_addr), ipaddr, sizeof ipaddr);
        }
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
unsigned short iphdr_checksum(unsigned short* buff, int _16bitword)
{
    unsigned long sum;
    for(sum=0;_16bitword>0;_16bitword--)
        sum += htons(*(buff)++);
    sum  = ((sum >> 16) + (sum & 0xFFFF));
    sum += (sum>>16);
    return (unsigned short)(~sum);
}
