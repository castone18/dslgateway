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
// | dslgateway_ui.c
// |
// |    This file implements a user interface to the dslgateway.
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
#include <signal.h>
#include <semaphore.h>
#include <pthread.h>
#include <linux/sockios.h>
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
#include <netinet/in.h>

#include "comms.h"
#include "util.h"

static int                  comms_serv_fd;
#ifdef IPV6
static struct sockaddr_in6  host_addr;
#else
static struct sockaddr_in   host_addr;
#endif
static unsigned int         cc_port=PORT;
static unsigned int         print_stats_delay=5;
static unsigned int         remote_thread_start=0;

// +----------------------------------------------------------------------------
// | Connect to the client on the comms port
// +----------------------------------------------------------------------------
static int reconnect_comms_to_client(void)
{
#ifdef IPV6
    if ((comms_serv_fd = socket(AF_INET6, SOCK_STREAM, 0)) < 0) {
        printf("%s-%d: Can not create comms socket - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
        exit(EIO);
    }
    host_addr.sin6_port       = htons((unsigned short)cc_port);
#else
    if ((comms_serv_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("%s-%d: Can not create comms socket - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
        exit(EIO);
    }
    host_addr.sin_port        = htons((unsigned short)cc_port);
#endif
    printf("Waiting for connection to server on port %u...", cc_port);
    fflush(stdout);
    if (connect(comms_serv_fd, (struct sockaddr *) &host_addr, sizeof(host_addr)) < 0) {
        printf(" Not connected - %s.\n", strerror(errno));
        return errno;
    }
    printf("Connected.\n");
    return 0;
}


// +----------------------------------------------------------------------------
// print help text
// +----------------------------------------------------------------------------
void print_usage(void)
{
    printf("dslgateway_ui [-p <port>] [-r <hostname>] [-n <iterations>] [-d <delay>]\n");
    printf("dslgateway_ui -h: Print this help text\n");
    printf("  -p <port>: Connect on port. Default is %d.\n", PORT);
    printf("  -r <hostname>: Name of host to connect to. Default is localhost.\n");
    printf("  -n <iterations>: Display stats for n iterations, then exit.\n");
    printf("  -d <delay>: Delay between refresh of stats print.\n");
    printf("\n");
}

void get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen)
{
    switch(sa->sa_family) {
        case AF_INET:
            inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
                    s, maxlen);
            break;

        case AF_INET6:
            inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
                    s, maxlen);
            break;

        default:
            strncpy(s, "Unknown AF", maxlen);
            return;
    }

    return;
}

static void print_stats(struct comms_reply_s *rply, char *name)
{
    char client_ip_str[2][INET6_ADDRSTRLEN];

    printf("\n%s interface statistics:\n", name);
    if (rply->stats.num_interfaces == 3) {
        printf("                 %19s  %19s  %19s\n", rply->stats.if_name[0],
                rply->stats.if_name[1], rply->stats.if_name[2]);
        printf("Rx Packets:      %19llu  %19llu  %19llu\n", rply->stats.if_rx_pkts[0],
                rply->stats.if_rx_pkts[1], rply->stats.if_rx_pkts[2]);
        printf("Tx Packets:      %19llu  %19llu  %19llu\n", rply->stats.if_tx_pkts[0],
                rply->stats.if_tx_pkts[1], rply->stats.if_tx_pkts[2]);
        printf("Rx Bytes:        %19llu  %19llu  %19llu\n", rply->stats.if_rx_bytes[0],
                rply->stats.if_rx_bytes[1], rply->stats.if_rx_bytes[2]);
        printf("Tx Bytes:        %19llu  %19llu  %19llu\n", rply->stats.if_tx_bytes[0],
                rply->stats.if_tx_bytes[1], rply->stats.if_tx_bytes[2]);
        printf("CBUF rxq sz:               %9u            %9u            %9u\n", rply->stats.circular_buffer_rxq_sz[0],
                rply->stats.circular_buffer_rxq_sz[1], rply->stats.circular_buffer_rxq_sz[2]);
        printf("CBUF txq sz:               %9u            %9u            %9u\n", rply->stats.circular_buffer_txq_sz[0],
                rply->stats.circular_buffer_txq_sz[1], rply->stats.circular_buffer_txq_sz[2]);
        printf("CBUF rxq freesz:           %9u            %9u            %9u\n", rply->stats.circular_buffer_rxq_freesz[0],
                rply->stats.circular_buffer_rxq_freesz[1], rply->stats.circular_buffer_rxq_freesz[2]);
        printf("CBUF txq freesz:           %9u            %9u            %9u\n", rply->stats.circular_buffer_txq_freesz[0],
                rply->stats.circular_buffer_txq_freesz[1], rply->stats.circular_buffer_txq_freesz[2]);
        printf("CBUF rxq ovhdsz:           %9u            %9u            %9u\n", rply->stats.circular_buffer_rxq_overheadsz[0],
                rply->stats.circular_buffer_rxq_overheadsz[1], rply->stats.circular_buffer_rxq_overheadsz[2]);
        printf("CBUF txq ovhdsz:           %9u            %9u            %9u\n\n", rply->stats.circular_buffer_txq_overheadsz[0],
                rply->stats.circular_buffer_txq_overheadsz[1], rply->stats.circular_buffer_txq_overheadsz[2]);
        printf("Reorders: %19llu  Reorder Failures: %19llu\n", rply->stats.reorders,
                rply->stats.reorder_failures);
        printf("Mempool total sz: %9u  free sz: %9u  overhead sz: %9u\n", rply->stats.mempool_totalsz,
                rply->stats.mempool_freesz, rply->stats.mempool_overheadsz);
    } else {
        printf("             %19s\n", rply->stats.if_name[0]);
        printf("Rx Packets:  %19llu\n", rply->stats.if_rx_pkts[0]);
        printf("Tx Packets:  %19llu\n", rply->stats.if_tx_pkts[0]);
        printf("Rx Bytes:    %19llu\n", rply->stats.if_rx_bytes[0]);
        printf("Tx Bytes:    %19llu\n", rply->stats.if_tx_bytes[0]);
        printf("CBUF rxq sz:           %9u\n", rply->stats.circular_buffer_rxq_sz[0]);
        printf("CBUF txq sz:           %9u\n", rply->stats.circular_buffer_txq_sz[0]);
        printf("CBUF rxq freesz:       %9u\n", rply->stats.circular_buffer_rxq_freesz[0]);
        printf("CBUF txq freesz:       %9u\n", rply->stats.circular_buffer_txq_freesz[0]);
        printf("CBUF rxq ovhdsz:       %9u\n", rply->stats.circular_buffer_rxq_overheadsz[0]);
        printf("CBUF txq ovhdsz:       %9u\n\n", rply->stats.circular_buffer_txq_overheadsz[0]);
        printf("Reorders: %19llu  Reorder Failures: %19llu\n", rply->stats.reorders,
                rply->stats.reorder_failures);
        printf("Mempool total sz: %9u  free sz: %9u  overhead sz: %9u\n", rply->stats.mempool_totalsz,
                rply->stats.mempool_freesz, rply->stats.mempool_overheadsz);
        if (rply->stats.client_connected) {
#ifdef IPV6
            inet_ntop(AF_INET6, &rply->stats.client_sa[0].sin6_addr, client_ip_str[0], INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &rply->stats.client_sa[1].sin6_addr, client_ip_str[1], INET6_ADDRSTRLEN);
#else            
            inet_ntop(AF_INET, &rply->stats.client_sa[0].sin_addr, client_ip_str[0], INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &rply->stats.client_sa[1].sin_addr, client_ip_str[1], INET_ADDRSTRLEN);
#endif
            printf("Client is connected on %s and %s.\n", client_ip_str[0], client_ip_str[1]);
        } else {
            printf("Client is not connected.\n");
        }
    }
    printf("\n\n");
}


// +----------------------------------------------------------------------------
// +----------------------------------------------------------------------------
static void print_all_stats(unsigned int iter)
{
    const char              clr[] = { 27, '[', '2', 'J', '\0' };
    const char              topLeft[] = { 27, '[', '1', ';', '1', 'H', '\0' };
    bool                    keep_going=true;
    fd_set                  set;
    struct timeval          timeout;
    int                     rc;
    struct comms_query_s    clntqry, srvrqry;
    struct comms_reply_s    clntrply, srvrrply;
    char                    c;

    clntqry.cmd         = COMMS_GETSTATS;
    clntqry.for_peer    = false;
    srvrqry.cmd         = COMMS_GETSTATS;
    srvrqry.for_peer    = true;


    do {
        send(comms_serv_fd, &clntqry, sizeof(struct comms_query_s), 0);
        recv(comms_serv_fd, &clntrply, sizeof(struct comms_reply_s), 0);
        printf("%s%s", clr, topLeft); // Clear screen and move to top left
        if (clntrply.rc == 0) print_stats(&clntrply, "Local");
        else printf("Error retrieving stats, rc=%d.\n", clntrply.rc);
        send(comms_serv_fd, &srvrqry, sizeof(struct comms_query_s), 0);
        recv(comms_serv_fd, &srvrrply, sizeof(struct comms_reply_s), 0);
        if (srvrrply.rc == 0) print_stats(&srvrrply, "Remote");
        else printf("Error retrieving remote stats, rc=%d.\n", srvrrply.rc);
        timeout.tv_sec      = print_stats_delay;
        timeout.tv_usec     = 0;
        FD_ZERO(&set);
        FD_SET(STDIN_FILENO, &set);
        while (((rc = select(STDIN_FILENO+1, &set, NULL, NULL, &timeout)) == -1) && errno == EINTR);
        if (rc > 0) {
            if (FD_ISSET(0, &set)) {
                read(STDIN_FILENO, &c, 1);
                if (c == 'q') keep_going=false;
            }
        }
        if (iter != 0)
            if (iter-- == 0) keep_going=false;
    } while (keep_going);
}


// +----------------------------------------------------------------------------
// +----------------------------------------------------------------------------
static void print_all_threads(void)
{
    struct comms_query_s    clntqry, srvrqry;
    struct comms_reply_s    clntrply, srvrrply;
    int                     i, j;

    clntqry.cmd         = COMMS_LISTTHREADS;
    clntqry.for_peer  = false;
    srvrqry.cmd         = COMMS_LISTTHREADS;
    srvrqry.for_peer  = true;


    send(comms_serv_fd, &clntqry, sizeof(struct comms_query_s), 0);
    recv(comms_serv_fd, &clntrply, sizeof(struct comms_reply_s), 0);
    printf("\nLocal Threads:\n");
    for (i=0, j=0; i<clntrply.num_threads; i++, j++) {
        printf("Thread %d: %s %s\n", j, clntrply.thread_names[j],
                clntrply.thread_status[j] ? "Running" : "Stopped");
    }
    remote_thread_start = j;
    send(comms_serv_fd, &srvrqry, sizeof(struct comms_query_s), 0);
    recv(comms_serv_fd, &srvrrply, sizeof(struct comms_reply_s), 0);
    if (srvrrply.rc == 0) {
        printf("\nRemote Threads:\n");
        for (i=0; i<srvrrply.num_threads; i++, j++) {
            printf("Thread %d: %s %s\n", j, srvrrply.thread_names[j],
                    srvrrply.thread_status[j] ? "Running" : "Stopped");
        }
    } else {
        printf("No connection to remote, assume remote threads not running.\n");
    }
}


// +----------------------------------------------------------------------------
// +----------------------------------------------------------------------------
static void start_stop_thread(bool start_stop, unsigned int thread_num)
{
    struct comms_query_s qry;
    struct comms_reply_s rply;

    if (start_stop) qry.cmd = COMMS_STARTTHREAD;
    if (thread_num >= remote_thread_start) qry.for_peer=true;
    send(comms_serv_fd, &qry, sizeof(struct comms_query_s), 0);
    recv(comms_serv_fd, &rply, sizeof(struct comms_reply_s), 0);
    if (start_stop) printf("\nThread %d started.\n", thread_num);
    else printf("\nThread %d stopped.\n", thread_num);
}


// +----------------------------------------------------------------------------
// +----------------------------------------------------------------------------
static void kill_daemons(void)
{
    struct comms_query_s qry;

    qry.cmd         = COMMS_KILL;
    qry.for_peer  = true;
    send(comms_serv_fd, &qry, sizeof(struct comms_query_s), 0);
    qry.for_peer  = false;
    send(comms_serv_fd, &qry, sizeof(struct comms_query_s), 0);
}


// +----------------------------------------------------------------------------
// | Main processing.
// +----------------------------------------------------------------------------
int main(int argc, char *argv[])
{
    int                     opt, rdsz;
    unsigned int            iter=0, thread_num;
    char                    hostname[256], command[4096];
    bool                    keep_going=true;
    struct comms_query_s    qry;
    char                    ipaddr[INET6_ADDRSTRLEN];

    memset(hostname, 0, 256);
    sprintf(hostname, "%s", "localhost");

    // Parse the options
    while ((opt = getopt(argc, argv, "p:n:r:d:h?")) != -1) {
      switch (opt) {
        case 'p':
            sscanf(optarg, "%u", &cc_port);
            break;
        case 'n':
            sscanf(optarg, "%u", &iter);
            break;
        case 'd':
            sscanf(optarg, "%u", &print_stats_delay);
            break;
        case 'r':
            sscanf(optarg, "%s", hostname);
            break;
        case 'h':
        case '?':
            print_usage();
            exit(0);
        default:
            printf("%c option is invalid, ignored.\n", opt);
      }
    }

    // Convert host name to ip address
#ifdef IPV6
    if (name_to_ip(hostname, (struct sockaddr_storage *) &host_addr, AF_INET6) != 0) {
#else
    if (name_to_ip(hostname, (struct sockaddr_storage *) &host_addr, AF_INET) != 0) {
#endif
        printf("Invalid host name.\n");
        exit(EINVAL);
    }
#ifdef IPV6
    inet_ntop(AF_INET6, &host_addr.sin6_addr, ipaddr, sizeof(ipaddr));
#else
    inet_ntop(AF_INET, &host_addr.sin_addr, ipaddr, sizeof(ipaddr));
#endif
    printf("Connecting to ip address %s.\n", ipaddr);

    // Connect to host
    if (reconnect_comms_to_client() != 0) exit(errno);

    if (iter != 0) {
        print_all_stats(iter);
        exit(0);
    }

    printf("\n\n");
    while (keep_going) {
        memset(command, 0, 4096);
        printf("==> ");
        fflush(stdout);
        rdsz = read(STDIN_FILENO, command, 4095);
        command[rdsz]='\0';
        if (strncmp(command, "stats", 5) == 0) {
            print_all_stats(0);
        }
        if (strncmp(command, "threads", 7) == 0) {
            print_all_threads();
            continue;
        }
        if (strncmp(command, "stop", 4) == 0) {
            if (remote_thread_start == 0) {
                printf("Please run threads command first.\n");
            }
            sscanf(&command[5], "%u", &thread_num);
            start_stop_thread(false, thread_num);
            continue;
        }
        if (strncmp(command, "start", 5) == 0) {
            if (remote_thread_start == 0) {
                printf("Please run threads command first.\n");
            }
            sscanf(&command[6], "%u", &thread_num);
            start_stop_thread(true, thread_num);
            continue;
        }
        if (strncmp(command, "exit", 4) == 0) {
            qry.cmd         = COMMS_EXIT;
            qry.for_peer  = false;
            send(comms_serv_fd, &qry, sizeof(struct comms_query_s), 0);
            close(comms_serv_fd);
            exit(0);
        }
        if (strncmp(command, "kill", 4) == 0) {
            kill_daemons();
            continue;
        }
        printf("Commands: stats, threads, stop <threadno>, start <threadno>, exit, kill\n");
    }
}