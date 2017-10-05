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
#include <libconfig.h>
#include <limits.h>
#include <termios.h>

#include "comms.h"
#include "util.h"
#include "dslgateway.h"

static int                  comms_serv_fd;
static struct sockaddr_in6  host_addr6;
static struct sockaddr_in   host_addr;
static int                  cc_port=-1;
static unsigned int         print_stats_delay=5;
static bool                 ipv6_mode=false;
static char                 config_file_name[PATH_MAX];


// +----------------------------------------------------------------------------
// | Read the config file and set all the appropriate variables from the values.
// +----------------------------------------------------------------------------
static void read_config_file(void)
{
    config_t                cfg;
    int                     i;

    config_init(&cfg);

    if (!config_read_file(&cfg, config_file_name)) {
        printf("%s-%d: Error reading config file, all parameters revert to defaults.\n", __FUNCTION__, __LINE__);
        return;
    }

    if (cc_port == -1)
        if (config_lookup_int(&cfg, "port", &cc_port))
            printf("Configured for comms port on %d.\n", cc_port);
    if (config_lookup_int(&cfg, "ipversion", &i)) {
        if (i == 6) ipv6_mode = true;
        printf("Configured for %s.\n", ipv6_mode ? "ipv6" : "ipv4");
    }

    config_destroy(&cfg);
}

// +----------------------------------------------------------------------------
// | Connect to the client on the comms port
// +----------------------------------------------------------------------------
static int reconnect_comms_to_client(void)
{
    if (ipv6_mode) {
        if ((comms_serv_fd = socket(AF_INET6, SOCK_STREAM, 0)) < 0) {
            printf("%s-%d: Can not create comms socket - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
            exit(EIO);
        }
        host_addr6.sin6_port       = htons((unsigned short)cc_port);
    } else {
        if ((comms_serv_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            printf("%s-%d: Can not create comms socket - %s.\n", __FUNCTION__, __LINE__, strerror(errno));
            exit(EIO);
        }
        host_addr.sin_port        = htons((unsigned short)cc_port);
    }
    printf("Waiting for connection to server on port %u...", cc_port);
    fflush(stdout);
    if (ipv6_mode) {
        if (connect(comms_serv_fd, (struct sockaddr *) &host_addr6, sizeof(host_addr6)) < 0) {
            printf(" Not connected - %s.\n", strerror(errno));
            return errno;
        }
    } else {
        if (connect(comms_serv_fd, (struct sockaddr *) &host_addr, sizeof(host_addr)) < 0) {
            printf(" Not connected - %s.\n", strerror(errno));
            return errno;
        }
    }
    printf("Connected.\n");
    return 0;
}


// +----------------------------------------------------------------------------
// print help text
// +----------------------------------------------------------------------------
void print_usage(void)
{
    printf("dslgateway_ui [-c <config filename>] [-r <hostname>] [-p <port>] [-n <iterations>] [-d <delay>] [-6]\n");
    printf("dslgateway_ui -h: Print this help text\n");
    printf("  -c <config filename>: Full path to config file. Default is /etc/dslgateway.cfg.\n");
    printf("  -r <hostname>:        Name of host to connect to. Default is localhost.\n");
    printf("  -p <port>:            Port to connect to. Default is from config file.\n");
    printf("  -n <iterations>:      Display stats for n iterations, then exit.\n");
    printf("  -d <delay>:           Delay between refresh of stats print.\n");
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
    char                client_ip_str[2][INET6_ADDRSTRLEN];
    struct sockaddr_in6 *addr6;
    struct sockaddr_in  *addr4;

    printf("\n%s interface statistics:\n", name);
    if (rply->stats.num_interfaces == 3) {
        printf("                 %19s  %19s  %19s\n", rply->stats.if_name[EGRESS_IF],
                rply->stats.if_name[EGRESS_IF+1], rply->stats.if_name[INGRESS_IF]);
        printf("Rx Packets:      %19llu  %19llu  %19llu\n", rply->stats.if_rx_pkts[EGRESS_IF],
                rply->stats.if_rx_pkts[EGRESS_IF+1], rply->stats.if_rx_pkts[INGRESS_IF]);
        printf("Tx Packets:      %19llu  %19llu  %19llu\n", rply->stats.if_tx_pkts[EGRESS_IF],
                rply->stats.if_tx_pkts[EGRESS_IF+1], rply->stats.if_tx_pkts[INGRESS_IF]);
        printf("Rx Bytes:        %19llu  %19llu  %19llu\n", rply->stats.if_rx_bytes[EGRESS_IF],
                rply->stats.if_rx_bytes[EGRESS_IF+1], rply->stats.if_rx_bytes[INGRESS_IF]);
        printf("Tx Bytes:        %19llu  %19llu  %19llu\n", rply->stats.if_tx_bytes[EGRESS_IF],
                rply->stats.if_tx_bytes[EGRESS_IF+1], rply->stats.if_tx_bytes[INGRESS_IF]);
        printf("Dropped:         %19llu  %19llu  %19llu\n", rply->stats.if_dropped_pkts[EGRESS_IF],
                rply->stats.if_dropped_pkts[EGRESS_IF+1], rply->stats.if_dropped_pkts[INGRESS_IF]);
        printf("CBUF rxq sz:               %9u            %9u            %9u\n", rply->stats.circular_buffer_rxq_sz[EGRESS_IF],
                rply->stats.circular_buffer_rxq_sz[EGRESS_IF+1], rply->stats.circular_buffer_rxq_sz[INGRESS_IF]);
        printf("CBUF txq sz:               %9u            %9u            %9u\n", rply->stats.circular_buffer_txq_sz[EGRESS_IF],
                rply->stats.circular_buffer_txq_sz[EGRESS_IF+1], rply->stats.circular_buffer_txq_sz[INGRESS_IF]);
        printf("CBUF rxq freesz:           %9u            %9u            %9u\n", rply->stats.circular_buffer_rxq_freesz[EGRESS_IF],
                rply->stats.circular_buffer_rxq_freesz[EGRESS_IF+1], rply->stats.circular_buffer_rxq_freesz[INGRESS_IF]);
        printf("CBUF txq freesz:           %9u            %9u            %9u\n", rply->stats.circular_buffer_txq_freesz[EGRESS_IF],
                rply->stats.circular_buffer_txq_freesz[EGRESS_IF+1], rply->stats.circular_buffer_txq_freesz[INGRESS_IF]);
        printf("CBUF rxq ovhdsz:           %9u            %9u            %9u\n", rply->stats.circular_buffer_rxq_overheadsz[EGRESS_IF],
                rply->stats.circular_buffer_rxq_overheadsz[EGRESS_IF+1], rply->stats.circular_buffer_rxq_overheadsz[INGRESS_IF]);
        printf("CBUF txq ovhdsz:           %9u            %9u            %9u\n\n", rply->stats.circular_buffer_txq_overheadsz[EGRESS_IF],
                rply->stats.circular_buffer_txq_overheadsz[EGRESS_IF+1], rply->stats.circular_buffer_txq_overheadsz[INGRESS_IF]);
        printf("Reorders: %19llu  Reorder Failures: %19llu\n", rply->stats.reorders,
                rply->stats.reorder_failures);
        printf("Mempool total sz: %9u  free sz: %9u  overhead sz: %9u\n", rply->stats.mempool_totalsz,
                rply->stats.mempool_freesz, rply->stats.mempool_overheadsz);
    } else {
        printf("             %19s\n", rply->stats.if_name[EGRESS_IF]);
        printf("Rx Packets:  %19llu\n", rply->stats.if_rx_pkts[EGRESS_IF]);
        printf("Tx Packets:  %19llu\n", rply->stats.if_tx_pkts[EGRESS_IF]);
        printf("Rx Bytes:    %19llu\n", rply->stats.if_rx_bytes[EGRESS_IF]);
        printf("Tx Bytes:    %19llu\n", rply->stats.if_tx_bytes[EGRESS_IF]);
        printf("Dropped:     %19llu\n", rply->stats.if_dropped_pkts[EGRESS_IF]);
        printf("CBUF rxq sz:           %9u\n", rply->stats.circular_buffer_rxq_sz[EGRESS_IF]);
        printf("CBUF txq sz:           %9u\n", rply->stats.circular_buffer_txq_sz[EGRESS_IF]);
        printf("CBUF rxq freesz:       %9u\n", rply->stats.circular_buffer_rxq_freesz[EGRESS_IF]);
        printf("CBUF txq freesz:       %9u\n", rply->stats.circular_buffer_txq_freesz[EGRESS_IF]);
        printf("CBUF rxq ovhdsz:       %9u\n", rply->stats.circular_buffer_rxq_overheadsz[EGRESS_IF]);
        printf("CBUF txq ovhdsz:       %9u\n\n", rply->stats.circular_buffer_txq_overheadsz[EGRESS_IF]);
        printf("Reorders: %19llu  Reorder Failures: %19llu\n", rply->stats.reorders,
                rply->stats.reorder_failures);
        printf("Mempool total sz: %9u  free sz: %9u  overhead sz: %9u\n", rply->stats.mempool_totalsz,
                rply->stats.mempool_freesz, rply->stats.mempool_overheadsz);
        if (rply->stats.client_connected) {
            if (ipv6_mode) {
                addr6 = (struct sockaddr_in6 *) &rply->stats.client_sa[0];
                inet_ntop(AF_INET6, &addr6->sin6_addr, client_ip_str[0], INET6_ADDRSTRLEN);
                addr6 = (struct sockaddr_in6 *) &rply->stats.client_sa[EGRESS_IF+1];
                inet_ntop(AF_INET6, &addr6->sin6_addr, client_ip_str[EGRESS_IF+1], INET6_ADDRSTRLEN);
            } else {
                addr4 = (struct sockaddr_in *) &rply->stats.client_sa[0];
                inet_ntop(AF_INET, &addr4->sin_addr, client_ip_str[0], INET_ADDRSTRLEN);
                addr4 = (struct sockaddr_in *) &rply->stats.client_sa[EGRESS_IF+1];
                inet_ntop(AF_INET, &addr4->sin_addr, client_ip_str[EGRESS_IF+1], INET_ADDRSTRLEN);
            }
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
    int                     rc, bytecnt;
    struct comms_query_s    clntqry, srvrqry;
    struct comms_reply_s    clntrply, srvrrply;
    char                    c, *clntqry_c=(char *) &clntqry, *srvrqry_c=(char*) &srvrqry;
    char                    *clntrply_c=(char *) &clntrply, *srvrrply_c=(char*) &srvrrply;
    struct termios          ctrl;

    clntqry.cmd         = COMMS_GETSTATS;
    clntqry.for_peer    = false;
    srvrqry.cmd         = COMMS_GETSTATS;
    srvrqry.for_peer    = true;

    tcgetattr(STDIN_FILENO, &ctrl);
    ctrl.c_lflag &= ~ICANON; // turning off canonical mode makes input unbuffered
    tcsetattr(STDIN_FILENO, TCSANOW, &ctrl);

    do {
        bytecnt = 0;
        do {
            if ((rc = send(comms_serv_fd, &clntqry_c[bytecnt], sizeof(struct comms_query_s)-bytecnt, 0)) == -1) {
                printf("Error sending request to local instance - %s", strerror(errno));
                continue;
            }
            bytecnt += rc;
        } while (bytecnt < sizeof(struct comms_query_s));
        bytecnt = 0;
        do {
            if ((rc = recv(comms_serv_fd, &clntrply_c[bytecnt], sizeof(struct comms_reply_s)-bytecnt, 0)) == -1) {
                printf("Error receiving reply from local instance - %s", strerror(errno));
                continue;
            }
            bytecnt += rc;
        } while (bytecnt < sizeof(struct comms_reply_s));
        printf("%s%s", clr, topLeft); // Clear screen and move to top left
        if (clntrply.rc == 0) print_stats(&clntrply, "Local");
        else printf("Error retrieving stats, rc=%d.\n", clntrply.rc);
        bytecnt = 0;
        do {
            if ((rc = send(comms_serv_fd, &srvrqry_c[bytecnt], sizeof(struct comms_query_s)-bytecnt, 0)) == -1) {
                printf("Error sending request to remote instance - %s", strerror(errno));
                continue;
            }
            bytecnt += rc;
        } while (bytecnt < sizeof(struct comms_query_s));
        bytecnt = 0;
        do {
            if ((rc = recv(comms_serv_fd, &srvrrply_c[bytecnt], sizeof(struct comms_reply_s)-bytecnt, 0)) == -1) {
                printf("Error receiving reply from remote instance - %s", strerror(errno));
                continue;
            }
            bytecnt += rc;
        } while (bytecnt < sizeof(struct comms_reply_s));
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

    tcgetattr(STDIN_FILENO, &ctrl);
    ctrl.c_lflag |= ICANON; // turning on canonical mode makes input buffered
    tcsetattr(STDIN_FILENO, TCSANOW, &ctrl);
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
// +----------------------------------------------------------------------------
static void send_qcontrol(char *command)
{
    struct comms_query_s qry;
    struct comms_reply_s rply;

    sscanf(&command[9], "%d %d", &qry.q_control_index, &qry.q_control_cnt);
    qry.cmd         = COMMS_SET_QCONTROL;
    qry.for_peer    = false;
    send(comms_serv_fd, &qry, sizeof(struct comms_query_s), 0);
    recv(comms_serv_fd, &rply, sizeof(struct comms_reply_s), 0);
}


// +----------------------------------------------------------------------------
// | Main processing.
// +----------------------------------------------------------------------------
int main(int argc, char *argv[])
{
    int                     opt, rdsz;
    unsigned int            iter=0;
    char                    hostname[256], command[4096];
    bool                    keep_going=true;
    struct comms_query_s    qry;
    char                    ipaddr[INET6_ADDRSTRLEN];

    memset(hostname, 0, 256);
    sprintf(hostname, "%s", "localhost");
    memset(config_file_name, 0, PATH_MAX);
    strcpy(config_file_name, "/etc/dslgateway.cfg");

    // Parse the options
    while ((opt = getopt(argc, argv, "c:n:r:d:p:h?")) != -1) {
        switch (opt) {
            case 'c':
                strcpy(config_file_name, optarg);
                break;
            case 'n':
                sscanf(optarg, "%u", &iter);
                break;
            case 'p':
                sscanf(optarg, "%u", &cc_port);
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

    // read config dile
    read_config_file();
    if (cc_port == -1) cc_port=PORT;

    // Convert host name to ip address
    if (ipv6_mode) {
        if (name_to_ip(hostname, (struct sockaddr_storage *) &host_addr6, AF_INET6) != 0) {
            printf("Invalid host name.\n");
            exit(EINVAL);
        }
        inet_ntop(AF_INET6, &host_addr6.sin6_addr, ipaddr, sizeof(ipaddr));
    } else {
        if (name_to_ip(hostname, (struct sockaddr_storage *) &host_addr, AF_INET) != 0) {
            printf("Invalid host name.\n");
            exit(EINVAL);
        }
        inet_ntop(AF_INET, &host_addr.sin_addr, ipaddr, sizeof(ipaddr));
    }
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
        if (strncmp(command, "qcontrol", 8) == 0) {
            send_qcontrol(command);
            continue;
        }
        printf("Commands: stats, exit, kill, qcontrol <index> <value>\n");
    }
}