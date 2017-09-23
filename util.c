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
// | util.c
// |
// |    Some utility functions for the dsl gateway.
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
#include <linux/if_bridge.h>
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

#include "util.h"
#include "log.h"


// +----------------------------------------------------------------------------
// | Create a joinable thread under SCHED_RR with provided priority and set the
// | thread name.
// +----------------------------------------------------------------------------
int create_thread(pthread_t *thread, void *(*start_routine) (void *), int priority,
        const char *name, void *arg)
{
    int                     rc = 0;
    struct sched_param      sparam;
    pthread_attr_t          thread_attr;
    char                    localName[17];

    if ((rc = pthread_attr_init(&thread_attr)) != 0)
        log_msg(LOG_ERR, "%s-%d: pthread_attr_init rc=%s\n", __FUNCTION__, __LINE__,
                strerror(rc));
    if ((rc = pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_JOINABLE)) != 0)
        log_msg(LOG_ERR, "%s-%d: pthread_attr_setdetachstate rc=%s\n", __FUNCTION__, __LINE__,
                strerror(rc));
    if ((rc = pthread_attr_setinheritsched(&thread_attr, PTHREAD_EXPLICIT_SCHED)) != 0)
        log_msg(LOG_ERR, "%s-%d: pthread_attr_setinheritsched rc=%s\n", __FUNCTION__, __LINE__,
                strerror(rc));
    sparam.sched_priority = priority;
    if ((rc = pthread_attr_setschedpolicy(&thread_attr, SCHED_RR)) != 0)
        log_msg(LOG_ERR, "%s-%d: pthread_attr_setschedpolicy rc=%s\n", __FUNCTION__, __LINE__,
                strerror(rc));
    if ((rc = pthread_attr_setschedparam(&thread_attr, &sparam)) != 0)
        log_msg(LOG_ERR, "%s-%d: pthread_attr_setschedparam rc=%s\n", __FUNCTION__, __LINE__,
                strerror(rc));
    rc = pthread_create(thread, &thread_attr, start_routine, arg);
    memset(localName, 0, 17);
    strncpy(localName, name, 16);
    pthread_setname_np(*thread, localName);

    return rc;
}


// +----------------------------------------------------------------------------
// | Compare two timespecs and return:
// |      -1 if time1 < time2
// |       0 if time1 == time2
// |      +1 if time1 > time2
// +----------------------------------------------------------------------------
int compare_ts (struct timespec *time1, struct timespec *time2)
{

    if (time1->tv_sec < time2->tv_sec)
        return (-1);				// Less than.
    else if (time1->tv_sec > time2->tv_sec)
        return (1);				// Greater than.
    else if (time1->tv_nsec < time2->tv_nsec)
        return (-1);				// Less than.
    else if (time1->tv_nsec > time2->tv_nsec)
        return (1);				// Greater than.
    else
        return (0);				// Equal.

}


// +----------------------------------------------------------------------------
// | Subtract two timespecs. Returns time1 minus time2. If time2 is greater than
// | time1, then a time of zero is returned. This function does not check the
// | validity of time1 and time2, thus the number of nanoseconds must be less
// | than the number of nanoseconds in a second. Results are undefined if either
// | of the two times are invalid. Negative times are invalid. Thus, if
// | time2>time1, zero time is returned.
// +----------------------------------------------------------------------------
struct timespec subtract_ts (struct timespec *time1, struct timespec *time2)
{
    struct  timespec  result;

    if ((time1->tv_sec < time2->tv_sec) ||
        ((time1->tv_sec == time2->tv_sec) &&
         (time1->tv_nsec <= time2->tv_nsec))) {		// time1 <= time2?
        result.tv_sec = result.tv_nsec = 0;
    } else {						// time1 > time2
        result.tv_sec = time1->tv_sec - time2->tv_sec;
        if (time1->tv_nsec < time2->tv_nsec) {
            result.tv_nsec = time1->tv_nsec + 1000000000L - time2->tv_nsec;
            result.tv_sec--;				// Borrow a second.
        } else {
            result.tv_nsec = time1->tv_nsec - time2->tv_nsec;
        }
    }

    return (result);
}


// +----------------------------------------------------------------------------
// | Add two timespecs. Returns time1 + time2.
// +----------------------------------------------------------------------------
struct timespec add_ts(struct timespec *time1, struct timespec *time2)
{
    struct timespec result;

    result.tv_sec   = time1->tv_sec + time2->tv_sec;
    result.tv_nsec  = time1->tv_nsec + time2->tv_nsec;
    if (result.tv_nsec > 1000000000L) {
        result.tv_sec++;
        result.tv_nsec = result.tv_nsec % 1000000000L;
    }

    return (result);
}


// +----------------------------------------------------------------------------
// | Convert a fully qualified hostname or ip address string into numeric ip address
// +----------------------------------------------------------------------------
int name_to_ip(char *remote_name, struct sockaddr_storage *server_addr, sa_family_t ip_family)
{
    struct addrinfo         hints, *res, *p;
    int                     rc;

    if (server_addr == NULL) return EINVAL;
    if (remote_name == NULL) return EINVAL;
    if (ip_family != AF_INET && ip_family != AF_INET6) return EINVAL;
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = ip_family;
    hints.ai_socktype = SOCK_STREAM;
    if ((rc = getaddrinfo(remote_name, NULL, &hints, &res)) == 0) {
        for (p = res; p != NULL; p = p->ai_next) {
            if (p->ai_family == ip_family) {
                if (ip_family == AF_INET)
                    memcpy(server_addr, p->ai_addr, sizeof (struct sockaddr_in));
                else
                    memcpy(server_addr, p->ai_addr, sizeof (struct sockaddr_in6));
                break;
            }
        }
        freeaddrinfo(res); // free the linked list
    } else return EINVAL;

    return 0;
}


// +----------------------------------------------------------------------------
// | Get sockaddr, IPv4 or IPv6:
// +----------------------------------------------------------------------------
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}
