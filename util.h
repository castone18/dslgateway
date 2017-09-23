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
// | util.h
// |
// |    Some utility functions for the dsl gateway.
// |
// +----------------------------------------------------------------------------

#ifndef UTIL_H
#define UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

// +----------------------------------------------------------------------------
// | Create a joinable thread under SCHED_RR with provided priority and set the
// | thread name.
// +----------------------------------------------------------------------------
int create_thread(pthread_t *thread, void *(*start_routine) (void *), int priority,
        const char *name, void *arg);


// +----------------------------------------------------------------------------
// | Compare two timespecs and return:
// |      -1 if time1 < time2
// |       0 if time1 == time2
// |      +1 if time1 > time2
// +----------------------------------------------------------------------------
int compare_ts (struct timespec *time1, struct timespec *time2);


// +----------------------------------------------------------------------------
// | Subtract two timespecs. Returns time1 minus time2. If time2 is greater than
// | time1, then a time of zero is returned. This function does not check the
// | validity of time1 and time2, thus the number of nanoseconds must be less
// | than the number of nanoseconds in a second. Results are undefined if either
// | of the two times are invalid. Negative times are invalid. Thus, if
// | time2>time1, zero time is returned.
// +----------------------------------------------------------------------------
struct timespec subtract_ts (struct timespec *time1, struct timespec *time2);


// +----------------------------------------------------------------------------
// | Add two timespecs. Returns time1 + time2.
// +----------------------------------------------------------------------------
struct timespec add_ts(struct timespec *time1, struct timespec *time2);


// +----------------------------------------------------------------------------
// | Convert a fully qualified hostname or ip address string into numeric ip address
// +----------------------------------------------------------------------------
int name_to_ip(char *remote_name, struct sockaddr_storage *server_addr, sa_family_t ip_family);


// +----------------------------------------------------------------------------
// | Get sockaddr, IPv4 or IPv6:
// +----------------------------------------------------------------------------
void *get_in_addr(struct sockaddr *sa);

#ifdef __cplusplus
}
#endif

#endif /* UTIL_H */

