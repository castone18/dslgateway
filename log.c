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
// | log.c
// |    Implementation of logging api.
// |
// +----------------------------------------------------------------------------

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <pthread.h>
#include <syslog.h>
#include <stdarg.h>

#include "log.h"

static bool         debug=false;
static bool         syslog_on=false;


// +----------------------------------------------------------------------------
// | log_init: Initializes the logger.
// | debug_on: true if debug messages should be logged, false otherwise
// | syslog_enable: true if syslog should be initialized
// | progname: identifier string for log messages
// +----------------------------------------------------------------------------
void log_init(bool debug_on, bool syslog_enable, char *progname) 
{
    if (syslog_enable) {
        openlog(progname, LOG_CONS|LOG_PID, LOG_DAEMON);
        syslog_on = syslog_enable;
    }
    debug = debug_on;
}


// +----------------------------------------------------------------------------
// | log_msg: prints a log message on syslog or console depending on daemon mode.
// | priority: The syslog priority.
// | fmt: Message format to log
// +----------------------------------------------------------------------------
void log_msg(int priority, char *fmt, ...)
{
    va_list argp;

    va_start(argp, fmt);
    if (syslog_on)
        vsyslog(priority, fmt, argp);
    else
        vprintf(fmt, argp);
    va_end(argp);
}


// +----------------------------------------------------------------------------
// | log_debug_msg: prints a debug log message on syslog or console depending on
// |    daemon mode and debug msg mode.
// | priority: The syslog priority.
// | fmt: Message format to log
// +----------------------------------------------------------------------------
void log_debug_msg(int priority, char *fmt, ...)
{
    va_list argp;

    if (debug) {
        va_start(argp, fmt);
        if (syslog_on)
            vsyslog(priority, fmt, argp);
        else
            vprintf(fmt, argp);
        va_end(argp);
    }
}