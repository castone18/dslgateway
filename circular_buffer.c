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
// | circular_buffer.c
// |    Implementation of circular buffer.
// |
// +----------------------------------------------------------------------------

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/queue.h>
#include <pthread.h>

#include "circular_buffer.h"
#include "log.h"

struct cbuf_entry_s {
    TAILQ_ENTRY(cbuf_entry_s)   entries;
    void                        *element;
};

struct circular_buffer_s {
    unsigned int                            nElements;
    mempool                                 mPool;
    unsigned int                            freeSz;
    unsigned int                            overheadSz;
    TAILQ_HEAD(, cbuf_entry_s)              free;
    TAILQ_HEAD(, cbuf_entry_s)              inuse;
    pthread_mutex_t                         cb_mutex;
};


// +----------------------------------------------------------------------------
// | Creates a circular buffer. Note that multiple circular buffers can share
// | the same memory pool.
// | nElements - maximum size of the circular buffer in elements
// | mPool - the backing storage memory pool
// | returns opaque handle that is provided to circular buffer functions to identify buffer
// +----------------------------------------------------------------------------
circular_buffer circular_buffer_create(unsigned int nElements, mempool mPool)
{
    int                     i, rc;
    struct cbuf_entry_s     *cbentry;
    pthread_mutexattr_t     mA;
    circular_buffer         cBuf = malloc(sizeof(struct circular_buffer_s));
    
    if (cBuf == NULL) return CIRCULAR_BUFFER_INVALID;
    pthread_mutexattr_init(&mA);
    pthread_mutexattr_settype(&mA, PTHREAD_MUTEX_NORMAL);
    pthread_mutexattr_setprotocol(&mA, PTHREAD_PRIO_INHERIT);
    if ((rc = pthread_mutex_init(&cBuf->cb_mutex, &mA)) != 0) {
        free(cBuf);
        return CIRCULAR_BUFFER_INVALID;
    }
    cBuf->overheadSz    = sizeof(struct circular_buffer_s);
    cBuf->nElements     = nElements;
    cBuf->freeSz        = nElements;
    cBuf->mPool         = mPool;
    TAILQ_INIT(&cBuf->free);
    TAILQ_INIT(&cBuf->inuse);
    for (i=0; i<nElements; i++) {
        if ((cbentry = malloc(sizeof(struct cbuf_entry_s))) == NULL) {
            if (i>0) {
                while (cbentry = TAILQ_FIRST(&cBuf->free)) {
                    TAILQ_REMOVE(&cBuf->free, cbentry, entries);
                    free(cbentry);
                }
            }
            free(cBuf);
            return CIRCULAR_BUFFER_INVALID;
        }
        cBuf->overheadSz    += sizeof(struct cbuf_entry_s);
        cbentry->element     = NULL;
        TAILQ_INSERT_TAIL(&cBuf->free, cbentry, entries);
    }
    return cBuf;
}

// +----------------------------------------------------------------------------
// | Destroy a circular buffer.
// | cBuf - buffer handle
// +----------------------------------------------------------------------------
void circular_buffer_destroy(circular_buffer cBuf) 
{
    struct cbuf_entry_s     *cbentry;

    if (cBuf == NULL) return;
    pthread_mutex_lock(&cBuf->cb_mutex);
    while (cbentry = TAILQ_FIRST(&cBuf->free)) {
        TAILQ_REMOVE(&cBuf->free, cbentry, entries);
        free(cbentry);
    }
    while (cbentry = TAILQ_FIRST(&cBuf->inuse)) {
        mempool_free(cBuf->mPool, cbentry->element, true);
        TAILQ_REMOVE(&cBuf->inuse, cbentry, entries);
        free(cbentry);
    }
    pthread_mutex_unlock(&cBuf->cb_mutex);
    pthread_mutex_destroy(&cBuf->cb_mutex);
    free(cBuf);
    cBuf = NULL;
}

// +----------------------------------------------------------------------------
// | Push an element on the head of the circular buffer.
// | cBuf - buffer handle
// | element - pointer to element
// +----------------------------------------------------------------------------
void circular_buffer_push(circular_buffer cBuf, void *element)
{
    struct cbuf_entry_s     *cbentry;
    
    if (cBuf == NULL) return;
    pthread_mutex_lock(&cBuf->cb_mutex);
    cbentry = TAILQ_FIRST(&cBuf->free);
    TAILQ_REMOVE(&cBuf->free, cbentry, entries);
    cbentry->element = element;
    TAILQ_INSERT_TAIL(&cBuf->inuse, cbentry, entries);
    cBuf->freeSz--;
    pthread_mutex_unlock(&cBuf->cb_mutex);
    element = NULL;
}

// +----------------------------------------------------------------------------
// | Pop an element from the tail of the circular buffer.
// | cBuf - buffer handle
// | Returns NULL if buffer is empty, element pointer otherwise
// +----------------------------------------------------------------------------
void *circular_buffer_pop(circular_buffer cBuf)
{
    struct cbuf_entry_s     *cbentry;
    void                    *element;
    
    if (cBuf == NULL) return NULL;
    pthread_mutex_lock(&cBuf->cb_mutex);
    cbentry = TAILQ_FIRST(&cBuf->inuse);
    TAILQ_REMOVE(&cBuf->inuse, cbentry, entries);
    element             = cbentry->element;
    cbentry->element    = NULL;
    TAILQ_INSERT_TAIL(&cBuf->free, cbentry, entries);
    cBuf->freeSz++;
    pthread_mutex_unlock(&cBuf->cb_mutex);
    return element;
}

// +----------------------------------------------------------------------------
// | Removes all the elements from the buffer and returns them to the 
// | memory pool.
// | cBuf - buffer handle
// +----------------------------------------------------------------------------
void circular_buffer_clear(circular_buffer cBuf)
{
    struct cbuf_entry_s     *cbentry;
    
    if (cBuf == NULL) return;
    pthread_mutex_lock(&cBuf->cb_mutex);
    while (cbentry = TAILQ_FIRST(&cBuf->inuse)) {
        mempool_free(cBuf->mPool, cbentry->element, true);
        TAILQ_REMOVE(&cBuf->inuse, cbentry, entries);
        cbentry->element    = NULL;
        TAILQ_INSERT_TAIL(&cBuf->free, cbentry, entries);
        cBuf->freeSz++;
    }
    pthread_mutex_unlock(&cBuf->cb_mutex);
}

// +----------------------------------------------------------------------------
// | Determine if circular buffer is empty.
// | cBuf - buffer handle
// | returns true if the circular buffer is empty, false otherwise
// +----------------------------------------------------------------------------
bool circular_buffer_is_empty(circular_buffer cBuf)
{
    if (cBuf == NULL) return false;
    return (cBuf->freeSz == cBuf->nElements);
}

// +----------------------------------------------------------------------------
// | Determine if circular buffer is full.
// | cBuf - buffer handle
// | returns true if the circular buffer is full, false otherwise
// +----------------------------------------------------------------------------
bool circular_buffer_is_full(circular_buffer cBuf)
{
    if (cBuf == NULL) return false;
    return (cBuf->freeSz == 0);
}

// +----------------------------------------------------------------------------
// | Get the number of elements in the circular buffer
// | cBuf - buffer handle
// | returns the number of elements in the circular buffer
// +----------------------------------------------------------------------------
unsigned int circular_buffer_sz(circular_buffer cBuf)
{
    if (cBuf == NULL) return 0;
    return cBuf->nElements - cBuf->freeSz;
}

// +----------------------------------------------------------------------------
// | Get the number of free elements in the circular buffer
// | cBuf - buffer handle
// | returns the number of free elements in the circular buffer
// +----------------------------------------------------------------------------
unsigned int circular_buffer_freesz(circular_buffer cBuf)
{
    if (cBuf == NULL) return 0;
    return cBuf->freeSz;
}

// +----------------------------------------------------------------------------
// | Get the overhead memory size for the circular buffer
// | cBuf - buffer handle
// | returns the overhead memory size for the circular buffer
// +----------------------------------------------------------------------------
unsigned int circular_buffer_overheadsz(circular_buffer cBuf)
{
    if (cBuf == NULL) return 0;
    return cBuf->overheadSz;
}