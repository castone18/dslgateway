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
// | mempool.c
// |    Implementation of memory pool api.
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
#include <syslog.h>

#include "mempool.h"
#include "log.h"

struct element_s;
struct mpool_entry_s {
    TAILQ_ENTRY(mpool_entry_s)  entries;
    struct element_s            *element;
};
struct element_s {
    unsigned int            guard;
    struct mpool_entry_s    *mentry;
    unsigned char           element[0];
};

struct mempool_s {
    unsigned int                            elementSz;
    unsigned int                            nElements;
    unsigned int                            freeSz;
    unsigned int                            totalSz;
    unsigned int                            overheadSz;
    unsigned char                           *memory;
    TAILQ_HEAD(, mpool_entry_s)             free;
    TAILQ_HEAD(, mpool_entry_s)             inuse;
    pthread_mutex_t                         mp_mutex;
};

// +----------------------------------------------------------------------------
// | Creates a memory pool.
// | elementSz - size of each element in the memory pool
// | nElements - maximum number of elements to keep in the pool
// | returns opaque handle that is provided to memory pool functions to identify
//|     pool, or MEM_POOL_INVALID
// +----------------------------------------------------------------------------
mempool mempool_create(unsigned int elementSz, unsigned int nElements)
{
    int                     i, rc;
    struct mpool_entry_s    *mentry;
    mempool                 mPool = malloc(sizeof(struct mempool_s));
    pthread_mutexattr_t     mA;
    unsigned int            *memoryi, memorySz_in_words;

    if (mPool == NULL) return MEM_POOL_INVALID;
    mPool->overheadSz   = sizeof(struct mempool_s);
    mPool->totalSz      = sizeof(struct mempool_s);
    // round elementSz up to a multiple of 4, which makes zeroing it faster
    if (elementSz % sizeof(unsigned int)) elementSz += (elementSz % sizeof(unsigned int));
    if ((mPool->memory = malloc((elementSz+sizeof(struct element_s))*nElements)) == NULL) {
        free(mPool);
        return MEM_POOL_INVALID;
    }
    mPool->totalSz      += (elementSz+sizeof(struct element_s))*nElements;
    memorySz_in_words    = ((elementSz+sizeof(struct element_s))*nElements) / sizeof(unsigned int);
    memoryi              = (unsigned int *) mPool->memory;
    for (i=0; i<memorySz_in_words; i++) memoryi[i] = 0;
    pthread_mutexattr_init(&mA);
    pthread_mutexattr_settype(&mA, PTHREAD_MUTEX_NORMAL);
    pthread_mutexattr_setprotocol(&mA, PTHREAD_PRIO_INHERIT);
    if ((rc = pthread_mutex_init(&mPool->mp_mutex, &mA)) != 0) {
        free(mPool->memory);
        free(mPool);
        return MEM_POOL_INVALID;
    }
    mPool->elementSz    = elementSz;
    mPool->nElements    = nElements;
    mPool->freeSz       = nElements;
    TAILQ_INIT(&mPool->free);
    TAILQ_INIT(&mPool->inuse);
    for (i=0; i<nElements; i++) {
        if ((mentry = malloc(sizeof(struct mpool_entry_s))) == NULL) {
            if (i>0) {
                while (mentry = TAILQ_FIRST(&mPool->free)) {
                    TAILQ_REMOVE(&mPool->free, mentry, entries);
                    free(mentry);
                }
            }
            free(mPool->memory);
            free(mPool);
            return MEM_POOL_INVALID;
        }
        mPool->totalSz          += sizeof(struct mpool_entry_s);
        mPool->overheadSz       += sizeof(struct mpool_entry_s);
        mentry->element         = (struct element_s *) (mPool->memory + (i*(elementSz+sizeof(struct element_s))));
        mentry->element->guard  = 0xdeadbeef;
        mentry->element->mentry = mentry;
        TAILQ_INSERT_TAIL(&mPool->free, mentry, entries);
    }
    return mPool;
}

// +----------------------------------------------------------------------------
// | Destroy a memory pool.
// | mPool - memory pool handle
// +----------------------------------------------------------------------------
void mempool_destroy(mempool mPool)
{
    struct mpool_entry_s  *mentry;
    unsigned int          *memoryi, memorySz_in_words, i;

    if (mPool == NULL) return;
    pthread_mutex_lock(&mPool->mp_mutex);
    while (mentry = TAILQ_FIRST(&mPool->free)) {
        TAILQ_REMOVE(&mPool->free, mentry, entries);
        free(mentry);
    }
    while (mentry = TAILQ_FIRST(&mPool->inuse)) {
        TAILQ_REMOVE(&mPool->inuse, mentry, entries);
        free(mentry);
    }
    memorySz_in_words  = ((mPool->elementSz+sizeof(struct element_s))*mPool->nElements) / sizeof(unsigned int);
    memoryi            = (unsigned int *) mPool->memory;
    for (i=0; i<memorySz_in_words; i++) memoryi[i] = 0;
    free(mPool->memory);
    pthread_mutex_unlock(&mPool->mp_mutex);
    pthread_mutex_destroy(&mPool->mp_mutex);
    free(mPool);
    mPool = NULL;
}

// +----------------------------------------------------------------------------
// | Allocate an item from the memory pool.
// | mPool - memory pool handle
// | returns NULL if memory pool is empty, pointer to element otherwise
// +----------------------------------------------------------------------------
void *mempool_alloc(mempool mPool) {
    struct mpool_entry_s    *mentry;

    if (mPool == NULL) return NULL;
    if (mPool->freeSz == 0) return NULL;
    pthread_mutex_lock(&mPool->mp_mutex);
    mentry = TAILQ_FIRST(&mPool->free);
    TAILQ_REMOVE(&mPool->free, mentry, entries);
    TAILQ_INSERT_TAIL(&mPool->inuse, mentry, entries);
    pthread_mutex_unlock(&mPool->mp_mutex);
    mPool->freeSz--;
    return &mentry->element->element[0];
}

// +----------------------------------------------------------------------------
// | Return an element to the memory pool.
// | mPool - memory pool handle
// | element - pointer to element allocated with mempool_alloc
// | wipe - zero out element memory if true, which has a performance impact
// +----------------------------------------------------------------------------
void mempool_free(mempool mPool, void *element, bool wipe)
{
    struct element_s        *elementp = element-sizeof(struct element_s);
    struct mpool_entry_s    *mentry;
    unsigned int            *elementi, elementSz_in_words, i;

    if (mPool == NULL) return;
    pthread_mutex_lock(&mPool->mp_mutex);
    if (elementp->guard != 0xdeadbeef) {
        // we can't trust the mentry pointer because someone stomped on our memory
        // do a linear search for the mentry
        TAILQ_FOREACH(mentry, &mPool->inuse, entries) {
            if (mentry->element == (struct element_s *) elementp) {
                elementp->guard     = 0xdeadbeef;
                elementp->mentry    = mentry;
                break;
            }
        }
    } else {
        mentry = (struct mpool_entry_s *) elementp->mentry;
    }
    if (mentry == (struct mpool_entry_s *) elementp->mentry) {
        TAILQ_REMOVE(&mPool->inuse, mentry, entries);
        TAILQ_INSERT_TAIL(&mPool->free, mentry, entries);
        if (wipe) {
            elementSz_in_words  = mPool->elementSz / sizeof(unsigned int);
            elementi            = (unsigned int *) element;
            for (i=0; i<elementSz_in_words; i++) elementi[i] = 0;
        }
        mPool->freeSz++;
    } else {
        log_msg(LOG_ERR, "%s-%d: Corrupted memory pool entry detected. Entry has become unusable.\n", __FUNCTION__, __LINE__);
    }
    pthread_mutex_unlock(&mPool->mp_mutex);
}

// +----------------------------------------------------------------------------
// | Return the number of free elements in the memory pool.
// | mPool - memory pool handle
// +----------------------------------------------------------------------------
unsigned int mempool_freeSz(mempool mPool)
{
    if (mPool == NULL) return 0;
    return mPool->freeSz;
}

// +----------------------------------------------------------------------------
// | Return the total number of bytes allocated for the memory pool.
// | mPool - memory pool handle
// +----------------------------------------------------------------------------
unsigned int mempool_totalSz(mempool mPool)
{
    if (mPool == NULL) return 0;
    return mPool->totalSz;
}

// +----------------------------------------------------------------------------
// | Return the total number of bytes allocated for managing the memory pool.
// | mPool - memory pool handle
// +----------------------------------------------------------------------------
unsigned int mempool_overheadSz(mempool mPool)
{
    if (mPool == NULL) return 0;
    return mPool->overheadSz;
}
