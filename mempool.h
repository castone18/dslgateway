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
// | mempool.h
// |    Memory pool API. Functions to manage a chunk of memory with allocation
// | and free of fixed sized elements.
// |
// +----------------------------------------------------------------------------


#ifndef MEMPOOL_H
#define MEMPOOL_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mempool_s *mempool;

#define MEM_POOL_INVALID   NULL

// +----------------------------------------------------------------------------
// | Creates a memory pool.
// | elementSz - size of each element in the memory pool
// | nElements - maximum number of elements to keep in the pool
// | returns opaque handle that is provided to memory pool functions to identify pool
// +----------------------------------------------------------------------------
mempool mempool_create(unsigned int elementSz, unsigned int nElements);

// +----------------------------------------------------------------------------
// | Destroy a memory pool.
// | mPool - memory pool handle
// +----------------------------------------------------------------------------
void mempool_destroy(mempool mPool);

// +----------------------------------------------------------------------------
// | Allocate an item from the memory pool.
// | mPool - memory pool handle
// | returns NULL if memory pool is empty, pointer to element otherwise
// +----------------------------------------------------------------------------
void *mempool_alloc(mempool mPool);

// +----------------------------------------------------------------------------
// | Return an element to the memory pool.
// | mPool - memory pool handle
// | element - pointer to element allocated with mempool_alloc
// | wipe - zero out element memory, which has a performance impact
// +----------------------------------------------------------------------------
void mempool_free(mempool mPool, void *element, bool wipe);

// +----------------------------------------------------------------------------
// | Return the number of free elements in the memory pool.
// | mPool - memory pool handle
// +----------------------------------------------------------------------------
unsigned int mempool_freeSz(mempool mPool);

// +----------------------------------------------------------------------------
// | Return the total number of bytes allocated for the memory pool.
// | mPool - memory pool handle
// +----------------------------------------------------------------------------
unsigned int mempool_totalSz(mempool mPool);

// +----------------------------------------------------------------------------
// | Return the total number of bytes allocated for managing the memory pool.
// | mPool - memory pool handle
// +----------------------------------------------------------------------------
unsigned int mempool_overheadSz(mempool mPool);

#ifdef __cplusplus
}
#endif

#endif /* MEMPOOL_H */

