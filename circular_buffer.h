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
// | circular_buffer.h
// |    Circular buffer API.
// |
// +----------------------------------------------------------------------------

#ifndef CIRCULAR_BUFFER_H
#define CIRCULAR_BUFFER_H

#include "mempool.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct circular_buffer_s *circular_buffer;

#define CIRCULAR_BUFFER_INVALID   NULL

// +----------------------------------------------------------------------------
// | Creates a circular buffer. Note that multiple circular buffers can share
// | the same memory pool.
// | mPool - the backing storage memory pool
// | nElements - maximum size of the circular buffer in elements
// | returns opaque handle that is provided to circular buffer functions to identify buffer
// +----------------------------------------------------------------------------
circular_buffer circular_buffer_create(unsigned int nElements, mempool mPool);

// +----------------------------------------------------------------------------
// | Destroy a circular buffer.
// | cBuf - buffer handle
// +----------------------------------------------------------------------------
void circular_buffer_destroy(circular_buffer cBuf);

// +----------------------------------------------------------------------------
// | Push an element on the head of the circular buffer.
// | cBuf - buffer handle
// | element - pointer to element
// +----------------------------------------------------------------------------
void circular_buffer_push(circular_buffer cBuf, void *element);

// +----------------------------------------------------------------------------
// | Pop an element from the tail of the circular buffer.
// | cBuf - buffer handle
// | Returns NULL if buffer is empty, element pointer otherwise
// +----------------------------------------------------------------------------
void *circular_buffer_pop(circular_buffer cBuf);

// +----------------------------------------------------------------------------
// | Removes all the elements from the buffer and returns them to the 
// | memory pool.
// | cBuf - buffer handle
// +----------------------------------------------------------------------------
void circular_buffer_clear(circular_buffer cBuf);

// +----------------------------------------------------------------------------
// | Determine if circular buffer is empty.
// | cBuf - buffer handle
// | returns true if the circular buffer is empty, false otherwise
// +----------------------------------------------------------------------------
bool circular_buffer_is_empty(circular_buffer cBuf);

// +----------------------------------------------------------------------------
// | Determine if circular buffer is full.
// | cBuf - buffer handle
// | returns true if the circular buffer is full, false otherwise
// +----------------------------------------------------------------------------
bool circular_buffer_is_full(circular_buffer cBuf);

// +----------------------------------------------------------------------------
// | Get the number of elements in the circular buffer
// | cBuf - buffer handle
// | returns the number of elements in the circular buffer
// +----------------------------------------------------------------------------
unsigned int circular_buffer_sz(circular_buffer cBuf);

// +----------------------------------------------------------------------------
// | Get the number of free elements in the circular buffer
// | cBuf - buffer handle
// | returns the number of free elements in the circular buffer
// +----------------------------------------------------------------------------
unsigned int circular_buffer_freesz(circular_buffer cBuf);

// +----------------------------------------------------------------------------
// | Get the overhead memory size for the circular buffer
// | cBuf - buffer handle
// | returns the overhead memory size for the circular buffer
// +----------------------------------------------------------------------------
unsigned int circular_buffer_overheadsz(circular_buffer cBuf);


#ifdef __cplusplus
}
#endif

#endif /* CIRCULAR_BUFFER_H */

