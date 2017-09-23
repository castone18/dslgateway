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
// | circular_buffer_ut.cpp
// |    circular buffer unit tests.
// |
// +----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/queue.h>
#include <pthread.h>

#include "mempool.h"
#include "circular_buffer.h"

#define CATCH_CONFIG_RUNNER
#include "catch.hpp"

#define TEST_MEMPOOL_NELEMENTS  4096
#define TEST_CBUF_NELEMENTS     2048

struct test_element_s {
    unsigned int    testuint;
    char            testchar[8];
};

static mempool          my_mempool;
static circular_buffer  my_cbuf;

int main(int argc, char *argv[]) {
    int                     result;

    if ((my_mempool = mempool_create(sizeof(struct test_element_s), TEST_MEMPOOL_NELEMENTS)) == NULL) exit(EINVAL);

    result = Catch::Session().run(argc, argv);

    mempool_destroy(my_mempool);

    exit(result<0xff ? result : 0xff);
}

TEST_CASE("Check that create a circular buffer works.", "[circbuf]") {

    printf("Check that create a circular buffer works.... ");
    REQUIRE((my_cbuf = circular_buffer_create(TEST_CBUF_NELEMENTS, my_mempool)) != NULL);
    REQUIRE(circular_buffer_sz(my_cbuf) == 0);
    REQUIRE(circular_buffer_is_empty(my_cbuf));
    REQUIRE(!circular_buffer_is_full(my_cbuf));
    printf("Pass.\n");
}

TEST_CASE("Check that push and pop works.", "[circbuf]") {
    struct test_element_s *my_element = (struct test_element_s *) mempool_alloc(my_mempool);

    printf("Check that push and pop works.... ");
    my_element->testuint    = 10;
    sprintf(my_element->testchar, "Hello.");
    circular_buffer_push(my_cbuf, my_element);
    my_element = NULL;
    REQUIRE(circular_buffer_sz(my_cbuf) == 1);
    REQUIRE(!circular_buffer_is_empty(my_cbuf));
    REQUIRE(!circular_buffer_is_full(my_cbuf));
    my_element = (struct test_element_s *) circular_buffer_pop(my_cbuf);
    REQUIRE(my_element->testuint == 10);
    REQUIRE(strncmp(my_element->testchar, "Hello.", 6) == 0);
    REQUIRE(circular_buffer_sz(my_cbuf) == 0);
    REQUIRE(circular_buffer_is_empty(my_cbuf));
    REQUIRE(!circular_buffer_is_full(my_cbuf));
    mempool_free(my_mempool, my_element, true);
    printf("Pass.\n");
}

TEST_CASE("Check that push and pop all elements works.", "[circbuf]") {
    struct test_element_s *my_element;
    int i, j;

    printf("Check that push and pop all elements works.... ");
    for (i=0; i<TEST_CBUF_NELEMENTS; i++) {
        my_element = (struct test_element_s *) mempool_alloc(my_mempool);
        REQUIRE(my_element != NULL);
        my_element->testuint    = i;
        sprintf(my_element->testchar, "%d", i);
        circular_buffer_push(my_cbuf, my_element);
    }
    REQUIRE(circular_buffer_sz(my_cbuf) == TEST_CBUF_NELEMENTS);
    REQUIRE(!circular_buffer_is_empty(my_cbuf));
    REQUIRE(circular_buffer_is_full(my_cbuf));
    for (i=0; i<TEST_CBUF_NELEMENTS; i++) {
        my_element = (struct test_element_s *) circular_buffer_pop(my_cbuf);
        REQUIRE(my_element != NULL);
        REQUIRE(my_element->testuint == i);
        sscanf(my_element->testchar, "%d", &j);
        REQUIRE(i == j);
        mempool_free(my_mempool, my_element, true);
    }
    REQUIRE(circular_buffer_sz(my_cbuf) == 0);
    REQUIRE(circular_buffer_is_empty(my_cbuf));
    REQUIRE(!circular_buffer_is_full(my_cbuf));
    printf("Pass.\n");
}

TEST_CASE("Check that destroy a circular buffer works.", "[circbuf]") {

    printf("Check that destroy a circular buffer works.... ");
    circular_buffer_destroy(my_cbuf);
    printf("Pass.\n");
}
