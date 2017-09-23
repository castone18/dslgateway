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
// | mempool_ut.cpp
// |    mempool unit tests.
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

#define CATCH_CONFIG_RUNNER
#include "catch.hpp"

#define TEST_MEMPOOL_NELEMENTS  4096

struct test_element_s {
    unsigned int    testuint;
    char            testchar[8];
};

static mempool  my_mempool;

int main(int argc, char *argv[]) {
    int                     result;

    result = Catch::Session().run(argc, argv);


    exit(result<0xff ? result : 0xff);
}

TEST_CASE("Check that create a memory pool works.", "[mempool]") {
    unsigned int totalsz, overheadsz;

    printf("Check that create a memory pool works.... ");
    REQUIRE((my_mempool = mempool_create(sizeof(struct test_element_s), TEST_MEMPOOL_NELEMENTS)) != NULL);
    REQUIRE(mempool_freeSz(my_mempool) == TEST_MEMPOOL_NELEMENTS);
    REQUIRE((totalsz = mempool_totalSz(my_mempool)) > 0);
    REQUIRE((overheadsz = mempool_overheadSz(my_mempool)) > 0);
    printf(" Memory Pool Total Size: %u   Overhead Size: %u ...", totalsz, overheadsz);
    printf("Pass.\n");
}

TEST_CASE("Check that allocate and free works.", "[mempool]") {
    struct test_element_s *my_element = (struct test_element_s *) mempool_alloc(my_mempool);

    printf("Check that allocate and free works.... ");
    REQUIRE(my_element != NULL);
    REQUIRE(mempool_freeSz(my_mempool) == TEST_MEMPOOL_NELEMENTS-1);
    mempool_free(my_mempool, my_element, true);
    REQUIRE(mempool_freeSz(my_mempool) == TEST_MEMPOOL_NELEMENTS);
    printf("Pass.\n");
}

TEST_CASE("Check that allocate and free all elements works.", "[mempool]") {
    struct test_element_s *my_element[TEST_MEMPOOL_NELEMENTS];
    int i;

    printf("Check that allocate and free all elements works.... ");
    for (i=0; i<TEST_MEMPOOL_NELEMENTS; i++) {
        my_element[i] = (struct test_element_s *) mempool_alloc(my_mempool);
        REQUIRE(my_element[i] != NULL);
    }
    REQUIRE(mempool_freeSz(my_mempool) == 0);
    REQUIRE(mempool_alloc(my_mempool) == NULL);
    for (i=0; i<TEST_MEMPOOL_NELEMENTS; i++) {
        mempool_free(my_mempool, my_element[i], true);
    }
    REQUIRE(mempool_freeSz(my_mempool) == TEST_MEMPOOL_NELEMENTS);
    printf("Pass.\n");
}

TEST_CASE("Check that destroy a memory pool works.", "[mempool]") {

    printf("Check that destroy a memory pool works.... ");
    mempool_destroy(my_mempool);
    printf("Pass.\n");
}
