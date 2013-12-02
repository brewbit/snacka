
WITH_BACKEND ?= YES

LIB_SRC = $(wildcard src/snacka/*.c) \
          $(wildcard src/external/uriparser/*.c) \
          $(wildcard src/external/http_parser/*.c)

ifeq ($(WITH_BACKEND),YES)
LIB_SRC += $(wildcard src/snacka/backends/bsdsocket/*.c)
endif

LIB_OBJS = $(patsubst %.c,%.o,$(LIB_SRC)) 
LIB_HEADERS = $(wildcard src/snacka/*.h) $(wildcard src/external/*/**.h)

TEST_SRC = $(wildcard src/test/autobahntestsuite/*.c)
TEST_OBJS = $(patsubst %.c,%.o,$(TEST_SRC)) 
TEST_HEADERS = $(wildcard src/test/autobahntestsuite/*.h)

LIB_DIR = build
LIB_NAME = snacka

AR = ar
ARFLAGS = rcs
CC = gcc
CFLAGS = -Wall -O3 -std=c99 -c -Isrc -Isrc/include
LOADLIBES = -L./

.PHONY = all lib autobahntestsuite

all: lib autobahntestsuite

lib: $(LIB_DIR) $(LIB_OBJS) $(LIB_HEADERS)
	$(AR) $(ARFLAGS) $(LIB_DIR)/lib$(LIB_NAME).a $(LIB_OBJS)

autobahntestsuite: $(LIB_DIR) lib $(TEST_OBJS)
	$(CC) $(TEST_OBJS) -o build/autobahntestsuite -L$(LIB_DIR) -l$(LIB_NAME) -lcurl

$(LIB_OBJS) : $(LIB_SRC) $(LIB_HEADERS)

$(TEST_OBJS) : $(TEST_SRC) $(TEST_HEADERS)

$(LIB_DIR):
	mkdir $(LIB_DIR)

clean:
	rm -rf $(LIB_DIR)
	rm -f $(LIB_OBJS)
	rm -f $(TEST_OBJS)