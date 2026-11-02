# ps5-perf - perf(1)-style profiler payload for the PlayStation 5
#
#   make                 build ps5-perf.elf
#   make deploy          send it to elfldr (PS5_HOST / PS5_PORT, default 9021)
#   make PS5PERF_PORT=N  change the TCP port the payload listens on (default 9077)

PS5_HOST ?= ps5
PS5_PORT ?= 9021
PS5PERF_PORT ?= 9077

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

ELF  := ps5-perf.elf
SRCS := $(wildcard src/*.c)
OBJS := $(SRCS:src/%.c=build/%.o) build/nid_table.o

CFLAGS := -std=gnu11 -Wall -Wextra -Wno-unused-parameter -Werror -O2 -g \
          -DPS5PERF_PORT=$(PS5PERF_PORT)
LDADD  := -lkernel_sys -lpthread

all: $(ELF)

build/%.o: src/%.c src/ps5perf.h
	@mkdir -p build
	$(CC) $(CFLAGS) -c -o $@ $<

build/nid_table.c: tools/gen_nids.py
	@mkdir -p build
	python3 tools/gen_nids.py $(PS5_PAYLOAD_SDK) $@

build/nid_table.o: build/nid_table.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(ELF): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDADD)

deploy: $(ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $<

clean:
	rm -rf build $(ELF)

.PHONY: all deploy clean
