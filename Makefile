APPS = app/udpc.exe \
       app/udps.exe \
       app/tcpc.exe \
       app/tcps.exe \

TESTS = test/test.exe \
        test/v6test_tap.exe \
        test/v6test_pcap.exe \
        test/v6test_udp_srv.exe \
        test/v6test_udp_cli.exe \
        test/v6test_slaac.exe \
        test/v6test_tcp.exe \

DRIVERS = driver/null.o \
          driver/loopback.o \

OBJS = util.o \
       net.o \
       ether.o \
       arp.o \
       ip.o \
       icmp.o \
       udp.o \
       tcp.o \
       sock.o \
       ip6.o \
       icmp6.o \
       nd6.o \
       udp6.o \
       tcp6.o \
       slaac.o \

CFLAGS := $(CFLAGS) -g -W -Wall -Wno-unused-parameter -iquote .

ifeq ($(shell uname),Linux)
       CFLAGS := $(CFLAGS) -pthread -iquote platform/linux
       DRIVERS := $(DRIVERS) platform/linux/driver/ether_tap.o platform/linux/driver/ether_pcap.o
       LDFLAGS := $(LDFLAGS) -lrt
       OBJS := $(OBJS) platform/linux/sched.o platform/linux/intr.o
endif

ifeq ($(shell uname),Darwin)
       CFLAGS := $(CFLAGS)
       DRIVERS := $(DRIVERS)
endif

.SUFFIXES:
.SUFFIXES: .c .o

.PHONY: all clean

all: $(APPS) $(TESTS)

$(APPS): %.exe : %.o $(OBJS) $(DRIVERS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(TESTS): %.exe : %.o $(OBJS) $(DRIVERS) test/test.h
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(APPS) $(APPS:.exe=.o) $(OBJS) $(DRIVERS) $(TESTS) $(TESTS:.exe=.o)

tap:
	sudo ./script/tap.sh

setup:
	sudo ./script/setup.sh

cleanup:
	sudo ip --all netns delete

