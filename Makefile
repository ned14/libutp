OBJS     = utp_internal.o utp_utils.o utp_hash.o utp_callbacks.o utp_api.o utp_packedsockaddr.o utp_crust.o
CFLAGS   = -Wall -DPOSIX -g
CXXFLAGS = $(CFLAGS) -fPIC -std=c++0x -sanitize=undefined
#CC       = gcc
#CXX      = g++ 

CXXFLAGS += -Wno-sign-compare
CXXFLAGS += -fpermissive -pthread

debug: CXXFLAGS += -D_DEBUG -g
debug: CCFLAGS += -D_DEBUG -g
all: CXXFLAGS += -O3 -DNDEBUG -g
all: CCFLAGS += -O3 -DNDEBUG -g

# Uncomment to enable utp_get_stats(), and a few extra sanity checks
#CFLAGS += -D_DEBUG

# Uncomment to enable debug logging
#CFLAGS += -DUTP_DEBUG_LOGGING

# Dynamically determine if librt is available.  If so, assume we need to link
# against it for clock_gettime(2).  This is required for clean builds on OSX;
# see <https://github.com/bittorrent/libutp/issues/1> for more.  This should
# probably be ported to CMake at some point, but is suitable for now.
lrt := $(shell echo 'int main() {}' | $(CC) -xc -o /dev/null - -lrt >/dev/null 2>&1; echo $$?)
ifeq ($(strip $(lrt)),0)
  LDFLAGS += -lrt
endif

all: libutp.so libutp.a ucat ucat-static test_utp_crust
debug: libutp.so libutp.a ucat ucat-static test_utp_crust

libutp.so: $(OBJS)
	$(CXX) $(CXXFLAGS) -o libutp.so -shared $(OBJS)

libutp.a: $(OBJS)
	ar rvs libutp.a $(OBJS)

ucat: ucat.o libutp.so
	$(CC) $(CFLAGS) -o ucat ucat.o -L. -lutp $(LDFLAGS)

ucat-static: ucat.o libutp.a
	$(CXX) $(CXXFLAGS) -o ucat-static ucat.o libutp.a $(LDFLAGS)
	
test_utp_crust: test_utp_crust.o libutp.a
	$(CXX) $(CXXFLAGS) -o test_utp_crust test_utp_crust.o libutp.a $(LDFLAGS)

clean:
	rm -f *.o libutp.so libutp.a ucat ucat-static test_utp_crust

tags: $(shell ls *.cpp *.h)
	rm -f tags
	ctags *.cpp *.h

anyway: clean all
.PHONY: clean all anyway
