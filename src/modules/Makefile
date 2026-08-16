
# find the OS
uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')

# Compile flags for linux / macOS
ifeq ($(uname_S),Linux)
	SHOBJ_CFLAGS ?= -W -Wall -fno-common -g -ggdb -std=gnu11 -O2
	SHOBJ_LDFLAGS ?= -shared
else
	SHOBJ_CFLAGS ?= -W -Wall -dynamic -fno-common -g -ggdb -std=gnu11 -O2
	SHOBJ_LDFLAGS ?= -bundle -undefined dynamic_lookup
endif

# OS X 11.x doesn't have /usr/lib/libSystem.dylib and needs an explicit setting.
ifeq ($(uname_S),Darwin)
ifeq ("$(wildcard /usr/lib/libSystem.dylib)","")
LIBS = -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib -lsystem
endif
endif

.SUFFIXES: .c .so .xo .o

all: helloworld.so hellotype.so helloblock.so hellocluster.so hellotimer.so hellodict.so hellohook.so helloacl.so nexvector.so nexts_module.so nexbp_module.so

.c.xo:
	$(CC) -I. $(CFLAGS) $(SHOBJ_CFLAGS) -fPIC -c $< -o $@

helloworld.xo: ../nexcachemodule.h

helloworld.so: helloworld.xo
	$(LD) -o $@ $^ $(SHOBJ_LDFLAGS) $(LIBS) -lc

hellotype.xo: ../nexcachemodule.h

hellotype.so: hellotype.xo
	$(LD) -o $@ $^ $(SHOBJ_LDFLAGS) $(LIBS) -lc

helloblock.xo: ../nexcachemodule.h

helloblock.so: helloblock.xo
	$(LD) -o $@ $^ $(SHOBJ_LDFLAGS) $(LIBS) -lpthread -lc

hellocluster.xo: ../nexcachemodule.h

hellocluster.so: hellocluster.xo
	$(LD) -o $@ $^ $(SHOBJ_LDFLAGS) $(LIBS) -lc

hellotimer.xo: ../nexcachemodule.h

hellotimer.so: hellotimer.xo
	$(LD) -o $@ $^ $(SHOBJ_LDFLAGS) $(LIBS) -lc

hellodict.xo: ../nexcachemodule.h

hellodict.so: hellodict.xo
	$(LD) -o $@ $^ $(SHOBJ_LDFLAGS) $(LIBS) -lc

hellohook.xo: ../nexcachemodule.h

hellohook.so: hellohook.xo
	$(LD) -o $@ $^ $(SHOBJ_LDFLAGS) $(LIBS) -lc

helloacl.xo: ../nexcachemodule.h

helloacl.so: helloacl.xo
	$(LD) -o $@ $^ $(SHOBJ_LDFLAGS) $(LIBS) -lc

nexvector.xo: ../nexcachemodule.h ../vector/hnsw.h

nexvector.so: nexvector.xo
	$(LD) -o $@ $^ $(SHOBJ_LDFLAGS) $(LIBS) -lpthread -lc

# nexts.c non è compilato nel server principale (assente da src/Makefile
# OBJS), quindi va compilato ed embeddato direttamente in questo modulo
# invece di fare affidamento su dynamic_lookup contro nexcache-server.
nexts.xo: ../timeseries/nexts.c ../timeseries/nexts.h
	$(CC) -I. $(CFLAGS) $(SHOBJ_CFLAGS) -fPIC -c ../timeseries/nexts.c -o nexts.xo

nexts_module.xo: ../nexcachemodule.h ../timeseries/nexts.h

nexts_module.so: nexts_module.xo nexts.xo
	$(LD) -o $@ $^ $(SHOBJ_LDFLAGS) $(LIBS) -lpthread -lc

# reactive.c (backpressure streams) è nella stessa situazione di nexts.c:
# non compilato nel server principale, va embeddato nel modulo.
reactive.xo: ../streams/reactive.c ../streams/reactive.h
	$(CC) -I. $(CFLAGS) $(SHOBJ_CFLAGS) -fPIC -c ../streams/reactive.c -o reactive.xo

nexbp_module.xo: ../nexcachemodule.h ../streams/reactive.h

nexbp_module.so: nexbp_module.xo reactive.xo
	$(LD) -o $@ $^ $(SHOBJ_LDFLAGS) $(LIBS) -lpthread -lc

clean:
	rm -rf *.xo *.so
