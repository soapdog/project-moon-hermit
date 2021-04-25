BIN = moonhermit

SODIUM = libsodium-1.0.18
LUA = lua-5.4.3

PREFIX = /usr/local
BINDIR = $(PREFIX)/bin
MANDIR = $(PREFIX)/share/man


CFLAGS = -Wall -Werror -Wextra -Wno-unused-const-variable -Wno-unused-parameter -Wno-unused-function -I$(PWD)/vendor/$(LUA)/src -I$(PWD)/vendor/$(SODIUM)/sodium-build/include

ifdef SHARED
	LDLIBS = -lsodium -llua5.4
else
	LDFLAGS= -L$(PWD)/vendor/$(SODIUM)/sodium-build/lib -L$(PWD)/vendor/$(LUA)/src
	LDLIBS = -llua  -lsodium
endif

all: $(BIN)

$(BIN): $(BIN).c base64.c jsmn.c

install: all
	@mkdir -vp $(DESTDIR)$(BINDIR) $(DESTDIR)$(MANDIR)/man1
	@cp -vf $(BIN) $(DESTDIR)$(BINDIR)
	@cp -vf $(BIN).1 $(DESTDIR)$(MANDIR)/man1

link: all
	@mkdir -vp $(DESTDIR)$(BINDIR) $(DESTDIR)$(MANDIR)/man1
	@ln -svf $(shell realpath $(BIN)) $(DESTDIR)$(BINDIR)
	@ln -svf $(shell realpath $(BIN).1) $(DESTDIR)$(MANDIR)/man1

uninstall:
	@rm -vf \
		$(DESTDIR)$(BINDIR)/$(BIN) \
		$(DESTDIR)$(MANDIR)/man1/$(BIN).1

test-shs1:
	@# %lzzcAZlM21slUIoiH4yd/wgDnXu8raNLvwqjxqrU06k=.sha256
	shs1testclient ./test-shs-inner.sh $(SHS1_TEST_SEED)

clean:
	@rm -vf $(BIN)
	cd ./vendor/$(SODIUM) && make clean
	cd ./vendor/$(LUA) && make clean
	
deps-sodium:
	cd ./vendor/$(SODIUM) && \
	./configure --prefix=$(PWD)/vendor/$(SODIUM)/sodium-build/ && \
	make && make check && make install && rm $(PWD)/vendor/$(SODIUM)/sodium-build/lib/*.dylib
	
deps-lua:
	cd ./vendor/$(LUA) && \
	make
	
deps: deps-sodium deps-lua

.PHONY:
	all install link uninstall test-shs1 clean
