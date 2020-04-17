BIN = moonhermit

PREFIX = /usr/local
BINDIR = $(PREFIX)/bin
MANDIR = $(PREFIX)/share/man

CFLAGS = -Wall -Werror -Wextra -Wno-unused-variable -Wno-unused-parameter -Wno-unused-but-set-variable -Wno-unused-function -I/usr/include/lua5.3

ifdef STATIC
	LDLIBS = -l:libsodium.a -l:liblua5.3.a
else
	LDLIBS = -lsodium -llua5.3
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

.PHONY:
	all install link uninstall test-shs1 clean
