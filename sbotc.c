/*
 * sbotc.c
 * Copyright (c) 2017 Secure Scuttlebutt Consortium
 *
 * Usage of the works is permitted provided that this instrument is
 * retained with the works, so that any entity that uses the works is
 * notified of this instrument.
 *
 * DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
 */

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <termios.h>
#include <unistd.h>

#include <sodium.h>

#include "base64.h"
#include "jsmn.h"

#define BOXS_MAXLEN 4096

#define write_buf(fd, buf) \
	write_all(fd, buf, sizeof(buf)-1)

struct boxs_header {
	uint16_t len;
	uint8_t mac[16];
};

struct boxs {
	int s;
	unsigned char encrypt_key[32];
	unsigned char decrypt_key[32];
	unsigned char nonce1[24];
	unsigned char nonce2[24];
	unsigned char rx_nonce[24];
	unsigned char rx_buf[BOXS_MAXLEN];
	size_t rx_buf_pos;
	size_t rx_buf_len;
	bool noauth;
	bool wrote_goodbye;
};

enum pkt_type {
	pkt_type_buffer = 0,
	pkt_type_string = 1,
	pkt_type_json = 2,
};

enum pkt_flags {
	pkt_flags_buffer = 0,
	pkt_flags_string = 1,
	pkt_flags_json = 2,
	pkt_flags_end = 4,
	pkt_flags_stream = 8,
};

struct pkt_header {
	uint32_t len;
	int32_t req;
} __attribute__((packed));

enum muxrpc_type {
	muxrpc_type_async,
	muxrpc_type_source,
	muxrpc_type_sink,
	muxrpc_type_duplex,
};

enum stream_state {
	stream_state_open,
	stream_state_ended_ok,
	stream_state_ended_error,
};

enum ip_family {
	ip_family_ipv4 = AF_INET,
	ip_family_ipv6 = AF_INET6,
	ip_family_any = AF_UNSPEC
};

static unsigned char zeros[24] = {0};

static const unsigned char ssb_cap[] = {
	0xd4, 0xa1, 0xcb, 0x88, 0xa6, 0x6f, 0x02, 0xf8,
	0xdb, 0x63, 0x5c, 0xe2, 0x64, 0x41, 0xcc, 0x5d,
	0xac, 0x1b, 0x08, 0x42, 0x0c, 0xea, 0xac, 0x23,
	0x08, 0x39, 0xb7, 0x55, 0x84, 0x5a, 0x9f, 0xfb
};

struct termios orig_tc;

static void reset_termios() {
	int rc = tcsetattr(STDIN_FILENO, TCSANOW, &orig_tc);
	if (rc < 0) warn("tcsetattr");
}

static void usage() {
	fputs("usage: sbotc [-j] [-T] [-l] [-r] [-e]\n"
	      "             [ -n | [-c <cap>] [-k <key>] [-K <keypair_seed>] ]\n"
	      "             [ [-s <host>] [-p <port>] [ -4 | -6 ] | [-u <socket_path>] ]\n"
	      "             [ -a | [-t <type>] <method> [<argument>...] ]\n", stderr);
	exit(EXIT_FAILURE);
}

static int connect_localhost(const char *port, enum ip_family ip_family) {
	int rc, family, fd, err;
	struct ifaddrs *ifaddr, *ifa;
	rc = getifaddrs(&ifaddr);
	if (rc < 0) return -1;
	int port_n = htons(atoi(port));

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL) continue;
		family = ifa->ifa_addr->sa_family;
		socklen_t addrlen;
		if (family == AF_INET) {
			if (ip_family != ip_family_ipv4 && ip_family != ip_family_any) continue;
			addrlen = sizeof(struct sockaddr_in);
			struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
			addr->sin_port = port_n;
		} else if (family == AF_INET6) {
			if (ip_family != ip_family_ipv6 && ip_family != ip_family_any) continue;
			addrlen = sizeof(struct sockaddr_in6);
			struct sockaddr_in6 *addr = (struct sockaddr_in6 *)ifa->ifa_addr;
			addr->sin6_port = port_n;
		} else continue;
		fd = socket(family, SOCK_STREAM, IPPROTO_TCP);
		if (fd < 0) continue;
		if (connect(fd, ifa->ifa_addr, addrlen) == 0) break;
		err = errno;
		close(fd);
		errno = err;
	}
	if (ifa == NULL) fd = -1;

	freeifaddrs(ifaddr);
	return fd;
}

static int tcp_connect(const char *host, const char *port, enum ip_family ip_family) {
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int s;
	int fd;
	int err;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = ip_family;
	hints.ai_protocol = IPPROTO_TCP;

	s = getaddrinfo(host, port, &hints, &result);
	if (s < 0) errx(1, "unable to resolve host: %s", gai_strerror(s));

	for (rp = result; rp; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd < 0) continue;
		if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
		err = errno;
		close(fd);
		errno = err;
	}
	if (rp == NULL) fd = -1;

	freeaddrinfo(result);

	if (fd == -1 && errno == ECONNREFUSED && (host == NULL || !strcmp(host, "localhost"))) {
		return connect_localhost(port, ip_family);
	}

	return fd;
}

static int unix_connect(const char *path) {
	struct sockaddr_un name;
	const size_t path_len = strlen(path);
	int s, rc;
	if (path_len >= sizeof(name.sun_path)-1) errx(1, "socket path too long");
	s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0) return -1;
	memset(&name, 0, sizeof(struct sockaddr_un));
	name.sun_family = AF_UNIX;
	strncpy(name.sun_path, path, sizeof(name.sun_path) - 1);
	rc = connect(s, (const struct sockaddr *)&name, sizeof name);
	if (rc < 0) return -1;
	return s;
}

static int get_socket_path(char *buf, size_t len, const char *app_dir) {
	struct stat st;
	int sz = snprintf(buf, len-1, "%s/%s", app_dir, "socket");
	if (sz < 0 || sz >= (int)len-1) err(1, "failed to get socket path");
	int rc = stat(buf, &st);
	if (rc < 0) return -1;
	if (!(st.st_mode & S_IFSOCK)) { errno = EINVAL; return -1; }
	return 0;
}

static int read_all(int fd, void *buf, size_t count) {
	ssize_t nbytes;
	while (count > 0) {
		nbytes = read(fd, buf, count);
		if (nbytes == 0) { errno = EPIPE; return -1; }
		if (nbytes < 0 && errno == EINTR) continue;
		if (nbytes < 0) return -1;
		buf += nbytes;
		count -= nbytes;
	}
	return 0;
}

static int read_some(int fd, unsigned char *buf, size_t *lenp) {
	ssize_t nbytes;
	do nbytes = read(fd, buf, *lenp);
	while (nbytes < 0 && errno == EINTR);
	if (nbytes == 0) { errno = EPIPE; return -1; }
	if (nbytes < 0) return -1;
	*lenp = nbytes;
	return 0;
}

static int write_all(int fd, const void *buf, size_t count) {
	ssize_t nbytes;
	while (count > 0) {
		nbytes = write(fd, buf, count);
		if (nbytes < 0 && errno == EINTR) continue;
		if (nbytes < 0) return -1;
		buf += nbytes;
		count -= nbytes;
	}
	return 0;
}

static void shs_connect(int sfd, int infd, int outfd, const unsigned char pubkey[32], const unsigned char seckey[64], const unsigned char appkey[32], const unsigned char server_pubkey[32], struct boxs *bs) {
	int rc;
	unsigned char local_app_mac[32], remote_app_mac[32];

	unsigned char kx_pk[32], kx_sk[32];
	rc = crypto_box_keypair(kx_pk, kx_sk);
	if (rc < 0) errx(1, "failed to generate auth keypair");

	rc = crypto_auth(local_app_mac, kx_pk, 32, appkey);
	if (rc < 0) err(1, "failed to generate app mac");

	// send challenge
	unsigned char buf[64];
	memcpy(buf, local_app_mac, 32);
	memcpy(buf+32, kx_pk, 32);
	rc = write_all(outfd, buf, sizeof(buf));
	if (rc < 0) err(1, "failed to send challenge");

	// recv challenge
	unsigned char remote_kx_pk[32];
	rc = read_all(infd, buf, sizeof(buf));
	if (rc < 0) err(1, "challenge not accepted");
	memcpy(remote_app_mac, buf, 32);
	memcpy(remote_kx_pk, buf+32, 32);
	rc = crypto_auth_verify(buf, remote_kx_pk, 32, appkey);
	if (rc < 0) errx(1, "wrong protocol (version?)");

	// send auth

	unsigned char secret[32];
	rc = crypto_scalarmult(secret, kx_sk, remote_kx_pk);
	if (rc < 0) errx(1, "failed to derive shared secret");

	unsigned char remote_pk_curve[32];
	rc = crypto_sign_ed25519_pk_to_curve25519(remote_pk_curve, server_pubkey);
	if (rc < 0) errx(1, "failed to curvify remote public key");

	unsigned char a_bob[32];
	rc = crypto_scalarmult(a_bob, kx_sk, remote_pk_curve);
	if (rc < 0) errx(1, "failed to derive a_bob");

	unsigned char secret2a[96];
	memcpy(secret2a, appkey, 32);
	memcpy(secret2a+32, secret, 32);
	memcpy(secret2a+64, a_bob, 32);

	unsigned char secret2[32];
	rc = crypto_hash_sha256(secret2, secret2a, sizeof(secret2a));
	if (rc < 0) errx(1, "failed to hash secret2");

	unsigned char shash[32];
	rc = crypto_hash_sha256(shash, secret, sizeof(secret));
	if (rc < 0) errx(1, "failed to hash secret");

	unsigned char signed1[96];
	memcpy(signed1, appkey, 32);
	memcpy(signed1+32, server_pubkey, 32);
	memcpy(signed1+64, shash, 32);

	unsigned char sig[64];
	rc = crypto_sign_detached(sig, NULL, signed1, sizeof(signed1), seckey);
	if (rc < 0) errx(1, "failed to sign inner hello");

	unsigned char hello[96];
	memcpy(hello, sig, 64);
	memcpy(hello+64, pubkey, 32);

	unsigned char boxed_auth[112];
	rc = crypto_secretbox_easy(boxed_auth, hello, sizeof(hello), zeros, secret2);
	if (rc < 0) errx(1, "failed to box hello");

	rc = write_all(outfd, boxed_auth, sizeof(boxed_auth));
	if (rc < 0) errx(1, "failed to send auth");

	// verify accept

	unsigned char boxed_okay[80];
	rc = read_all(infd, boxed_okay, sizeof(boxed_okay));
	if (rc < 0) err(1, "hello not accepted");

	unsigned char local_sk_curve[32];
	rc = crypto_sign_ed25519_sk_to_curve25519(local_sk_curve, seckey);
	if (rc < 0) errx(1, "failed to curvify local secret key");

	unsigned char b_alice[32];
	rc = crypto_scalarmult(b_alice, local_sk_curve, remote_kx_pk);
	if (rc < 0) errx(1, "failed to derive b_alice");

	unsigned char secret3a[128];
	memcpy(secret3a, appkey, 32);
	memcpy(secret3a+32, secret, 32);
	memcpy(secret3a+64, a_bob, 32);
	memcpy(secret3a+96, b_alice, 32);

	unsigned char secret3[32];
	rc = crypto_hash_sha256(secret3, secret3a, sizeof(secret3a));
	if (rc < 0) errx(1, "failed to hash secret3");

	rc = crypto_secretbox_open_easy(sig, boxed_okay, sizeof(boxed_okay), zeros, secret3);
	if (rc < 0) errx(1, "failed to unbox the okay");

	unsigned char signed2[160];
	memcpy(signed2, appkey, 32);
	memcpy(signed2+32, hello, 96);
	memcpy(signed2+128, shash, 32);

	rc = crypto_sign_verify_detached(sig, signed2, sizeof(signed2), server_pubkey);
	if (rc < 0) errx(1, "server not authenticated");

	rc = crypto_hash_sha256(secret, secret3, 32);
	if (rc < 0) errx(1, "failed to hash secret3");

	unsigned char enc_key_hashed[64];
	memcpy(enc_key_hashed, secret, 32);
	memcpy(enc_key_hashed+32, server_pubkey, 32);
	rc = crypto_hash_sha256(bs->encrypt_key, enc_key_hashed, 64);
	if (rc < 0) errx(1, "failed to hash the encrypt key");

	unsigned char dec_key_hashed[64];
	memcpy(dec_key_hashed, secret, 32);
	memcpy(dec_key_hashed+32, pubkey, 32);
	rc = crypto_hash_sha256(bs->decrypt_key, dec_key_hashed, 64);
	if (rc < 0) errx(1, "failed to hash the decrypt key");

	memcpy(bs->nonce1, remote_app_mac, 24);
	memcpy(bs->nonce2, remote_app_mac, 24);
	memcpy(bs->rx_nonce, local_app_mac, 24);

	bs->rx_buf_pos = 0;
	bs->rx_buf_len = 0;
	bs->s = sfd;
	bs->noauth = false;
	bs->wrote_goodbye = false;
}

static int pubkey_decode(const char *key_str, unsigned char key[32]) {
	if (!key_str) { errno = EPROTO; return -1; }
	if (!*key_str) { errno = EPROTO; return -1; }
	if (*key_str == '@') key_str++;
	size_t len = strlen(key_str);
	if (len == 52 && strcmp(key_str+44, ".ed25519") == 0) {}
	else if (len != 44) { errno = EMSGSIZE; return -1; }
	return base64_decode(key_str, 44, key, 32);
}

static jsmntok_t *json_lookup(const char *buf, jsmntok_t *tok, const char *prop, size_t prop_len) {
	jsmntok_t *end = tok + tok->size + 1;
	if (tok->type != JSMN_OBJECT) { errno = EPROTO; return NULL; }
	tok++;
	while (tok < end) {
		if (tok + 1 >= end) { errno = EPROTO; return NULL; }
		if (tok->type == JSMN_STRING
		    && tok->end - tok->start == (int)prop_len
		    && memcmp(buf + tok->start, prop, prop_len) == 0)
			return tok + 1;
		tok += tok->size + 1;
		end += tok->size;
	}
	return NULL;
}

static ssize_t json_get_value(const char *buf, const char *path, const char **value) {
	static const int num_tokens = 1024;
	jsmntok_t tokens[num_tokens], *tok = tokens;
	jsmn_parser parser;

	jsmn_init(&parser);
	switch (jsmn_parse(&parser, buf, tokens, num_tokens)) {
		case JSMN_ERROR_NOMEM: errno = ENOMEM; return -1;
		case JSMN_ERROR_INVAL: errno = EINVAL; return -1;
		case JSMN_ERROR_PART: errno = EMSGSIZE; return -1;
		case JSMN_SUCCESS: break;
		default: errno = EPROTO; return -1;
	}

	while (*path) {
		const char *end = strchr(path, '.');
		size_t part_len = end ? (size_t)end - (size_t)path : strlen(path);
		tok = json_lookup(buf, tok, path, part_len);
		if (!tok) { errno = ENOMSG; return -1; }
		path += part_len;
		if (*path == '.') path++;
	}

	*value = buf + tok->start;
	return tok->end - tok->start;
}

static void get_app_dir(char *dir, size_t len) {
	const char *path, *home, *appname;
	int rc;
	path = getenv("ssb_path");
	if (path) {
		if (strlen(path) > len) errx(1, "ssb_path too long");
		strncpy(dir, path, len);
		return;
	}
	home = getenv("HOME");
	if (!home) home = ".";
	appname = getenv("ssb_appname");
	if (!appname) appname = "ssb";
	rc = snprintf(dir, len, "%s/.%s", home, appname);
	if (rc < 0) err(1, "failed to get app dir");
	if ((size_t)rc >= len) errx(1, "path to app dir too long");
}

static ssize_t read_file(char *buf, size_t len, const char *fmt, ...) {
	va_list ap;
	int rc;
	struct stat st;
	int fd;

	va_start(ap, fmt);
	rc = vsnprintf(buf, len, fmt, ap);
	va_end(ap);
	if (rc < 0) return -1;
	if ((size_t)rc >= len) { errno = ENAMETOOLONG; return -1; }

	rc = stat(buf, &st);
	if (rc < 0) return -1;
	if (st.st_size > (off_t)(len-1)) { errno = EMSGSIZE; return -1; }

	fd = open(buf, O_RDONLY);
	if (fd < 0) return -1;

	rc = read_all(fd, buf, st.st_size);
	if (rc < 0) return -1;
	buf[st.st_size] = '\0';

	close(fd);
	return st.st_size;
}


static void read_private_key(const char *dir, unsigned char pk[64]) {
	ssize_t len;
	char buf[8192];
	const char *pk_b64;
	int rc;
	ssize_t key_len;
	char *line;

	len = read_file(buf, sizeof(buf), "%s/secret", dir);
	if (len < 0) err(1, "failed to read secret file");

	// strip comments
	for (line = buf; *line; ) {
		if (*line == '#') while (*line && *line != '\n') *line++ = ' ';
		else while (*line && *line++ != '\n');
	}

	key_len = json_get_value(buf, "private", &pk_b64);
	if (key_len < 0) err(1, "unable to read private key");

	if (key_len > 8 && memcmp(pk_b64 + key_len - 8, ".ed25519", 8) == 0)
		key_len -= 8;
	rc = base64_decode(pk_b64, key_len, pk, 64);
	if (rc < 0) err(1, "unable to decode private key");
}

static void increment_nonce(uint8_t nonce[24]) {
	int i;
	for (i = 23; i >= 0 && nonce[i] == 0xff; i--) nonce[i] = 0;
	if (i >= 0) nonce[i]++;
}

static void bs_write_end_box(struct boxs *bs) {
	unsigned char boxed[34];
	int rc = crypto_secretbox_easy(boxed, zeros, 18, bs->nonce1, bs->encrypt_key);
	if (rc < 0) errx(1, "failed to box packet end header");
	increment_nonce(bs->nonce1);
	increment_nonce(bs->nonce2);
	rc = write_all(bs->s, boxed, 34);
	if (rc < 0) err(1, "failed to write boxed end header");
}

static void bs_write_packet(struct boxs *bs, const unsigned char *buf, uint16_t len) {
	size_t boxed_len = len + 34;
	unsigned char boxed[boxed_len];
	increment_nonce(bs->nonce2);
	int rc = crypto_secretbox_easy(boxed + 18, buf, len, bs->nonce2, bs->encrypt_key);
	if (rc < 0) errx(1, "failed to box packet data");
	struct boxs_header header;
	header.len = htons(len);
	memcpy(header.mac, boxed + 18, 16);
	rc = crypto_secretbox_easy(boxed, (unsigned char *)&header, 18, bs->nonce1, bs->encrypt_key);
	if (rc < 0) errx(1, "failed to box packet header");
	increment_nonce(bs->nonce1);
	increment_nonce(bs->nonce1);
	increment_nonce(bs->nonce2);
	rc = write_all(bs->s, boxed, boxed_len);
	if (rc < 0) err(1, "failed to write boxed packet");
}

static void bs_end(struct boxs *bs) {
	if (!bs->noauth) {
		bs_write_end_box(bs);
	}
	shutdown(bs->s, SHUT_WR);
}

static int bs_read_packet(struct boxs *bs, void *buf, size_t *lenp) {
	int rc;
	if (bs->noauth) {
		rc = read_some(bs->s, buf, lenp);
		if (rc < 0 && errno == EPIPE) return -1;
		if (rc < 0) err(1, "failed to read packet data");
		return 0;
	}
	unsigned char boxed_header[34];
	struct boxs_header header;
	rc = read_all(bs->s, boxed_header, 34);
	if (rc < 0 && errno == EPIPE) errx(1, "unexpected end of parent stream");
	if (rc < 0) err(1, "failed to read boxed packet header");
	rc = crypto_secretbox_open_easy((unsigned char *)&header, boxed_header, 34, bs->rx_nonce, bs->decrypt_key);
	if (rc < 0) errx(1, "failed to unbox packet header");
	increment_nonce(bs->rx_nonce);
	if (header.len == 0 && !memcmp(header.mac, zeros, 16)) { errno = EPIPE; return -1; }
	size_t len = ntohs(header.len);
	if (len > BOXS_MAXLEN) errx(1, "received boxed packet too large");
	unsigned char boxed_data[len + 16];
	rc = read_all(bs->s, boxed_data + 16, len);
	if (rc < 0) err(1, "failed to read boxed packet data");
	memcpy(boxed_data, header.mac, 16);
	rc = crypto_secretbox_open_easy(buf, boxed_data, len+16, bs->rx_nonce, bs->decrypt_key);
	if (rc < 0) errx(1, "failed to unbox packet data");
	increment_nonce(bs->rx_nonce);
	*lenp = len;
	return 0;
}

static int bs_read(struct boxs *bs, char *buf, size_t len) {
	if (bs->noauth) {
		int rc = read_all(bs->s, buf, len);
		if (rc < 0) err(1, "failed to read packet data");
		return 0;
	}
	size_t remaining;
	while (len > 0) {
		remaining = bs->rx_buf_len > len ? len : bs->rx_buf_len;
		if (buf) memcpy(buf, bs->rx_buf + bs->rx_buf_pos, remaining);
		bs->rx_buf_len -= remaining;
		bs->rx_buf_pos += remaining;
		len -= remaining;
		buf += remaining;
		if (len == 0) return 0;
		if (bs_read_packet(bs, bs->rx_buf, &bs->rx_buf_len) < 0) return -1;
		bs->rx_buf_pos = 0;
	}
	return 0;
}

static enum stream_state bs_read_out_1(struct boxs *bs, int fd) {
	size_t buf[4096];
	size_t len = sizeof(buf);
	int rc;
	rc = bs_read_packet(bs, buf, &len);
	if (rc < 0 && errno == EPIPE) return stream_state_ended_ok;
	if (rc < 0) return stream_state_ended_error;
	rc = write_all(fd, buf, len);
	if (rc < 0) return stream_state_ended_error;
	return stream_state_open;
}

static int bs_read_out(struct boxs *bs, int fd, size_t len) {
	size_t chunk;
	char buf[4096];
	int rc;
	while (len > 0) {
		chunk = len > sizeof(buf) ? sizeof(buf) : len;
		rc = bs_read(bs, buf, chunk);
		if (rc < 0) return -1;
		rc = write_all(fd, buf, chunk);
		if (rc < 0) return -1;
		len -= chunk;
	}
	return 0;
}

static int bs_read_error(struct boxs *bs, int errfd, enum pkt_flags flags, size_t len, bool no_newline) {
	// suppress printing "true" indicating end without error
	if (flags & pkt_flags_json && len == 4) {
		char buf[4];
		if (bs_read(bs, buf, 4) < 0) return -1;
		if (strncmp(buf, "true", 4) == 0) {
			return 0;
		}
		if (write_all(errfd, buf, 4) < 0) return -1;
	} else {
		if (bs_read_out(bs, errfd, len) < 0) return -1;
	}
	if (flags & (pkt_flags_json | pkt_flags_string) && !no_newline) {
		if (write_buf(errfd, "\n") < 0) return -1;
	}
	return 1;
}

static void bs_write(struct boxs *bs, const unsigned char *buf, size_t len) {
	if (bs->noauth) {
		int rc = write_all(bs->s, buf, len);
		if (rc < 0) err(1, "failed to write packet");
		return;
	}
	while (len > 0) {
		size_t l = len > BOXS_MAXLEN ? BOXS_MAXLEN : len;
		bs_write_packet(bs, buf, l);
		len -= l;
		buf += l;
	}
}

static enum stream_state bs_write_in_1(struct boxs *bs, int fd) {
	unsigned char buf[4096];
	ssize_t sz = read(fd, buf, sizeof(buf));
	if (sz < 0) err(1, "read");
	if (sz == 0) {
		bs_end(bs);
		return stream_state_ended_ok;
	}
	bs_write(bs, buf, sz);
	return stream_state_open;
}

static void ps_write(struct boxs *bs, const char *data, size_t len, enum pkt_type type, int req_id, bool stream, bool end) {
	size_t out_len = 9 + len;
	unsigned char out_buf[out_len];
	struct pkt_header header = {htonl(len), htonl(req_id)};
	out_buf[0] = (stream << 3) | (end << 2) | (type & 3);
	memcpy(out_buf+1, &header, 8);
	memcpy(out_buf+9, data, len);
	bs_write(bs, out_buf, out_len);
}

static void ps_goodbye(struct boxs *bs) {
	if (bs->wrote_goodbye) return;
	bs->wrote_goodbye = true;
	bs_write(bs, zeros, 9);
}

static int ps_read_header(struct boxs *bs, size_t *len, int *req_id, enum pkt_flags *flags) {
	char buf[9];
	struct pkt_header header;
	if (bs_read(bs, buf, sizeof(buf)) < 0) return -1;
	memcpy(&header, buf+1, 8);
	if (len) *len = ntohl(header.len);
	if (req_id) *req_id = ntohl(header.req);
	if (flags) *flags = buf[0];
	return 0;
}

static void muxrpc_call(struct boxs *bs, const char *method, const char *argument, enum muxrpc_type type, const char *typestr, int req_id) {
	char req[33792]; // 32768 max message value size + 1024 extra
	ssize_t reqlen;
	bool is_request = type == muxrpc_type_async;

	if (is_request) {
		reqlen = snprintf(req, sizeof(req),
				  "{\"name\":%s,\"args\":%s}",
				  method, argument);
	} else {
		reqlen = snprintf(req, sizeof(req),
				  "{\"name\":%s,\"args\":%s,\"type\":\"%s\"}",
				  method, argument, typestr);
	}
	if (reqlen < 0) err(1, "failed to construct request");
	if ((size_t)reqlen >= sizeof(req)) errx(1, "request too large");

	ps_write(bs, req, reqlen, pkt_type_json, req_id, !is_request, false);
}

static int bs_passthrough(struct boxs *bs, int infd, int outfd) {
	int rc;
	fd_set rd;
	int sfd = bs->s;
	int maxfd = infd > sfd ? infd : sfd;
	enum stream_state in = stream_state_open;
	enum stream_state out = stream_state_open;

	while (out == stream_state_open) {
		FD_ZERO(&rd);
		if (in == stream_state_open) FD_SET(infd, &rd);
		if (out == stream_state_open) FD_SET(sfd, &rd);
		rc = select(maxfd + 1, &rd, 0, 0, NULL);
		if (rc < 0) err(1, "select");
		if (FD_ISSET(infd, &rd)) in = bs_write_in_1(bs, infd);
		if (FD_ISSET(sfd, &rd)) out = bs_read_out_1(bs, outfd);
	}

	return in == stream_state_ended_ok && out == stream_state_ended_ok ? 0 :
	  in == stream_state_ended_error || out == stream_state_ended_error ? 2 : 1;
}

static void ps_reject(struct boxs *bs, size_t len, int32_t req, enum pkt_flags flags) {
	// ignore the packet. if this is a request, the substream on the other end
	// will just have to wait until the rpc connection closes.
	(void)req;
	(void)flags;
	write_buf(STDERR_FILENO, "ignoring packet: ");
	int rc = bs_read_out(bs, STDERR_FILENO, len);
	if (rc < 0) err(1, "bs_read_out");
	write_buf(STDERR_FILENO, "\n");
}

static enum stream_state muxrpc_read_source_1(struct boxs *bs, int outfd, int req_id, bool no_newline) {
	enum pkt_flags flags;
	size_t len;
	int32_t req;
	int rc = ps_read_header(bs, &len, &req, &flags);
	if (rc < 0) err(1, "ps_read_header");
	if (req == 0 && len == 0) {
		if (bs->wrote_goodbye) return stream_state_ended_ok;
		warnx("unexpected end of parent stream");
		return stream_state_ended_error;
	}
	if (req != -req_id) {
		ps_reject(bs, len, req, flags);
		return stream_state_open;
	}
	if (flags & pkt_flags_end) {
		rc = bs_read_error(bs, STDERR_FILENO, flags, len, no_newline);
		if (rc < 0) err(1, "bs_read_error");
		if (rc == 1) return stream_state_ended_error;
		return stream_state_ended_ok;
	}
	rc = bs_read_out(bs, outfd, len);
	if (rc < 0) err(1, "bs_read_out");
	if (flags & (pkt_flags_json | pkt_flags_string) && !no_newline) {
		rc = write_buf(outfd, "\n");
		if (rc < 0) err(1, "write_buf");
	}
	return stream_state_open;
}

static int muxrpc_read_source(struct boxs *bs, int outfd, int req_id, bool no_newline) {
	enum stream_state state;
	while ((state = muxrpc_read_source_1(bs, outfd, req_id, no_newline)) == stream_state_open);
	return state == stream_state_ended_ok ? 0 :
		state == stream_state_ended_error ? 2 : 1;
}

static int muxrpc_read_async(struct boxs *bs, int outfd, int req_id, bool no_newline) {
	enum pkt_flags flags;
	size_t len;
	int32_t req;
	int rc;

	while (1) {
		rc = ps_read_header(bs, &len, &req, &flags);
		if (rc < 0) err(1, "ps_read_header");
		if (req == -req_id) break;
		if (req == 0 && len == 0) errx(1, "unexpected end of parent stream");
		ps_reject(bs, len, req, flags);
	}
	if (flags & pkt_flags_end) {
		rc = bs_read_error(bs, STDERR_FILENO, flags, len, no_newline);
		if (rc < 0) err(1, "bs_read_error");
		if (rc == 1) return 2;
		return 1;
	}
	rc = bs_read_out(bs, outfd, len);
	if (rc < 0) err(1, "bs_read_out");
	if (flags & (pkt_flags_json | pkt_flags_string) && !no_newline) {
		rc = write_buf(outfd, "\n");
		if (rc < 0) err(1, "write_buf");
	}
	return 0;
}

static enum stream_state muxrpc_write_sink_1(struct boxs *bs, int infd,
		enum pkt_type ptype, int req_id) {
	char buf[4096];
	ssize_t sz = read(infd, buf, sizeof(buf));
	if (sz < 0) err(1, "read");
	if (sz == 0) {
		ps_write(bs, "true", 4, pkt_type_json, req_id, true, true);
		return stream_state_ended_ok;
	}
	ps_write(bs, buf, sz, ptype, req_id, true, false);
	return stream_state_open;
}

static enum stream_state muxrpc_write_sink_1_hashed(struct boxs *bs, int infd,
		crypto_hash_sha256_state *hash_state, int req_id) {
	int rc;
	unsigned char buf[4096];
	ssize_t sz = read(infd, buf, sizeof(buf));
	if (sz < 0) err(1, "read");
	if (sz == 0) {
		ps_write(bs, "true", 4, pkt_type_json, req_id, true, true);
		return stream_state_ended_ok;
	}
	rc = crypto_hash_sha256_update(hash_state, buf, sz);
	if (rc < 0) errx(1, "hash update failed");
	ps_write(bs, (char *)buf, sz, pkt_type_buffer, req_id, true, false);
	return stream_state_open;
}

static int muxrpc_write_sink(struct boxs *bs, int infd, enum pkt_type ptype, int req_id, bool no_newline) {
	int rc;
	fd_set rd;
	int sfd = bs->s;
	int maxfd = infd > sfd ? infd : sfd;
	enum stream_state in = stream_state_open;
	enum stream_state out = stream_state_open;

	while (out == stream_state_open) {
		FD_ZERO(&rd);
		if (in == stream_state_open) FD_SET(infd, &rd);
		if (out == stream_state_open) FD_SET(sfd, &rd);
		rc = select(maxfd + 1, &rd, 0, 0, NULL);
		if (rc < 0) err(1, "select");
		if (FD_ISSET(infd, &rd)) in = muxrpc_write_sink_1(bs, infd, ptype, req_id);
		if (FD_ISSET(sfd, &rd)) out = muxrpc_read_source_1(bs, -1, req_id, no_newline);
	}

	return in == stream_state_ended_ok && out == stream_state_ended_ok ? 0 :
	  in == stream_state_ended_error || out == stream_state_ended_error ? 2 : 1;
}

static int muxrpc_write_blob_add(struct boxs *bs, int infd, int outfd, int req_id, bool no_newline) {
	int rc;
	fd_set rd;
	int sfd = bs->s;
	int maxfd = infd > sfd ? infd : sfd;
	enum stream_state in = stream_state_open;
	enum stream_state out = stream_state_open;
	crypto_hash_sha256_state hash_state;
	unsigned char hash[32];
	char id[54] = "&";

	rc = crypto_hash_sha256_init(&hash_state);
	if (rc < 0) { errno = EINVAL; return -1; }

	while (out == stream_state_open) {
		FD_ZERO(&rd);
		if (in == stream_state_open) FD_SET(infd, &rd);
		if (out == stream_state_open) FD_SET(sfd, &rd);
		rc = select(maxfd + 1, &rd, 0, 0, NULL);
		if (rc < 0) err(1, "select");
		if (FD_ISSET(infd, &rd)) in = muxrpc_write_sink_1_hashed(bs, infd, &hash_state, req_id);
		if (FD_ISSET(sfd, &rd)) out = muxrpc_read_source_1(bs, -1, req_id, no_newline);
	}

	rc = crypto_hash_sha256_final(&hash_state, hash);
	if (rc < 0) errx(1, "hash finalize failed");

	rc = base64_encode(hash, 32, id+1, sizeof(id)-1);
	if (rc < 0) err(1, "encoding hash failed");
	strcpy(id + 45, ".sha256\n");
	rc = write_all(outfd, id, sizeof(id)-1);
	if (rc < 0) err(1, "writing hash failed");

	return in == stream_state_ended_ok && out == stream_state_ended_ok ? 0 :
	  in == stream_state_ended_error || out == stream_state_ended_error ? 2 : 1;
}

static int muxrpc_duplex(struct boxs *bs, int infd, int outfd, enum pkt_type in_ptype, int req_id, bool no_newline) {
	int rc;
	fd_set rd;
	int sfd = bs->s;
	int maxfd = infd > sfd ? infd : sfd;
	enum stream_state in = stream_state_open;
	enum stream_state out = stream_state_open;

	while (out == stream_state_open) {
		FD_ZERO(&rd);
		if (in == stream_state_open) FD_SET(infd, &rd);
		if (out == stream_state_open) FD_SET(sfd, &rd);
		rc = select(maxfd + 1, &rd, 0, 0, NULL);
		if (rc < 0) err(1, "select");
		if (FD_ISSET(infd, &rd)) in = muxrpc_write_sink_1(bs, infd, in_ptype, req_id);
		if (FD_ISSET(sfd, &rd)) out = muxrpc_read_source_1(bs, outfd, req_id, no_newline);
	}

	return in == stream_state_ended_ok && out == stream_state_ended_ok ? 0 :
	  in == stream_state_ended_error || out == stream_state_ended_error ? 2 : 1;
}

static int method_to_json(char *out, size_t outlen, const char *str) {
	// blobs.get => ["blobs", "get"]
	size_t i = 0;
	char c;
	if (i+2 > outlen) return -1;
	out[i++] = '[';
	out[i++] = '"';
	while ((c = *str++)) {
		if (c == '.') {
			if (i+3 > outlen) return -1;
			out[i++] = '"';
			out[i++] = ',';
			out[i++] = '"';
		} else if (c == '"') {
			if (i+2 > outlen) return -1;
			out[i++] = '\\';
			out[i++] = '"';
		} else {
			if (i+1 > outlen) return -1;
			out[i++] = c;
		}
	}
	if (i+3 > outlen) return -1;
	out[i++] = '"';
	out[i++] = ']';
	out[i++] = '\0';
	return i;
}

static int args_to_json_length(int argc, char *argv[], bool encode_strings) {
	int i = 0;
	int len = 3; // "[]\0"
	for (i = 0; i < argc; i++) {
		if (!encode_strings) {
			len += strlen(argv[i])+1;
		} else {
			len += 3; // "\"\","
			char *arg = argv[i], c;
			while ((c = *arg++)) switch (c) {
				case '"': len += 2; break;
				case '\\': len += 2; break;
				default: len++;
			}
		}
	}
	return len;
}

static int args_to_json(char *out, size_t outlen, unsigned int argc, char *argv[], bool encode_strings) {
	size_t i = 0;
	size_t j;
	if (i+1 > outlen) return -1;
	out[i++] = '[';
	for (j = 0; j < argc; j++) {
		if (!encode_strings) {
			size_t len = strlen(argv[j]);
			if (j > 0) out[i++] = ',';
			if (i+len > outlen) return -1;
			strncpy(out+i, argv[j], len);
			i += len;
		} else {
			char *arg = argv[j];
			char c;
			if (j > 0) {
				if (i+1 > outlen) return -1;
				out[i++] = ',';
			}
			if (i+1 > outlen) return -1;
			out[i++] = '"';
			while ((c = *arg++)) {
				if (i+2 > outlen) return -1;
				if (c == '"' || c == '\\') out[i++] = '\\';
				out[i++] = c;
			}
			if (i+1 > outlen) return -1;
			out[i++] = '"';
		}
	}
	if (i+2 > outlen) return -1;
	out[i++] = ']';
	out[i++] = '\0';
	return i;
}

int main(int argc, char *argv[]) {
	int i, s, infd, outfd, rc;
	const char *key = NULL;
	const char *keypair_seed_str = NULL;
	const char *host = NULL;
	const char *port = "8008";
	const char *typestr = NULL, *methodstr = NULL;
	const char *shs_cap_key_str = NULL;
	const char *socket_path = NULL;
	size_t argument_len;
	unsigned char private_key[64];
	unsigned char public_key[32];
	unsigned char remote_key[32];
	unsigned char shs_cap_key[32];
	enum muxrpc_type type;
	enum pkt_type ptype = pkt_type_buffer;
	char method[256];
	char app_dir[_POSIX_PATH_MAX];
	ssize_t len;
	bool test = false;
	bool noauth = false;
	bool no_newline = false;
	bool raw = false;
	bool host_arg = false;
	bool port_arg = false;
	bool key_arg = false;
	bool shs_cap_key_str_arg = false;
	bool ipv4_arg = false;
	bool ipv6_arg = false;
	bool passthrough = false;
	bool strings = false;
	enum ip_family ip_family;

	get_app_dir(app_dir, sizeof(app_dir));

	char config_buf[8192];
	len = read_file(config_buf, sizeof(config_buf), "%s/config", app_dir);
	if (len > 0) {
		ssize_t key_len = json_get_value(config_buf, "key", &key);
		ssize_t host_len = json_get_value(config_buf, "host", &host);
		ssize_t port_len = json_get_value(config_buf, "port", &port);
		ssize_t shs_cap_len = json_get_value(config_buf, "caps.shs", &shs_cap_key_str);
		if (key_len >= 0) ((char *)key)[key_len] = '\0';
		if (host_len >= 0) ((char *)host)[host_len] = '\0';
		if (port_len >= 0) ((char *)port)[port_len] = '\0';
		if (shs_cap_len >= 0) ((char *)shs_cap_key_str)[shs_cap_len] = '\0';
	} else if (len < 0 && errno != ENOENT) {
		 err(1, "failed to read config");
	}

	for (i = 1; i < argc && (argv[i][0] == '-'); i++) {
		switch (argv[i][1]) {
			case 'c': shs_cap_key_str = argv[++i]; shs_cap_key_str_arg = true; break;
			case 'j': ptype = pkt_type_json; break;
			case 'T': test = true; break;
			case 's': host = argv[++i]; host_arg = true; break;
			case 'k': key = argv[++i]; key_arg = true; break;
			case 'K': keypair_seed_str = argv[++i]; break;
			case 'p': port = argv[++i]; port_arg = true; break;
			case 'u': socket_path = argv[++i]; break;
			case 't': typestr = argv[++i]; break;
			case 'n': noauth = true; break;
			case '4': ipv4_arg = true; break;
			case '6': ipv6_arg = true; break;
			case 'a': passthrough = true; break;
			case 'l': no_newline = true; break;
			case 'r': raw = true; no_newline = true; break;
			case 'e': strings = true; break;
			default: usage();
		}
	}
	if (i < argc) methodstr = argv[i++];
	else if (!test && !passthrough) usage();

	if (ipv4_arg && ipv6_arg) errx(1, "options -4 and -6 conflict");
	ip_family =
		ipv4_arg ? ip_family_ipv4 :
		ipv6_arg ? ip_family_ipv6 :
		ip_family_any;

	if (shs_cap_key_str) {
		rc = pubkey_decode(shs_cap_key_str, shs_cap_key);
		if (rc < 0) err(1, "unable to decode cap key '%s'", shs_cap_key_str);
	} else {
		memcpy(shs_cap_key, ssb_cap, 32);
	}

	argument_len = test ? 0 : args_to_json_length(argc-i, argv+i, strings);
	char argument[argument_len];

	if (passthrough) {
		if (methodstr) errx(1, "-a option conflicts with method");
		if (typestr) errx(1, "-a option conflicts with -t option");
		if (argc-i > 0) errx(1, "-a option conflicts with method arguments");
		if (test) errx(1, "-a option conflicts with -T test");

	} else if (!test) {
		rc = args_to_json(argument, sizeof(argument), argc-i, argv+i, strings);
		if (rc < 0) errx(1, "unable to collect arguments");

		char manifest_buf[8192];
		if (!typestr) {
			len = read_file(manifest_buf, sizeof(manifest_buf),
				"%s/manifest.json", app_dir);
			if (len < 0) err(1, "failed to read manifest file");

			ssize_t type_len = json_get_value(manifest_buf, methodstr, &typestr);
			if (!typestr && errno == ENOMSG) errx(1,
				"unable to find method '%s' in manifest", methodstr);
			if (!typestr) err(1, "unable to read manifest %s/%s", manifest_buf, methodstr);
			((char *)typestr)[type_len] = '\0';
		}
		if (strcmp(typestr, "sync") == 0) type = muxrpc_type_async;
		else if (strcmp(typestr, "async") == 0) type = muxrpc_type_async;
		else if (strcmp(typestr, "sink") == 0) type = muxrpc_type_sink;
		else if (strcmp(typestr, "source") == 0) type = muxrpc_type_source;
		else if (strcmp(typestr, "duplex") == 0) type = muxrpc_type_duplex;
		else errx(1, "type must be one of <async|sink|source|duplex>");

		rc = method_to_json(method, sizeof(method), methodstr);
		if (rc < 0) errx(0, "unable to convert method name");
	}

	if (keypair_seed_str) {
		unsigned char seed[crypto_sign_SEEDBYTES];
		unsigned char ed25519_skpk[crypto_sign_ed25519_SECRETKEYBYTES];

		rc = pubkey_decode(keypair_seed_str, ed25519_skpk);
		if (rc < 0) err(1, "unable to decode private key");
		rc = crypto_sign_ed25519_sk_to_seed(seed, ed25519_skpk);
		if (rc < 0) err(1, "unable to convert private key to seed");
		rc = crypto_sign_seed_keypair(public_key, private_key, seed);
		if (rc < 0) err(1, "unable to generate keypair from seed");
	} else {
		read_private_key(app_dir, private_key);
		memcpy(public_key, private_key+32, 32);
	}

	if (key) {
		rc = pubkey_decode(key, remote_key);
		if (rc < 0) err(1, "unable to decode remote key '%s'", key);
	} else {
		memcpy(remote_key, public_key, 32);
	}

	bool implied_tcp = host_arg || port_arg || ipv4_arg || ipv6_arg;
	bool implied_auth = key_arg || keypair_seed_str || shs_cap_key_str_arg || test;

	if (test) {
		infd = STDIN_FILENO;
		outfd = STDOUT_FILENO;
		s = -1;

	} else if (socket_path) {
		if (implied_tcp) errx(1, "-u option conflicts with -s and -p options");
		s = unix_connect(socket_path);
		if (s < 0) err(1, "unix_connect");
		infd = outfd = s;

	} else if (!implied_tcp && !implied_auth) {
		char socket_path_buf[_POSIX_PATH_MAX];
		rc = get_socket_path(socket_path_buf, sizeof(socket_path_buf), app_dir);
		if (rc < 0 && noauth) err(1, "get_socket_path");
		if (rc < 0) goto do_tcp_connect;
		s = unix_connect(socket_path_buf);
		if (s < 0 && noauth) err(1, "unix_connect");
		if (s < 0) goto do_tcp_connect;
		noauth = true;
		infd = outfd = s;

	} else {
do_tcp_connect:
		s = tcp_connect(host, port, ip_family);
		if (s < 0) err(1, "tcp_connect");
		infd = outfd = s;
	}

	struct boxs bs;
	if (noauth) {
		bs.s = s;
		bs.noauth = true;
		if (implied_auth) errx(1, "-n option conflicts with -k, -K, -c and -T options.");
	} else {
		shs_connect(s, infd, outfd, public_key, private_key, shs_cap_key, remote_key, &bs);
	}

	if (test) {
		rc = write_all(outfd, bs.encrypt_key, sizeof(bs.encrypt_key));
		rc |= write_all(outfd, bs.nonce1, sizeof(bs.nonce1));
		rc |= write_all(outfd, bs.decrypt_key, sizeof(bs.decrypt_key));
		rc |= write_all(outfd, bs.rx_nonce, sizeof(bs.rx_nonce));
		if (rc < 0) err(1, "failed to write handshake result");
		return 0;
	}

	if (passthrough) {
		rc = bs_passthrough(&bs, STDIN_FILENO, STDOUT_FILENO);
		close(s);
		return rc;
	}

	muxrpc_call(&bs, method, argument, type, typestr, 1);

	if (raw) {
		struct termios raw_tc;
		rc = tcgetattr(STDIN_FILENO, &orig_tc);
		if (rc < 0) warn("tcgetattr");
		raw_tc = orig_tc;
		raw_tc.c_lflag &= ~(ICANON | ECHO);
		rc = tcsetattr(STDIN_FILENO, TCSANOW, &raw_tc);
		if (rc < 0) warn("tcgetattr");
		rc = atexit(reset_termios);
		if (rc < 0) warn("atexit");
	}

	switch (type) {
		case muxrpc_type_async:
			rc = muxrpc_read_async(&bs, STDOUT_FILENO, 1, no_newline);
			break;
		case muxrpc_type_source:
			rc = muxrpc_read_source(&bs, STDOUT_FILENO, 1, no_newline);
			break;
		case muxrpc_type_sink:
			if (!strcmp(methodstr, "blobs.add")) {
				rc = muxrpc_write_blob_add(&bs, STDIN_FILENO, STDOUT_FILENO, 1, no_newline);
			} else {
				rc = muxrpc_write_sink(&bs, STDIN_FILENO, ptype, 1, no_newline);
			}
			break;
		case muxrpc_type_duplex:
			rc = muxrpc_duplex(&bs, STDIN_FILENO, STDOUT_FILENO, ptype, 1, no_newline);
			break;
	}

	ps_goodbye(&bs);
	bs_end(&bs);
	close(s);
	return rc;
}
