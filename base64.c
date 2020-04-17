/*

	This code is public domain software.

*/

#include "base64.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>


//  single base64 character conversion
//
static int POS(char c)
{
	if (c>='A' && c<='Z') return c - 'A';
	if (c>='a' && c<='z') return c - 'a' + 26;
	if (c>='0' && c<='9') return c - '0' + 52;
	if (c == '+') return 62;
	if (c == '/') return 63;
	if (c == '=') return -1;
	return -2;
}

//  base64 decoding
//
//  s:	     base64 string
//  str_len  size of the base64 string
//  data:    output buffer for decoded data
//  data_len expected size of decoded data
//  return:  0 on success, -1 on failure
//
int base64_decode(const char* s, size_t str_len, void *data, size_t data_len)
{
	const char *p, *str_end;
	unsigned char *q, *end;
	int n[4] = { 0, 0, 0, 0 };

	if (str_len % 4) { errno = EBADMSG; return -1; }
	q = (unsigned char*) data;
	end = q + data_len;
	str_end = s + str_len;

	for (p = s; p < str_end; ) {
		n[0] = POS(*p++);
		n[1] = POS(*p++);
		n[2] = POS(*p++);
		n[3] = POS(*p++);

		if (n[0] == -2 || n[1] == -2 || n[2] == -2 || n[3] == -2)
			{ errno = EBADMSG; return -1; }

		if (n[0] == -1 || n[1] == -1)
			{ errno = EBADMSG; return -1; }

		if (n[2] == -1 && n[3] != -1)
			{ errno = EBADMSG; return -1; }

		if (q >= end) { errno = EMSGSIZE; return -1; }
		q[0] = (n[0] << 2) + (n[1] >> 4);
		if (n[2] != -1) {
			if (q+1 >= end) { errno = EMSGSIZE; return -1; }
			q[1] = ((n[1] & 15) << 4) + (n[2] >> 2);
		}
		if (n[3] != -1) {
			if (q+2 >= end) { errno = EMSGSIZE; return -1; }
			q[2] = ((n[2] & 3) << 6) + n[3];
		}
		q += 3;
	}

	return 0;
}

int base64_encode(const void* buf, size_t size, char *str, size_t out_size) {
	static const char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	char* p = str;
	const unsigned char* q = (const unsigned char*) buf;
	size_t i = 0;

	if ((size+3)*4/3 + 1 > out_size) {
		errno = EMSGSIZE;
		return -1;
	}

	while (i < size) {
		int c = q[i++];
		c *= 256;
		if (i < size)
            c += q[i];
		i++;

		c *= 256;
		if (i < size)
            c += q[i];
		i++;

		*p++ = base64[(c & 0x00fc0000) >> 18];
		*p++ = base64[(c & 0x0003f000) >> 12];

		if (i > size + 1)
			*p++ = '=';
		else
			*p++ = base64[(c & 0x00000fc0) >> 6];

		if (i > size)
			*p++ = '=';
		else
			*p++ = base64[c & 0x0000003f];
	}

	*p = 0;

	return 0;
}
