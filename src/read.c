/*
 * Copyright (c) 2006-2014 Erik Ekman <yarrick@kryo.se>,
 * 2006-2009 Bjorn Andersson <flex@kryo.se>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdint.h>
#include <stdlib.h>

/* TODO allow raw-encoded hostnames */
size_t
readname_loop(uint8_t *packet, size_t packetlen, uint8_t **src, uint8_t *dst, size_t length, size_t loop)
{
	uint8_t *dummy, *s, *d;
	size_t len, offset;
	uint8_t labellen;

	if (loop <= 0)
		return 0;

	len = 0;
	s = *src;
	d = dst;
	while(*s && len < length - 1) {
		labellen = *s++;

		/* is this a compressed label? */
		if((labellen & 0xc0) == 0xc0) {
			offset = (((labellen & 0x3f) << 8) | (*s++ & 0xff));
			if (offset > packetlen) {
				if (len == 0) {
					/* Bad jump first in packet */
					return 0;
				} else {
					/* Bad jump after some data */
					break;
				}
			}
			dummy = packet + offset;
			len += readname_loop(packet, packetlen, &dummy, d, length - len, loop - 1);
			goto end;
		} else if ((labellen & 0xc0) != 0) {
			/* invalid hostname, abort */
			break;
		}

		while (labellen && len < length - 1 && packetlen - (s - packet) > 1) {
			*d++ = *s++;
			len++;
			labellen--;
		}

		if (len >= length || packetlen - (s - packet) < 1) {
			break; /* We used up all space */
		}

		if (*s != 0) {
			*d++ = '.';
			len++;
		}
	}

end:
	(*src) = s+1;
	return len;
}

size_t
readname(uint8_t *packet, size_t packetlen, uint8_t **src, uint8_t *dst, size_t length)
{
	return readname_loop(packet, packetlen, src, dst, length, 10);
}

size_t
readshort(uint8_t *packet, uint8_t **src, uint16_t *dst)
{
	uint8_t *p;

	p = *src;
	*dst = (p[0] << 8) | p[1];

	(*src) += sizeof(uint16_t);
	return sizeof(uint16_t);
}

size_t
readlong(uint8_t *packet, uint8_t **src, uint32_t *dst)
{
	/* A long as described in dns protocol is always 32 bits */
	uint8_t *p;

	p = *src;

	*dst = ((uint32_t)p[0] << 24)
		 | ((uint32_t)p[1] << 16)
		 | ((uint32_t)p[2] << 8)
		 | ((uint32_t)p[3]);

	(*src) += sizeof(uint32_t);
	return sizeof(uint32_t);
}

size_t
readdata(uint8_t *packet, uint8_t **src, uint8_t *dst, size_t len)
{
	memcpy(dst, *src, len);

	(*src) += len;

	return len;
}

size_t
readtxtbin(uint8_t *packet, uint8_t **src, size_t srcremain, uint8_t *dst, size_t dstremain)
{
	uint8_t *uc;
	size_t tocopy;
	size_t dstused = 0;

	while (srcremain > 0)
	{
		uc = (*src);
		tocopy = *uc;
		(*src)++;
		srcremain--;

		if (tocopy > srcremain)
			return 0;	/* illegal, better have nothing */
		if (tocopy > dstremain)
			return 0;	/* doesn't fit, better have nothing */

		memcpy(dst, *src, tocopy);
		dst += tocopy;
		(*src) += tocopy;
		srcremain -= tocopy;
		dstremain -= tocopy;
		dstused += tocopy;
	}
	return dstused;
}

size_t
putname(uint8_t **buf, size_t buflen, uint8_t *host, size_t hostlen)
{
	uint8_t *p, *labelprefix, *h;
	size_t len = 0, total = 0, hpos = 0;

	labelprefix = p = *buf;
	h = host;
	p++;

	while (1) {
		if (*h == '.' || hpos >= hostlen) {
			h++;
			*labelprefix = (uint8_t) len & 0x3F;
			labelprefix = p++;
			len = 0; /* start next label */
		} else {
			*p++ = *h++;
			len++;
		}

		if (len >= 63 || total >= buflen) {
			/* invalid hostname or buffer too small */
			return 0;
		}
		hpos++;
		total++;
		if (hpos > hostlen) {
			break;
		}
	}

	*p++ = 0; /* add root label (len=0) */
	*buf = p;

	return total + 1;
}

size_t
putbyte(uint8_t **dst, uint8_t value)
{
	**dst = value;
	(*dst)++;

	return sizeof(uint8_t);
}

size_t
putshort(uint8_t **dst, uint16_t value)
{
	uint8_t *p;

	p = *dst;

	*p++ = (value >> 8);
	*p++ = value;

	(*dst) = p;
	return sizeof(uint16_t);
}

size_t
putlong(uint8_t **dst, uint32_t value)
{
	/* A long as described in dns protocol is always 32 bits */
	uint8_t *p;

	p = *dst;

	*p++ = (value >> 24);
	*p++ = (value >> 16);
	*p++ = (value >> 8);
	*p++ = (value);

	(*dst) = p;
	return sizeof(uint32_t);
}

size_t
putdata(uint8_t **dst, uint8_t *data, size_t len)
{
	memcpy(*dst, data, len);

	(*dst) += len;
	return len;
}

size_t
puttxtbin(uint8_t **buf, size_t bufremain, uint8_t *from, size_t fromremain)
{
	uint8_t uc;
	uint8_t *ucp = &uc;
	uint8_t *cp = ucp;
	size_t tocopy, bufused = 0;

	while (fromremain > 0)
	{
		tocopy = fromremain;
		if (tocopy > 252)
			tocopy = 252;	/* allow off-by-1s in caches etc */
		if (tocopy + 1 > bufremain)
			return -1;	/* doesn't fit, better have nothing */

		uc = tocopy;
		**buf = *cp;
		(*buf)++;
		bufremain--;
		bufused++;

		memcpy(*buf, from, tocopy);
		(*buf) += tocopy;
		from += tocopy;
		bufremain -= tocopy;
		fromremain -= tocopy;
		bufused += tocopy;
	}
	return bufused;
}
