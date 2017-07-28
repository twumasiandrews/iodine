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

#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

#ifdef WINDOWS32
#include "windows.h"
#else
#include <arpa/nameser.h>
#ifdef DARWIN
#define BIND_8_COMPAT
#include <arpa/nameser_compat.h>
#endif
#include <netinet/in.h>
#include <arpa/inet.h>
#include <err.h>
#ifdef ANDROID
#include "android_dns.h"
#endif
#endif

#include "common.h"
#include "dns.h"
#include "encoding.h"
#include "read.h"

int dnsc_use_edns0 = 1;

void
dns_packet_destroy(struct dns_packet *p)
{
	free(p->q);
	free(p->an);
	free(p);
}

struct dns_packet *
dns_packet_create(uint16_t qdcount, uint16_t ancount)
{
	struct dns_packet *p;
	p = calloc(1, sizeof(struct dns_packet));
	if (!p) return NULL;
	p->qdcount = qdcount;
	p->ancount = ancount;
	if (qdcount) {
		p->q = calloc(qdcount, sizeof(struct dns_question));
		if (!p->q) {
			dns_packet_destroy(p);
			return NULL;
		}
	}
	if (ancount) {
		p->an = calloc(ancount, sizeof(struct dns_rr));
		if (!p->an) {
			dns_packet_destroy(p);
			return NULL;
		}
	}
	return p;
}

#define CHECKLEN(x) if (buflen < (x) + (unsigned)(p-buf))  return 0

int
dns_encode(uint8_t *buf, size_t *buflen, struct dns_packet *q)
/*				puttxtbin(&p, buflen - (p - buf), data, datalen);
 * 					answer CNAME to A question */
{
	HEADER *header;
	uint16_t ancount;
	uint8_t *p;
	size_t len;

	if (buflen < sizeof(HEADER))
		return 0;

	memset(buf, 0, buflen);

	header = (HEADER*)buf;

	header->id = htons(q->id);
	header->qr = (q->qr == QR_ANSWER);
	header->opcode = 0;
	header->aa = (q->qr == QR_ANSWER);
	header->tc = 0;
	header->rd = (q->qr == QR_QUERY);
	header->ra = 0;
	header->qdcount = htons(q->qdcount);
	header->ancount = htons(q->ancount);

	p = buf + sizeof(HEADER);

	/* Question section(s); must contain valid DNS names (len-prefixed labels) */
	uint16_t qlabel[q->qdcount];
	struct dns_question *qs;
	for (uint16_t qd = 0; qd < q->qdcount; qd++) {
		qs = &q->q[qd];
		CHECKLEN(qs->namelen + 4);
		qlabel[qd] = ((p - buf) & 0x3fff) | 0xc000;
		putdata(&p, qs->name, qs->namelen);
		putshort(&p, qs->type);
		putshort(&p, C_IN);
	}

	switch (q->qr) {
	case QR_ANSWER:

		/* Answer section(s) */
		struct dns_rr *a;
		for (uint16_t ann = 0; ann < q->ancount; ann++) {
			a = &q->an[ann];

			CHECKLEN(10);
			/* name pertaining to RR is given as pointer */
			putshort(&p, qlabel[a->qnum]);
			/* 16 bits TYPE */
			putshort(&p, a->type);
			putshort(&p, C_IN); /* 16 bits CLASS */
			putlong(&p, 0);	/* 32 bits TTL */
			putshort(&p, a->rdlength); /* 16 bits RDLENGTH */

			/* append actual data to query */
			CHECKLEN(a->rdlength);
			putdata(&p, a->rdata, a->rdlength);
		}
		break;
	case QR_QUERY:
		/* Note that iodined also uses this for forward queries */

		/* EDNS0 to advertise maximum response length
		   (even CNAME/A/MX, 255+255+header would be >512) */
		if (dnsc_use_edns0) {
			header->arcount = htons(1);
			CHECKLEN(11);
			putbyte(&p, 0x00);    /* Root */
			putshort(&p, 0x0029); /* OPT */
			putshort(&p, 0x1000); /* Payload size: 4096 */
			putshort(&p, 0x0000); /* Higher bits/edns version */
			putshort(&p, 0x8000); /* Z */
			putshort(&p, 0x0000); /* Data length */
		}

		break;
	}

	len = p - buf;

	*buflen = len;
	return 1;
}

int
dns_encode_ns_response(uint8_t *buf, size_t buflen, struct query *q, uint8_t *topdomain)
/* Only used when iodined gets an NS type query */
/* Mostly same as dns_encode_a_response() below */
{
	HEADER *header;
	int len;
	short name;
	short topname;
	short nsname;
	uint8_t *ipp;
	int domain_len;
	uint8_t *p;

	if (buflen < sizeof(HEADER))
		return 0;

	memset(buf, 0, buflen);

	header = (HEADER*)buf;

	header->id = htons(q->id);
	header->qr = 1;
	header->opcode = 0;
	header->aa = 1;
	header->tc = 0;
	header->rd = 0;
	header->ra = 0;

	p = buf + sizeof(HEADER);

	header->qdcount = htons(1);
	header->ancount = htons(1);
	header->arcount = htons(1);

	/* pointer to start of name */
	name = 0xc000 | ((p - buf) & 0x3fff);

	domain_len = strlen(q->name) - strlen(topdomain);
	if (domain_len < 0 || domain_len == 1)
		return -1;
	if (strcasecmp(q->name + domain_len, topdomain))
		return -1;
	if (domain_len >= 1 && q->name[domain_len - 1] != '.')
		return -1;

	/* pointer to start of topdomain; instead of dots at the end
	   we have length-bytes in front, so total length is the same */
	topname = 0xc000 | ((p - buf + domain_len) & 0x3fff);

	/* Query section */
	putname(&p, buflen - (p - buf), q->name, q->len);	/* Name */
	CHECKLEN(4);
	putshort(&p, q->type);			/* Type */
	putshort(&p, C_IN);			/* Class */

	/* Answer section */
	CHECKLEN(12);
	putshort(&p, name);			/* Name */
	putshort(&p, q->type);			/* Type */
	putshort(&p, C_IN);			/* Class */
	putlong(&p, 3600);			/* TTL */
	putshort(&p, 5);			/* Data length */

	/* pointer to ns.topdomain */
	nsname = 0xc000 | ((p - buf) & 0x3fff);
	CHECKLEN(5);
	putbyte(&p, 2);
	putbyte(&p, 'n');
	putbyte(&p, 's');
	putshort(&p, topname);			/* Name Server */

	/* Additional data (A-record of NS server) */
	CHECKLEN(12);
	putshort(&p, nsname);			/* Name Server */
	putshort(&p, T_A);			/* Type */
	putshort(&p, C_IN);			/* Class */
	putlong(&p, 3600);			/* TTL */
	putshort(&p, 4);			/* Data length */

	/* ugly hack to output IP address */
	ipp = (uint8_t *) &q->destination;
	CHECKLEN(4);
	putbyte(&p, *(ipp++));
	putbyte(&p, *(ipp++));
	putbyte(&p, *(ipp++));
	putbyte(&p, *ipp);

	len = p - buf;
	return len;
}

int
dns_encode_a_response(uint8_t *buf, size_t buflen, struct query *q)
/* Only used when iodined gets an A type query for ns.topdomain or www.topdomain */
/* Mostly same as dns_encode_ns_response() above */
{
	HEADER *header;
	int len;
	short name;
	uint8_t *ipp;
	uint8_t *p;

	if (buflen < sizeof(HEADER))
		return 0;

	memset(buf, 0, buflen);

	header = (HEADER*)buf;

	header->id = htons(q->id);
	header->qr = 1;
	header->opcode = 0;
	header->aa = 1;
	header->tc = 0;
	header->rd = 0;
	header->ra = 0;

	p = buf + sizeof(HEADER);

	header->qdcount = htons(1);
	header->ancount = htons(1);

	/* pointer to start of name */
	name = 0xc000 | ((p - buf) & 0x3fff);

	/* Query section */
	putname(&p, buflen - (p - buf), q->name, q->len);	/* Name */
	CHECKLEN(4);
	putshort(&p, q->type);			/* Type */
	putshort(&p, C_IN);			/* Class */

	/* Answer section */
	CHECKLEN(12);
	putshort(&p, name);			/* Name */
	putshort(&p, q->type);			/* Type */
	putshort(&p, C_IN);			/* Class */
	putlong(&p, 3600);			/* TTL */
	putshort(&p, 4);			/* Data length */

	/* ugly hack to output IP address */
	ipp = (uint8_t *) &q->destination;
	CHECKLEN(4);
	putbyte(&p, *(ipp++));
	putbyte(&p, *(ipp++));
	putbyte(&p, *(ipp++));
	putbyte(&p, *ipp);

	len = p - buf;
	return len;
}

#undef CHECKLEN

unsigned short
dns_get_id(uint8_t *packet, size_t packetlen)
{
	HEADER *header;
	header = (HEADER*)packet;

	if (packetlen < sizeof(HEADER))
		return 0;

	return ntohs(header->id);
}

#define CHECKLEN(x) if (packetlen < (x) + (unsigned)(p-packet))  return 0

struct dns_packet *
dns_decode(uint8_t *packet, size_t packetlen)
{
	uint8_t name[QUERY_NAME_SIZE], *p;
	uint16_t class;
	uint32_t ttl;
	struct dns_packet *q;

	/* Reject short packets */
	if (packetlen < sizeof(HEADER))
		return NULL;

	HEADER *header = (HEADER *) packet;
	q = dns_packet_create(ntohs(header->qdcount), ntohs(header->ancount));
	if (!q) {
		warnx("error allocating memory for dns_packet!");
		return NULL;
	}

	q->id = ntohs(header->id);
	q->qr = header->qr == 0 ? QR_QUERY : QR_ANSWER;
	q->rcode = header->rcode;

	p = packet + sizeof(HEADER);
	if (header->arcount != 0 || header->nscount != 0) {
		warnx("DNS response has %hu authority + %hu NS RRs!", ntohs(header->arcount), ntohs(header->nscount));
	}

	if(q->qdcount < 1) {
		/* We need a question */
		return -1;
	}

	/* Read question section */
	for (uint16_t qn = 0; qn < q->qdcount; qn++) {
		struct dns_question *qs = &q->q[qn];
		qs->namelen = readname(packet, packetlen, &p, qs->name, sizeof(qs->name));
		CHECKLEN(4);
		readshort(packet, &p, &qs->type);
		readshort(packet, &p, &class);
		if (class != C_IN) {
			return -1;
		}
	}

	if (q->qr == QR_ANSWER) {
		if (q->ancount < 1) {
			/* DNS errors like NXDOMAIN have ancount=0 and
			   stop here. CNAME may also have A; MX/SRV may have
			   multiple results. */
			return -1;
		}

		/* Answer section RRs */
		struct dns_rr *a;
		for (uint16_t ann = 0; ann < q->ancount; ann++) {
			a = &q->an[ann];
			/* name of corresponding question */
			readname(packet, packetlen, &p, name, sizeof(name), 1, 1);
			CHECKLEN(10);
			readshort(packet, &p, &a->type); /* answer type */
			readshort(packet, &p, &class); /* answer class */
			readlong(packet, &p, &ttl); /* answer TTL (seconds) */
			readshort(packet, &p, &a->rdlength); /* length of RDATA */
			readdata(packet, &p, a->rdata, a->rdlength); /* RDATA */
		}
	}

	return q;
}

#define CHECKLEN(x) if (sizeof(qs->name) < (x) + p-qs->name) return 0

struct dns_packet *
dns_encode_data_query(uint16_t qtype, char *td, uint8_t *data, size_t datalen)
/* encode (possibly binary) data as DNS labels and fill dns_packet structure */
{
	struct dns_packet *q = dns_packet_create(1, 0);
	if (!q)
		return NULL;

	struct dns_question *qs = &q->q[0];
	qs->type = qtype;
	q->id = rand() & 0xFFFF;
	q->qr = QR_QUERY;
	q->rcode = NOERROR;

	uint8_t *p = qs->name;
	CHECKLEN(DNS_HOSTLEN(datalen) + strlen(td) - 1);
	size_t hostlen = putname(&p, sizeof(qs->name), data, datalen, 1) - 1;

	/* overwrite root label with topdomain */
	p--;
	hostlen += putname(&p, sizeof(qs->name) - hostlen, td, strlen(td), 0);
	qs->namelen = hostlen;
	return q;
}

#define CHECKLEN(x, ann) if (sizeof(q->an[ann].rdata) < (x) + (p-q->an[ann].rdata)) return 0

int
dns_encode_data_answer(struct dns_packet *q, uint8_t *data, size_t datalen)
/* encodes (possibly binary) data into query q using whichever
 * RR types are applicable to the question type
 * returns 0 on failure, 1 on success
 * note: q is modified */
{
	if (q->qdcount == 0 || q->ancount != 0 || q->qr != QR_QUERY) {
		/* we need a question */
		return 0;
	}

	q->qr = QR_ANSWER;

	/* determine anstype + number of RRs to be encoded */
	q->ancount = 1;
	uint16_t type = q->q[0].type;
	uint16_t anstype = type;
	if (type == T_A || type == T_AAAA) {
		anstype = T_CNAME;
	} else if (type == T_MX) {
		q->ancount = datalen / (DNS_MAX_HOST_DATA - 2) + 1;
	} else if (type == T_SRV) {
		q->ancount = datalen / (DNS_MAX_HOST_DATA - 6) + 1;
	}

	if (q->an)
		free(q->an);
	q->an = calloc(q->ancount, sizeof(struct dns_rr));

	uint8_t *p;
	if (anstype == T_CNAME || anstype == T_DNAME ||
		anstype == T_PTR || anstype == T_A6) {
		if (DNS_NUM_LABELS(datalen) + 1 + datalen > sizeof(q->an[0].rdata)) {
			warnx("cannot encode more than QUERY_RDATA_SIZE (%d)", QUERY_RDATA_SIZE);
			return 0;
		}
		p = q->an[0].rdata;
		/* produce simple rdata with single hostname */
		if (anstype == T_A6) {
			CHECKLEN(1, 0);
			/* A6 prefix len = 128 (no address suffix); see RFC 2874 */
			putbyte(&p, 128);
		}
		putname(&p, q->an[0].rdlength - (p - q->an[0].rdata), data, datalen, 1);
	} else if (anstype == T_MX || anstype == T_SRV) {
		size_t rdhostlen = datalen / q->ancount + 1;
		size_t remain = datalen;
		uint8_t *d = data;
		for (uint16_t ann = 0; ann < q->ancount; ann++) {
			q->an[ann].type = anstype;
			p = q->an[ann].rdata;
			/* preference (both MX & SRV); used for reassembly */
			CHECKLEN(2, ann);
			putshort(&p, 10 * (ann + 1));
			if (anstype == T_SRV) {
				CHECKLEN(4, ann);
				/* SRV has extra 2 fields in RDATA; see RFC 2782 */
				putshort(&p, 10); /* 16 bits weight */
				putshort(&p, 5060); /* 16 bits port (5060 = SIP) */
			}
			CHECKLEN(DNS_HOSTLEN(rdhostlen), ann);
			putname(&p, sizeof(q->an[ann].rdata) - (p - q->an[0].rdata),
					data, datalen, 1);
			q->an[ann].rdlength = p - q->an[ann].rdata;
		}
	} else if (anstype == T_TXT) {
		CHECKLEN(DNS_TXTRDLEN(datalen), 0);
		q->an[0].rdlength = puttxtbin(&p, sizeof(q->an[0].rdata), data, datalen);
	} else { /* NULL or PRIVATE */
		CHECKLEN(datalen, 0);
		memcpy(data, q->an[0].rdata, datalen);
		q->an[0].rdlength = datalen;
	}
	return 1;
}

int
dns_decode_rr(struct dns_rr *r, uint8_t *out, size_t *outlen)
{
//	if (type == T_A || type == T_CNAME ||
//		type == T_PTR || type == T_AAAA ||
//		type == T_A6 || type == T_DNAME) {
//
//		/* Assume that first answer is what we wanted */
//		if (type == T_A6) {
//			unsigned char prefix;
//			CHECKLEN(1);
//			readdata(packet, &p, (uint8_t *) &prefix, 1);
//			if (prefix != 128) {
//				return 0;
//			}
//		}
//		memset(name, 0, sizeof(name));
//		readname(packet, packetlen, &p, name, sizeof(name) - 1);
//	}
//	else if ((type == T_MX || type == T_SRV) && buf) {
//		/* We support 250 records, 250*(255+header) ~= 64kB.
//		   Only exact 10-multiples are accepted, and gaps in
//		   numbering are not jumped over (->truncated).
//		   Hopefully DNS servers won't mess around too much.
//		 */
//		uint8_t names[250][QUERY_NAME_SIZE];
//		uint8_t *rdatastart;
//		unsigned short pref;
//		int i;
//		int offset;
//
//		memset(names, 0, sizeof(names));
//
//		for (i=0; i < ancount; i++) {
//			readshort(packet, &p, &pref);
//
//			if (type == T_SRV) {
//				/* skip weight, port */
//				p += 4;
//				CHECKLEN(0);
//			}
//
//			if (pref % 10 == 0 && pref >= 10 &&
//				pref < 2500) {
//				readname(packet, packetlen, &p,
//					 names[pref / 10 - 1],
//					 QUERY_NAME_SIZE - 1);
//				names[pref / 10 - 1][QUERY_NAME_SIZE-1] = '\0';
//			}
//
//			/* always trust rlen, not name encoding */
//			p = rdatastart + rlen;
//			CHECKLEN(0);
//		}
//
//	}
//	else if (type == T_TXT && buf) {
//		/* Assume that first answer is what we wanted */
//		rv = readtxtbin(packet, &p, rlen, rdata, sizeof(rdata));
//	}

}
