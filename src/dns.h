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

#ifndef __DNS_H__
#define __DNS_H__

#define QUERY_NAME_SIZE		255
#define QUERY_RDATA_SIZE	4096

#define DNS_MAXCHARSTR		255

/* Don't push the limit with DNS servers: potentially unwanted behaviour
 * if labels are all 63 chars long (DNS standard max label length) */
#define DNS_MAXLABEL		17

#define DNS_NUM_LABELS(hl)	(((hl) + DNS_MAXLABEL - 1) / DNS_MAXLABEL)

/* maximum number of labels that can be in a hostname (including root label) */
#define DNS_MAX_NUM_LABELS		DNS_NUM_LABELS(QUERY_NAME_SIZE)
#define DNS_MAX_HOST_DATA		(QUERY_NAME_SIZE - DNS_MAX_NUM_LABELS)

#define DNS_HOSTLEN(rawlen)		((rawlen) + DNS_NUM_LABELS(rawlen) + 1)
#define DNS_TXTRDLEN(rawlen)	(rawlen + (rawlen / DNS_MAXCHARSTR + 1))

#define T_PRIVATE 65399
/* Undefined RR type; "private use" range, see http://www.bind9.net/dns-parameters */
#define T_UNSET 65432
/* Unused RR type, never actually sent */

#define HOSTLEN(dnshost)		(strlen((char *) dnshost) + 1)


typedef enum {
	QR_QUERY = 0,
	QR_ANSWER = 1
} qr_t;

/* general packet metadata */
struct pkt_metadata {
	struct timeval time_recv;
	struct sockaddr_storage dest;
	struct sockaddr_storage from;
	socklen_t destlen, fromlen;
};

/* question data */
struct dns_question {
	uint8_t name[QUERY_NAME_SIZE];
	size_t namelen;
	uint16_t type;
};

/* answer section resource record data */
struct dns_rr {
	uint16_t qnum; /* question number this RR refers to */
	uint16_t type;
	uint16_t rdlength;
	uint8_t rdata[QUERY_RDATA_SIZE];
};

struct dns_packet {
	size_t refcount; /* counter for references */
	struct dns_question *q; /* array of QDCOUNT queries */
	struct dns_rr *an; /* array of ANCOUNT answer RRs */
	struct dns_rr *ns; /* array of NSCOUNT NS authority RRs */
	struct dns_rr *ar; /* array of ARCOUNT additional RRs */
	struct pkt_metadata m;
	qr_t qr;
	uint16_t id;
	uint16_t rcode;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
};

#include "common.h"

struct dns_packet *dns_packet_create(uint16_t qdcount, uint16_t ancount, uint16_t nscount, uint16_t arcount);
void dns_packet_destroy(struct dns_packet *p);

uint16_t get_qtype_from_name(char *qtype);
char *get_qtype_name(uint16_t qtype);

struct dns_packet *dns_encode_data_query(uint16_t qtype, uint8_t *td, uint8_t *data, size_t datalen);
struct dns_packet *dns_encode_data_answer(struct dns_packet *q, uint8_t *data, size_t datalen);
int dns_encode(uint8_t *buf, size_t *buflen, struct dns_packet *data, int edns0);
size_t dns_encode_ns_response(uint8_t *buf, size_t buflen, struct dns_packet *q, uint8_t *topdomain);
size_t dns_encode_a_response(uint8_t *buf, size_t buflen, struct dns_packet *q);

unsigned short dns_get_id(uint8_t *packet, size_t packetlen);
struct dns_packet *dns_decode(uint8_t *, size_t);
int dns_decode_data_answer(struct dns_packet *q, uint8_t *out, size_t *outlen);
int dns_decode_data_query(struct dns_packet *q, uint8_t *td, uint8_t *out, size_t *outlen);
#endif /* _DNS_H_ */
