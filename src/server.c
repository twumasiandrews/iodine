/*
 * Copyright (c) 2006-2015 Erik Ekman <yarrick@kryo.se>,
 * 2006-2009 Bjorn Andersson <flex@kryo.se>,
 * 2015 Frekk van Blagh <frekk@frekkworks.com>
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

 #ifndef WINDOWS32
 #ifdef HAVE_CONFIG_H
 #include "config.h"
 #endif
 #endif

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/time.h>
#include <fcntl.h>
#include <time.h>
#include <zlib.h>
#include <ctype.h>
#include <errno.h>

#include "common.h"
#include "version.h"

#include "dns.h"
#include "encoding.h"
#include "base32.h"
#include "base64.h"
#include "base64u.h"
#include "base128.h"
#include "user.h"
#include "login.h"
#include "tun.h"
#include "fw_query.h"
#include "util.h"
#include "server.h"
#include "window.h"

#ifdef HAVE_SYSTEMD
# include <systemd/sd-daemon.h>
#endif

#ifdef WINDOWS32
WORD req_version = MAKEWORD(2, 2);
WSADATA wsa_data;
#else
#include <err.h>
#endif

static void
send_raw(int fd, uint8_t *buf, size_t buflen, int user, int cmd, struct sockaddr_storage *from, socklen_t fromlen)
{
	char packet[buflen + RAW_HDR_LEN];
	int len = buflen;

	memcpy(packet, raw_header, RAW_HDR_LEN);
	if (len) {
		memcpy(&packet[RAW_HDR_LEN], buf, len);
	}

	len += RAW_HDR_LEN;
	packet[RAW_HDR_CMD] = cmd | (user & 0x0F);

	DEBUG(3, "TX-raw: client %s (user %d), cmd %d, %d bytes",
			format_addr(from, fromlen), user, cmd, len);

	sendto(fd, packet, len, 0, (struct sockaddr *) from, fromlen);
}

/* Ringbuffer Query Handling (qmem) and DNS Cache:
   This is used to make the handling duplicates and query timeouts simpler
   and all handled in one place.
   Using this, lazy mode is possible with n queries (n <= windowsize)

   New queries are placed consecutively in the buffer, replacing any old
   queries (already responded to) if length == QMEM_LEN. Old queries are kept
   as a record for duplicate requests. If a dupe is found and USE_DNSCACHE is
   defined, the previous answer is sent (if it exists), otherwise an invalid
   response is sent.

   On the DNS cache:
   This cache is implemented to better handle the aggressively impatient DNS
   servers that very quickly re-send requests when we choose to not
   immediately answer them in lazy mode. This cache works much better than
   pruning(=dropping) the improper requests, since the DNS server will
   actually get an answer instead of silence.

   Because of the CMC in both ping and upstream data, unwanted cache hits
   are prevented. Due to the combination of CMC and varying sequence IDs, it
   is extremely unlikely that any duplicate answers will be incorrectly sent
   during a session (given QMEM_LEN is not very large). */

#define QMEM_DEBUG(l, u, ...) \
	if (server.debug >= l) {\
		TIMEPRINT("[QMEM u%d (%" L "u/%u)] ", u, users[u].qmem.num_pending, users[u].outgoing->windowsize); \
		fprintf(stderr, __VA_ARGS__);\
		fprintf(stderr, "\n");\
	}

static void
qmem_init(int userid)
/* initialize user QMEM and DNS cache (if enabled) */
{
	memset(&users[userid].qmem, 0, sizeof(struct qmem_buffer));
	for (size_t i = 0; i < QMEM_LEN; i++) {
		users[userid].qmem.queries[i].q.id = -1;
	}
}

static int
qmem_is_cached(int dns_fd, int userid, struct query *q)
/* Check if an answer for a particular query is cached in qmem
 * If so, sends an "invalid" answer or one from DNS cache
 * Returns 0 if new query (ie. not cached), 1 if cached (and then answered) */
{
	struct qmem_buffer *buf;
	struct query *pq;
	char *data = "x";
	char dataenc = 'T';
	size_t len = 1;
	int dnscache = 0;
	buf = &users[userid].qmem;

	/* Check if this is a duplicate query */
	for (size_t p = buf->start; p != buf->end; p = (p + 1) % QMEM_LEN) {
		pq = &buf->queries[p].q;
		if (pq->id != q->id)
			continue;
		if (pq->type != q->type)
			continue;

		if (strcasecmp(pq->name, q->name))
			continue;

		/* Aha! A match! */

#ifdef USE_DNSCACHE
		/* Check if answer is in DNS cache */
		if (buf->queries[p].a.len) {
			data = (char *)buf->queries[p].a.data;
			len = buf->queries[p].a.len;
			dataenc = users[userid].downenc;
			dnscache = 1;
		}
#endif

		QMEM_DEBUG(2, userid, "OUT from qmem for '%s', %s", q->name,
				dnscache ? "answer from DNS cache" : "sending invalid response");
		write_dns(dns_fd, q, data, len, dataenc);
		return 1;
	}
	return 0;
}

static int
qmem_append(int userid, struct query *q)
/* Appends incoming query to the buffer. */
{
	struct qmem_buffer *buf;
	buf = &users[userid].qmem;

	if (buf->num_pending >= QMEM_LEN) {
		/* this means we have QMEM_LEN *pending* queries; respond to oldest
		 * one to make space for new query */
		QMEM_DEBUG(2, userid, "Full of pending queries! Replacing old query %d with new %d.",
				   buf->queries[buf->start].q.id, q->id);
		send_data_or_ping(userid, &buf->queries[buf->start].q, 0, 0, NULL);
	}

	if (buf->length < QMEM_LEN) {
		buf->length++;
	} else {
		/* will replace oldest query (in buf->queries[buf->start]) */
		buf->start = (buf->start + 1) % QMEM_LEN;
	}

	QMEM_DEBUG(5, userid, "add query ID %d, timeout %" L "u ms", q->id, timeval_to_ms(&users[userid].dns_timeout));

	/* Copy query into end of buffer */
	memcpy(&buf->queries[buf->end].q, q, sizeof(struct query));
#ifdef USE_DNSCACHE
	buf->queries[buf->end].a.len = 0;
#endif
	buf->end = (buf->end + 1) % QMEM_LEN;
	buf->num_pending += 1;
	return 1;
}

static void
qmem_answered(int userid, uint8_t *data, size_t len)
/* Call when oldest/first/earliest query added has been answered */
{
	struct qmem_buffer *buf;
	size_t answered;
	buf = &users[userid].qmem;

	if (buf->num_pending == 0) {
		/* Most likely caused by bugs somewhere else. */
		QMEM_DEBUG(1, userid, "Query answered with 0 in qmem! Fix bugs.");
		return;
	}
	answered = buf->start_pending;
	buf->start_pending = (buf->start_pending + 1) % QMEM_LEN;
	buf->num_pending -= 1;

#ifdef USE_DNSCACHE
	/* Add answer to query entry */
	if (len && data) {
		if (len > 4096) {
			QMEM_DEBUG(1, userid, "got answer with length >4096!");
		}
		memcpy(&buf->queries[answered].a.data, data, MIN(len, 4096));
		buf->queries[answered].a.len = len;
	}
#endif

	QMEM_DEBUG(3, userid, "query ID %d answered", buf->queries[answered].q.id);
}

struct query *
qmem_get_next_response(int userid)
/* Gets oldest query to be responded to (for lazy mode) or NULL if none available
 * The query is NOT marked as "answered" since that is done later. */
{
	struct qmem_buffer *buf;
	struct query *q;
	buf = &users[userid].qmem;
	if (buf->length == 0 || buf->num_pending == 0)
		return NULL;
	q = &buf->queries[buf->start_pending].q;
	QMEM_DEBUG(3, userid, "next response using cached query: ID %d", q->id);
	return q;
}

static struct timeval
qmem_max_wait(int *touser, struct query **sendq)
/* Gets max interval before the next query has to be responded to
 * Response(s) are sent automatically for queries if:
 *  - the query has timed out
 *  - the user has data to send or pending ACKs, and spare pending queries
 *  - the user has excess pending queries (>downstream window size)
 * Returns largest safe time to wait before next timeout */
{
	struct timeval now, timeout, soonest, tmp, age, nextresend;
	soonest.tv_sec = 10;
	soonest.tv_usec = 0;
	int userid, nextuser = -1, resend = 0;
	struct query *q = NULL, *nextq = NULL;
	size_t sending, total, sent;
	struct tun_user *u;

	gettimeofday(&now, NULL);
	for (userid = 0; userid < created_users; userid++) {
		if (!user_active(userid))
			continue;

		u = &users[userid];

		if (u->qmem.num_pending == 0)
			continue;

		/* Keep track of how many fragments we can send */
		if (u->lazy) {
			total = window_sending(u->outgoing, &nextresend);
			if ((nextresend.tv_sec != 0 || nextresend.tv_usec != 0)
				&& u->qmem.num_pending >= 1) {
				/* will use nextresend as max wait time if it is smallest
				 * and if user has spare queries */
				resend = 1;
				soonest = nextresend;
			}

			if (u->qmem.num_pending > u->outgoing->windowsize) {
				/* calculate number of "excess" queries */
				total = MAX(total, u->qmem.num_pending - u->outgoing->windowsize);
			}
		} else {
			/* User in immediate mode, must answer all pending queries */
			total = u->qmem.num_pending;
		}

		sending = total;
		sent = 0;

		int qnum = u->qmem.start_pending;
		for (; qnum != u->qmem.end; qnum = (qnum + 1) % QMEM_LEN) {
			q = &u->qmem.queries[qnum].q;

			/* queries will always be in time order */
			timeradd(&q->time_recv, &u->dns_timeout, &timeout);
			if (sending > 0 || !timercmp(&now, &timeout, <) || u->next_upstream_ack >= 0) {
				/* respond to a query with ping/data if:
				 *  - query has timed out (ping, or data if available)
				 *  - user has pending data (always data)
				 *  - user has pending ACK (either) */
				timersub(&now, &q->time_recv, &age);
				time_t age_ms = timeval_to_ms(&age);

				/* only consider "immediate" when age is negligible */
				int immediate = llabs(age_ms) <= 10;

				QMEM_DEBUG(3, userid, "ANSWER: ID %d, age=%ldms (imm=%d), timeout %ldms, ACK %d,"
						" sent %" L "u/%" L "u (+%" L "u)", q->id, age_ms, immediate,
						timeval_to_ms(&u->dns_timeout), u->next_upstream_ack, sent, total, sending);

				sent++;
				send_data_or_ping(userid, q, 0, immediate, NULL);

				if (sending > 0)
					sending--;
				continue;
			}

			timersub(&timeout, &now, &tmp);
			if (timercmp(&tmp, &soonest, <)) {
				/* the oldest non-timed-out query in the buffer will be the
				 * soonest to timeout for this user; we can skip the rest */
				soonest = tmp;
				nextuser = userid;
				nextq = q;
				break;
			}
		}
	}

	if (server.debug >= 5) {
		time_t soonest_ms = timeval_to_ms(&soonest);
		if (nextq && nextuser >= 0) {
			QMEM_DEBUG(5, nextuser, "can wait for %" L "d ms, will send id %d", soonest_ms, nextq->id);
		} else {
			if (nextuser < 0)
				nextuser = 0;
			if (soonest_ms != 10000 && resend) {
				/* only if resending some frags */
				QMEM_DEBUG(5, nextuser, "Resending some fragments, soonest = %d ms", soonest_ms);
				if (soonest_ms == 0)
					QMEM_DEBUG(5, nextuser, "soonest_ms == 0! tv=%ds,%dus", soonest.tv_sec, soonest.tv_usec);
			} else {
				QMEM_DEBUG(2, nextuser, "Don't need to send anything to any users, waiting %" L "d ms", soonest_ms);
			}
		}
	}

	if (sendq)
		*sendq = nextq;
	if (touser)
		*touser = nextuser;

	return soonest;
}

static int
get_dns_fd(struct dnsfd *fds, struct sockaddr_storage *addr)
{
	if (addr->ss_family == AF_INET6) {
		return fds->v6fd;
	}
	return fds->v4fd;
}


static void
forward_query(int bind_fd, struct query *q)
{
	char buf[64*1024];
	int len;
	struct fw_query fwq;
	struct sockaddr_in *myaddr;
	in_addr_t newaddr;

	len = dns_encode(buf, sizeof(buf), q, QR_QUERY, q->name, strlen(q->name));
	if (len < 1) {
		warnx("dns_encode doesn't fit");
		return;
	}

	/* Store sockaddr for q->id */
	memcpy(&(fwq.addr), &(q->from), q->fromlen);
	fwq.addrlen = q->fromlen;
	fwq.id = q->id;
	fw_query_put(&fwq);

	newaddr = inet_addr("127.0.0.1");
	myaddr = (struct sockaddr_in *) &(q->from);
	memcpy(&(myaddr->sin_addr), &newaddr, sizeof(in_addr_t));
	myaddr->sin_port = htons(server.bind_port);

	DEBUG(2, "TX: NS reply");

	if (sendto(bind_fd, buf, len, 0, (struct sockaddr*)&q->from, q->fromlen) <= 0) {
		warn("forward query error");
	}
}

static void
send_version_response(int fd, version_ack_t ack, uint32_t payload, int userid, struct query *q)
{
	char out[9];

	switch (ack) {
	case VERSION_ACK:
		strncpy(out, "VACK", sizeof(out));
		break;
	case VERSION_NACK:
		strncpy(out, "VNAK", sizeof(out));
		break;
	case VERSION_FULL:
		strncpy(out, "VFUL", sizeof(out));
		break;
	}

	*(uint32_t *) (out + 4) = htonl(payload);
	out[8] = userid & 0xff;

	write_dns(fd, q, out, sizeof(out), users[userid].downenc);
}

void
send_data_or_ping(int userid, struct query *q, int ping, int immediate, char *tcperror)
/* Sends current fragment to user, or a ping if no data available.
   ping: 1=force send ping (even if data available), 0=only send if no data.
   immediate: 1=not from qmem (ie. fresh query), 0=query is from qmem
   tcperror: whether to tell user that TCP socket is closed (NULL if OK or pointer to error message) */
{
	size_t datalen, headerlen;
	fragment *f = NULL;
	struct frag_buffer *out, *in;

	in = users[userid].incoming;
	out = users[userid].outgoing;

	uint8_t pkt[out->maxfraglen + DOWNSTREAM_PING_HDR];

	if (!tcperror) {
		f = window_get_next_sending_fragment(out, &users[userid].next_upstream_ack);
	} else {
		/* construct fake fragment containing error message. */
		fragment fr;
		f = &fr;
		memset(f, 0, sizeof(fragment));
		f->ack_other = -1;
		f->len = strlen(tcperror);
		memcpy(f->data, tcperror, f->len);
		f->data[f->len] = 0;
		f->start = 1;
		f->end = 1;
		DEBUG(2, "Sending ping with TCP forward disconnect; error: %s", f->data);
	}

	/* Build downstream data/ping header (see doc/proto_xxxxxxxx.txt) for details */
	if (!f) {
		/* No data, send data/ping header (with extra info) */
		ping = 1;
		datalen = 0;
		pkt[0] = 0; /* Pings don't need seq IDs unless they have data */
		pkt[1] = users[userid].next_upstream_ack & 0xFF;
		pkt[2] = (users[userid].next_upstream_ack < 0 ? 0 : 1) << 3;
		users[userid].next_upstream_ack = -1;
	} else {
		datalen = f->len;
		pkt[0] = f->seqID & 0xFF;
		pkt[1] = f->ack_other & 0xFF;
		pkt[2] = ((f->ack_other < 0 ? 0 : 1) << 3) | ((f->compressed & 1) << 2) | (f->start << 1) | f->end;
		headerlen = DOWNSTREAM_HDR;
	}

	/* If this is being responded to immediately (ie. not from qmem)
	 * This flag is used by client to calculate stats */
	pkt[2] |= (immediate & 1) << 5;
	if (tcperror) {
		pkt[2] |= (1 << 6);
	}

	if (ping) {
		/* set ping flag and build extra header */
		pkt[2] |= 1 << 4;
		pkt[3] = out->windowsize & 0xFF;
		pkt[4] = in->windowsize & 0xFF;
		pkt[5] = out->start_seq_id & 0xFF;
		pkt[6] = in->start_seq_id & 0xFF;
		headerlen = DOWNSTREAM_PING_HDR;
	}
	if (datalen + headerlen > sizeof(pkt)) {
		warnx("send_data_or_ping: fragment too large to send! (%" L "u)", datalen);
		window_tick(out);
		return;
	}
	if (f) {
		memcpy(pkt + headerlen, f->data, datalen);
	}

	write_dns(get_dns_fd(&server.dns_fds, &q->from), q, (char *)pkt,
			  datalen + headerlen, users[userid].downenc);

	/* mark query as answered */
	qmem_answered(userid, pkt, datalen + headerlen);
	window_tick(out);
}

void
user_process_incoming_data(int userid, int ack)
{
	uint8_t pkt[65536];
	size_t datalen;
	uint8_t compressed = 0;
	int can_reassemble = 1;

	if (ack >= 0) {
		window_ack(users[userid].outgoing, ack);
		window_tick(users[userid].outgoing);
	}

	while (can_reassemble == 1) {
		datalen = sizeof(pkt);
		can_reassemble = window_reassemble_data(users[userid].incoming, pkt, &datalen, &compressed);

		/* Update time info */
		users[userid].last_pkt = time(NULL);

		if (datalen > 0) {
			/* Data reassembled successfully + cleared out of buffer */
			handle_full_packet(userid, pkt, datalen, compressed);
		}
	}
}

static int
user_send_data(int userid, uint8_t *indata, size_t len, int compressed)
/* Appends data to a user's outgoing queue and sends it (in raw mode only) */
{
	size_t datalen;
	int ret = 0;
	uint8_t out[65536], *data;

	data = indata;
	datalen = len;

	/* use compressed or uncompressed packet to match user settings */
	if (users[userid].down_compression && !compressed) {
		datalen = sizeof(out);
		compress2(out, &datalen, indata, len, 9);
		data = out;
	} else if (!users[userid].down_compression && compressed) {
		datalen = sizeof(out);
		ret = uncompress(out, &datalen, indata, len);
		if (ret != Z_OK) {
			DEBUG(1, "FAIL: Uncompress == %d: %" L "u bytes to user %d!", ret, len, userid);
			return 0;
		}
	}

	compressed = users[userid].down_compression;

	if (users[userid].conn == CONN_DNS_NULL && data && datalen) {
		/* append new data to user's outgoing queue; sent later in qmem_max_wait */
		ret = window_add_outgoing_data(users[userid].outgoing, data, datalen, compressed);

	} else if (data && datalen) { /* CONN_RAW_UDP */
		if (!compressed)
			DEBUG(1, "Sending in RAW mode uncompressed to user %d!", userid);
		int dns_fd = get_dns_fd(&server.dns_fds, &users[userid].host);
		send_raw(dns_fd, data, datalen, userid, RAW_HDR_CMD_DATA,
					&users[userid].host, users[userid].hostlen);
		ret = 1;
	}

	return ret;
}

static int
user_send_tcp_disconnect(int userid, struct query *q, char *errormsg)
/* tell user that TCP socket has been disconnected */
{
	users[userid].remote_forward_connected = -1;
	close_socket(users[userid].remote_tcp_fd);
	if (q == NULL)
		q = qmem_get_next_response(userid);
	if (q != NULL) {
		send_data_or_ping(userid, q, 1, 0, errormsg);
		users[userid].active = 0;
		return 1;
	}
	users[userid].active = 0;
	return 0;
}

static int
tunnel_bind()
{
	char packet[64*1024];
	struct sockaddr_storage from;
	socklen_t fromlen;
	struct fw_query *query;
	unsigned short id;
	int dns_fd;
	int r;

	fromlen = sizeof(struct sockaddr);
	r = recvfrom(server.bind_fd, packet, sizeof(packet), 0,
		(struct sockaddr*)&from, &fromlen);

	if (r <= 0)
		return 0;

	id = dns_get_id(packet, r);

	DEBUG(3, "RX: Got response on query %u from DNS", (id & 0xFFFF));

	/* Get sockaddr from id */
	fw_query_get(id, &query);
	if (!query) {
		DEBUG(2, "Lost sender of id %u, dropping reply", (id & 0xFFFF));
		return 0;
	}

	DEBUG(3, "TX: client %s id %u, %d bytes",
			format_addr(&query->addr, query->addrlen), (id & 0xffff), r);

	dns_fd = get_dns_fd(&server.dns_fds, &query->addr);
	if (sendto(dns_fd, packet, r, 0, (const struct sockaddr *) &(query->addr),
		query->addrlen) <= 0) {
		warn("forward reply error");
	}

	return 0;
}

static ssize_t
tunnel_tcp(int userid)
{
	ssize_t len;
	uint8_t buf[64*1024];
	char *errormsg = NULL;

	if (users[userid].remote_forward_connected != 1) {
		DEBUG(2, "tunnel_tcp: user %d TCP socket not connected!", userid);
		return 0;
	}

	len = read(users[userid].remote_tcp_fd, buf, sizeof(buf));

	DEBUG(5, "read %ld bytes on TCP", len);
	if (len == 0) {
		DEBUG(1, "EOF on TCP forward for user %d; closing connection.", userid);
		errormsg = "Connection closed by remote host.";
		user_send_tcp_disconnect(userid, NULL, errormsg);
		return -1;
	} else if (len < 0) {
		errormsg = strerror(errno);
		DEBUG(1, "Error %d on TCP forward for user %d: %s", errno, userid, errormsg);
		user_send_tcp_disconnect(userid, NULL, errormsg);
		return -1;
	}

	user_send_data(userid, buf, (size_t) len, 0);
	return len;
}

static int
tunnel_tun()
{
	struct ip *header;
	static uint8_t in[64*1024];
	int userid;
	int read;

	if ((read = read_tun(server.tun_fd, in, sizeof(in))) <= 0)
		return 0;

	/* find target ip in packet, in is padded with 4 bytes TUN header */
	header = (struct ip*) (in + 4);
	userid = find_user_by_ip(header->ip_dst.s_addr);
	if (userid < 0)
		return 0;

	DEBUG(3, "IN: %d byte pkt from tun to user %d; compression %d",
				read, userid, users[userid].down_compression);

	return user_send_data(userid, in, read, 0);
}

static int
tunnel_dns(int dns_fd)
{
	struct query q;
	int read;
	int domain_len;
	int inside_topdomain = 0;

	if ((read = read_dns(dns_fd, &q)) <= 0)
		return 0;

	DEBUG(3, "RX: client %s ID %5d, type %d, name %s",
			format_addr(&q.from, q.fromlen), q.id, q.type, q.name);

	domain_len = strlen(q.name) - strlen(server.topdomain);
	if (domain_len >= 0 && !strcasecmp(q.name + domain_len, server.topdomain))
		inside_topdomain = 1;
	/* require dot before topdomain */
	if (domain_len >= 1 && q.name[domain_len - 1] != '.')
		inside_topdomain = 0;

	if (inside_topdomain) {
		/* This is a query we can handle */

		/* Handle A-type query for ns.topdomain, possibly caused
		   by our proper response to any NS request */
		if (domain_len == 3 && q.type == T_A &&
		    (q.name[0] == 'n' || q.name[0] == 'N') &&
		    (q.name[1] == 's' || q.name[1] == 'S') &&
		     q.name[2] == '.') {
			handle_a_request(dns_fd, &q, 0);
			return 0;
		}

		/* Handle A-type query for www.topdomain, for anyone that's
		   poking around */
		if (domain_len == 4 && q.type == T_A &&
		    (q.name[0] == 'w' || q.name[0] == 'W') &&
		    (q.name[1] == 'w' || q.name[1] == 'W') &&
		    (q.name[2] == 'w' || q.name[2] == 'W') &&
		     q.name[3] == '.') {
			handle_a_request(dns_fd, &q, 1);
			return 0;
		}

		switch (q.type) {
		case T_NULL:
		case T_PRIVATE:
		case T_CNAME:
		case T_A:
		case T_MX:
		case T_SRV:
		case T_TXT:
		case T_PTR:
		case T_AAAA:
		case T_A6:
		case T_DNAME:
			/* encoding is "transparent" here */
			handle_null_request(dns_fd, &q, domain_len);
			break;
		case T_NS:
			handle_ns_request(dns_fd, &q);
			break;
		default:
			break;
		}
	} else {
		/* Forward query to other port ? */
		DEBUG(2, "Requested domain outside our topdomain.");
		if (server.bind_fd) {
			forward_query(server.bind_fd, &q);
		}
	}
	return 0;
}

int
server_tunnel()
{
	struct timeval tv;
	fd_set read_fds, write_fds;
	int i;
	int userid;
	struct query *answer_now = NULL;
	time_t last_action = time(NULL);

	window_debug = server.debug;

	while (server.running) {
		int maxfd;
		/* max wait time based on pending queries */
		tv = qmem_max_wait(&userid, &answer_now);

		FD_ZERO(&read_fds);
		FD_ZERO(&write_fds);
		maxfd = 0;

		if (server.dns_fds.v4fd >= 0) {
			FD_SET(server.dns_fds.v4fd, &read_fds);
			maxfd = MAX(server.dns_fds.v4fd, maxfd);
		}
		if (server.dns_fds.v6fd >= 0) {
			FD_SET(server.dns_fds.v6fd, &read_fds);
			maxfd = MAX(server.dns_fds.v6fd, maxfd);
		}

		if (server.bind_fd) {
			/* wait for replies from real DNS */
			FD_SET(server.bind_fd, &read_fds);
			maxfd = MAX(server.bind_fd, maxfd);
		}

		/* Don't read from tun if all users have filled outpacket queues */
		if(!all_users_waiting_to_send()) {
			FD_SET(server.tun_fd, &read_fds);
			maxfd = MAX(server.tun_fd, maxfd);
		}

		/* add connected user TCP forward FDs to read set */
		maxfd = MAX(set_user_tcp_fds(&read_fds, 1), maxfd);

		/* add connectING user TCP FDs to write set */
		maxfd = MAX(set_user_tcp_fds(&write_fds, 2), maxfd);

		i = select(maxfd + 1, &read_fds, &write_fds, NULL, &tv);

		if(i < 0) {
			if (server.running)
				warn("select < 0");
			return 1;
		}

		if (i == 0) {
			if (server.max_idle_time) {
				/* only trigger the check if that's worth ( ie, no need to loop over if there
				is something to send */
				if (difftime(time(NULL), last_action) > server.max_idle_time) {
					for (userid = 0; userid < created_users; userid++) {
						last_action = (users[userid].last_pkt > last_action) ? users[userid].last_pkt : last_action;
					}
					if (difftime(time(NULL), last_action) > server.max_idle_time) {
						fprintf(stderr, "Server idle for too long, shutting down...\n");
						server.running = 0;
					}
				}
			}
		} else {
			if (FD_ISSET(server.tun_fd, &read_fds)) {
				tunnel_tun();
			}

			for (userid = 0; userid < created_users; userid++) {
				if (FD_ISSET(users[userid].remote_tcp_fd, &read_fds) && users[userid].remoteforward_addr_len > 0) {
					DEBUG(4, "tunnel_tcp called for user %d", userid);
					tunnel_tcp(userid);
				} else if (users[userid].remote_forward_connected == 2 &&
					FD_ISSET(users[userid].remote_tcp_fd, &write_fds)) {
					DEBUG(2, "User %d TCP socket now writable (connection established)", userid);
					users[userid].remote_forward_connected = 1;
				}
			}

			if (FD_ISSET(server.dns_fds.v4fd, &read_fds)) {
				tunnel_dns(server.dns_fds.v4fd);
			}
			if (FD_ISSET(server.dns_fds.v6fd, &read_fds)) {
				tunnel_dns(server.dns_fds.v6fd);
			}

			if (FD_ISSET(server.bind_fd, &read_fds)) {
				tunnel_bind();
			}
		}
	}

	return 0;
}

void
handle_full_packet(int userid, uint8_t *data, size_t len, int compressed)
{
	size_t rawlen;
	uint8_t out[64*1024], *rawdata;
	struct ip *hdr;
	int touser = -1;
	int ret;

	/* Check if data needs to be uncompressed */
	if (compressed) {
		rawlen = sizeof(out);
		ret = uncompress(out, &rawlen, data, len);
		rawdata = out;
	} else {
		rawlen = len;
		rawdata = data;
		ret = Z_OK;
	}

	if (ret == Z_OK) {
		if (users[userid].remoteforward_addr_len == 0) {
			hdr = (struct ip*) (out + 4);
			touser = find_user_by_ip(hdr->ip_dst.s_addr);
			DEBUG(2, "FULL PKT: %" L "u bytes from user %d (touser %d)", len, userid, touser);
			if (touser == -1) {
				/* send the uncompressed packet to tun device */
				write_tun(server.tun_fd, rawdata, rawlen);
			} else {
				/* don't re-compress if possible */
				if (users[touser].down_compression && compressed) {
					user_send_data(touser, data, len, 1);
				} else {
					user_send_data(touser, rawdata, rawlen, 0);
				}
			}
		} else {
			/* Write full pkt to user's remote forward TCP stream */
			if ((ret = write(users[userid].remote_tcp_fd, rawdata, rawlen)) != rawlen) {
				DEBUG(2, "Write error %d on TCP socket for user %d: %s", errno, userid, strerror(errno));
			}
		}

	} else {
		DEBUG(2, "Discarded pkt from user %d, uncompress()==%d, len=%" L "u, rawlen=%" L "u",
				userid, ret, len, rawlen);
	}
}

static void
handle_raw_login(uint8_t *packet, size_t len, struct query *q, int fd, int userid)
{
	char myhash[16];

	if (len < 16) {
		DEBUG(2, "Invalid raw login packet: length %" L "u < 16 bytes!", len);
		return;
	}

	if (userid < 0 || userid >= created_users ||
		check_authenticated_user_and_ip(userid, q, server.check_ip) != 0) {
		DEBUG(2, "User %d not authenticated, ignoring raw login!", userid);
		return;
	}

	DEBUG(1, "RX-raw: login, len %" L "u, from user %d", len, userid);

	/* User sends hash of seed + 1 */
	login_calculate(myhash, 16, server.password, users[userid].seed + 1);
	if (memcmp(packet, myhash, 16) == 0) {
		/* Update time info for user */
		users[userid].last_pkt = time(NULL);

		/* Store remote IP number */
		memcpy(&(users[userid].host), &(q->from), q->fromlen);
		users[userid].hostlen = q->fromlen;

		/* Correct hash, reply with hash of seed - 1 */
		user_set_conn_type(userid, CONN_RAW_UDP);
		login_calculate(myhash, 16, server.password, users[userid].seed - 1);
		send_raw(fd, (uint8_t *)myhash, 16, userid, RAW_HDR_CMD_LOGIN, &q->from, q->fromlen);

		users[userid].authenticated_raw = 1;
	}
}

static void
handle_raw_data(uint8_t *packet, size_t len, struct query *q, int userid)
{
	if (check_authenticated_user_and_ip(userid, q, server.check_ip) != 0) {
		return;
	}
	if (!users[userid].authenticated_raw) return;

	/* Update time info for user */
	users[userid].last_pkt = time(NULL);

	/* copy to packet buffer, update length */

	DEBUG(3, "RX-raw: full pkt raw, length %" L "u, from user %d", len, userid);

	handle_full_packet(userid, packet, len, 1);
}

static void
handle_raw_ping(struct query *q, int dns_fd, int userid)
{
	if (check_authenticated_user_and_ip(userid, q, server.check_ip) != 0) {
		return;
	}
	if (!users[userid].authenticated_raw) return;

	/* Update time info for user */
	users[userid].last_pkt = time(NULL);

	DEBUG(3, "RX-raw: ping from user %d", userid);

	/* Send ping reply */
	send_raw(dns_fd, NULL, 0, userid, RAW_HDR_CMD_PING, &q->from, q->fromlen);
}

static int
raw_decode(uint8_t *packet, size_t len, struct query *q, int dns_fd)
{
	int raw_user;
	uint8_t raw_cmd;

	/* minimum length */
	if (len < RAW_HDR_LEN) return 0;
	/* should start with header */
	if (memcmp(packet, raw_header, RAW_HDR_IDENT_LEN))
		return 0;

	raw_cmd = RAW_HDR_GET_CMD(packet);
	raw_user = RAW_HDR_GET_USR(packet);

	DEBUG(3, "RX-raw: client %s, user %d, raw command 0x%02X, length %" L "u",
			  format_addr(&q->from, q->fromlen), raw_user, raw_cmd, len);

	packet += RAW_HDR_LEN;
	len -= RAW_HDR_LEN;
	switch (raw_cmd) {
	case RAW_HDR_CMD_LOGIN:
		/* Login challenge */
		handle_raw_login(packet, len, q, dns_fd, raw_user);
		break;
	case RAW_HDR_CMD_DATA:
		/* Data packet */
		handle_raw_data(packet, len, q, raw_user);
		break;
	case RAW_HDR_CMD_PING:
		/* Keepalive packet */
		handle_raw_ping(q, dns_fd, raw_user);
		break;
	default:
		DEBUG(1, "Unhandled raw command %02X from user %d", raw_cmd, raw_user);
		break;
	}
	return 1;
}

int
read_dns(int fd, struct query *q)
{
	struct sockaddr_storage from;
	socklen_t addrlen;
	uint8_t packet[64*1024];
	int r;
#ifndef WINDOWS32
	char control[CMSG_SPACE(sizeof (struct in6_pktinfo))];
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsg;

	addrlen = sizeof(struct sockaddr_storage);
	iov.iov_base = packet;
	iov.iov_len = sizeof(packet);

	msg.msg_name = (caddr_t) &from;
	msg.msg_namelen = (unsigned) addrlen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	msg.msg_flags = 0;

	r = recvmsg(fd, &msg, 0);
#else
	addrlen = sizeof(struct sockaddr_storage);
	r = recvfrom(fd, packet, sizeof(packet), 0, (struct sockaddr*)&from, &addrlen);
#endif /* !WINDOWS32 */

	if (r > 0) {
		memcpy(&q->from, &from, addrlen);
		q->fromlen = addrlen;
		gettimeofday(&q->time_recv, NULL);

		/* TODO do not handle raw packets here! */
		if (raw_decode(packet, r, q, fd)) {
			return 0;
		}
		if (dns_decode(NULL, 0, q, QR_QUERY, (char *)packet, r) < 0) {
			return 0;
		}

#ifndef WINDOWS32
		memset(&q->destination, 0, sizeof(struct sockaddr_storage));
		/* Read destination IP address */
		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
			cmsg = CMSG_NXTHDR(&msg, cmsg)) {

			if (cmsg->cmsg_level == IPPROTO_IP &&
				cmsg->cmsg_type == DSTADDR_SOCKOPT) {

				struct sockaddr_in *addr = (struct sockaddr_in *) &q->destination;
				addr->sin_family = AF_INET;
				addr->sin_addr = *dstaddr(cmsg);
				q->dest_len = sizeof(*addr);
				break;
			}
			if (cmsg->cmsg_level == IPPROTO_IPV6 &&
				cmsg->cmsg_type == IPV6_PKTINFO) {

				struct in6_pktinfo *pktinfo;
				struct sockaddr_in6 *addr = (struct sockaddr_in6 *) &q->destination;
				pktinfo = (struct in6_pktinfo *) CMSG_DATA(cmsg);
				addr->sin6_family = AF_INET6;
				memcpy(&addr->sin6_addr, &pktinfo->ipi6_addr, sizeof(struct in6_addr));
				q->dest_len = sizeof(*addr);
				break;
			}
		}
#endif

		return strlen(q->name);
	} else if (r < 0) {
		/* Error */
		warn("read dns");
	}

	return 0;
}

static size_t
write_dns_nameenc(uint8_t *buf, size_t buflen, uint8_t *data, size_t datalen, char downenc)
/* Returns #bytes of data that were encoded */
{
	static int td_cmc;
	char td[3];
	struct encoder *enc;

	/* Make a rotating topdomain to prevent filtering, ie 10-bit CMC */
	td_cmc ++;
	td_cmc &= 0x3FF;

	td[0] = b32_5to8(td_cmc & 0x1F);
	td[1] = b32_5to8((td_cmc >> 5) & 0x1F);
	td[2] = 0;

	/* encode data,datalen to CNAME/MX answer */
	if (downenc == 'S') {
		buf[0] = 'i';
		enc = b64;
	} else if (downenc == 'U') {
		buf[0] = 'j';
		enc = b64u;
	} else if (downenc == 'V') {
		buf[0] = 'k';
		enc = b128;
	} else {
		buf[0] = 'h';
		enc = b32;
	}

	return build_hostname(buf, buflen, data, datalen, td, enc, 0xFF, 1);
}

void
write_dns(int fd, struct query *q, char *data, size_t datalen, char downenc)
{
	char buf[64*1024];
	int len = 0;

	if (q->type == T_CNAME || q->type == T_A ||
		q->type == T_PTR || q->type == T_AAAA || q->type == T_A6 || q->type == T_DNAME) {
		char cnamebuf[1024];		/* max 255 */

		write_dns_nameenc((uint8_t *)cnamebuf, sizeof(cnamebuf), (uint8_t *)data, datalen, downenc);

		len = dns_encode(buf, sizeof(buf), q, QR_ANSWER, cnamebuf, sizeof(cnamebuf));
	} else if (q->type == T_MX || q->type == T_SRV) {
		char mxbuf[64*1024];
		char *b = mxbuf;
		int offset = 0;
		int res;

		while (1) {
			res = write_dns_nameenc((uint8_t *)b, sizeof(mxbuf) - (b - mxbuf),
									(uint8_t *)data + offset, datalen - offset, downenc);
			if (res < 1) {
				/* nothing encoded */
				b++;	/* for final \0 */
				break;
			}

			b = b + strlen(b) + 1;

			offset += res;
			if (offset >= datalen)
				break;
		}

		/* Add final \0 */
		*b = '\0';

		len = dns_encode(buf, sizeof(buf), q, QR_ANSWER, mxbuf,
				 sizeof(mxbuf));
	} else if (q->type == T_TXT) {
		/* TXT with base32 */
		uint8_t txtbuf[64*1024];
		size_t space = sizeof(txtbuf) - 1;;

		memset(txtbuf, 0, sizeof(txtbuf));

		if (downenc == 'S') {
			txtbuf[0] = 's';	/* plain base64(Sixty-four) */
			len = b64->encode(txtbuf+1, &space, (uint8_t *)data, datalen);
		}
		else if (downenc == 'U') {
			txtbuf[0] = 'u';	/* Base64 with Underscore */
			len = b64u->encode(txtbuf+1, &space, (uint8_t *)data, datalen);
		}
		else if (downenc == 'V') {
			txtbuf[0] = 'v';	/* Base128 */
			len = b128->encode(txtbuf+1, &space, (uint8_t *)data, datalen);
		}
		else if (downenc == 'R') {
			txtbuf[0] = 'r';	/* Raw binary data */
			len = MIN(datalen, sizeof(txtbuf) - 1);
			memcpy(txtbuf + 1, data, len);
		} else {
			txtbuf[0] = 't';	/* plain base32(Thirty-two) */
			len = b32->encode(txtbuf+1, &space, (uint8_t *)data, datalen);
		}
		len = dns_encode(buf, sizeof(buf), q, QR_ANSWER, (char *)txtbuf, len+1);
	} else {
		/* Normal NULL-record encode */
		len = dns_encode(buf, sizeof(buf), q, QR_ANSWER, data, datalen);
	}

	if (len < 1) {
		warnx("dns_encode doesn't fit");
		return;
	}

	DEBUG(3, "TX: client %s ID %5d, %" L "u bytes data, type %d, name '%10s'",
			format_addr(&q->from, q->fromlen), q->id, datalen, q->type, q->name);

	sendto(fd, buf, len, 0, (struct sockaddr*)&q->from, q->fromlen);
}

#define CHECK_LEN(l, x) \
	if (l < x) { \
		write_dns(dns_fd, q, "BADLEN", 6, 'T'); \
		return; \
	}

void
handle_dns_version(int dns_fd, struct query *q, uint8_t *domain, int domain_len)
{
	uint8_t unpacked[512];
	uint32_t version = !PROTOCOL_VERSION;
	int userid, read;

	read = unpack_data(unpacked, sizeof(unpacked), (uint8_t *)domain + 1, domain_len - 1, b32);
	/* Version greeting, compare and send ack/nak */
	if (read >= 4) {
		/* Received V + 32bits version (network byte order) */
		version = ntohl(*(uint32_t *) unpacked);
	} /* if invalid pkt, just send VNAK */

	if (version != PROTOCOL_VERSION) {
		send_version_response(dns_fd, VERSION_NACK, PROTOCOL_VERSION, 0, q);
		syslog(LOG_INFO, "dropped user from %s, sent bad version %08X",
			   format_addr(&q->from, q->fromlen), version);
		return;
	}

	userid = find_available_user();
	if (userid < 0) {
		/* No space for another user */
		send_version_response(dns_fd, VERSION_FULL, created_users, 0, q);
		syslog(LOG_INFO, "dropped user from %s, server full",
		format_addr(&q->from, q->fromlen));
		return;
	}

	/* Reset user options to safe defaults */
	struct tun_user *u = &users[userid];
	u->seed = rand();
	/* Store remote IP number */
	memcpy(&(u->host), &(q->from), q->fromlen);
	u->hostlen = q->fromlen;
	u->remote_forward_connected = 0;
	u->remoteforward_addr_len = 0;
	u->remote_tcp_fd = 0;
	u->remoteforward_addr.ss_family = AF_UNSPEC;
	u->fragsize = 100; /* very safe */
	u->conn = CONN_DNS_NULL;
	u->encoder = get_base32_encoder();
	u->down_compression = 1;
	u->lazy = 0;
	u->next_upstream_ack = -1;
	window_buffer_resize(u->outgoing, u->outgoing->length,
			u->encoder->get_raw_length(u->fragsize) - DOWNSTREAM_PING_HDR);
	window_buffer_clear(u->incoming);
	qmem_init(userid);

	if (q->type == T_NULL || q->type == T_PRIVATE) {
		u->downenc = 'R';
		u->downenc_bits = 8;
	} else {
		u->downenc = 'T';
		u->downenc_bits = 5;
	}

	send_version_response(dns_fd, VERSION_ACK, u->seed, userid, q);

	syslog(LOG_INFO, "Accepted version for user #%d from %s",
		userid, format_addr(&q->from, q->fromlen));

	DEBUG(1, "User %d connected with correct version from %s.",
				userid, format_addr(&q->from, q->fromlen));
	DEBUG(3, "User %d has login challenge 0x%08x", userid, u->seed);
}

void
handle_dns_downstream_codec_check(int dns_fd, struct query *q, uint8_t *domain, int domain_len)
{
	char *datap;
	int datalen, i, codec;

	i = b32_8to5(domain[2]); /* check variant: second char in b32 */

	if (i == 1) {
		datap = DOWNCODECCHECK1;
		datalen = DOWNCODECCHECK1_LEN;
	} else {
		write_dns(dns_fd, q, "BADLEN", 6, 'T');
		return;
	}

	/* codec to test: first char raw */
	codec = toupper(domain[1]);
	switch (codec) {
		case 'T':
		case 'S':
		case 'U':
		case 'V':
			if (q->type == T_TXT ||
				q->type == T_SRV || q->type == T_MX ||
				q->type == T_CNAME || q->type == T_A ||
				q->type == T_PTR || q->type == T_AAAA ||
				q->type == T_A6 || q->type == T_DNAME) {
				write_dns(dns_fd, q, datap, datalen, codec);
				return;
			}
			break;
		case 'R':
			if (q->type == T_NULL || q->type == T_TXT) {
				write_dns(dns_fd, q, datap, datalen, 'R');
				return;
			}
			break;
	}

	/* if still here, then codec not available */
	write_dns(dns_fd, q, "BADCODEC", 8, 'T');
}

void
handle_dns_login(int dns_fd, struct query *q, uint8_t *domain, int domain_len, int userid)
{
	uint8_t unpacked[512], flags;
	char logindata[16], *tmp[2], out[512], *reason = NULL;
	char *errormsg = NULL, fromaddr[100];
	struct in_addr tempip;
	char remote_tcp, remote_isnt_localhost, use_ipv6, poll_status; //, drop_packets;
	int length = 17, read, addrlen, login_ok = 1;
	uint16_t port;
	struct tun_user *u = &users[userid];
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) &u->remoteforward_addr;
	struct sockaddr_in *addr = (struct sockaddr_in *) &u->remoteforward_addr;

	read = unpack_data(unpacked, sizeof(unpacked), (uint8_t *) domain + 2, domain_len - 2, b32);

	/* Decode flags and calculate min. length */
	flags = unpacked[0];
	remote_tcp = flags & 1;
	remote_isnt_localhost = (flags & 2) >> 1;
	use_ipv6 = (flags & 4) >> 2;
	//drop_packets = (flags & 8) >> 3; /* currently unimplemented */
	poll_status = (flags & 0x10) >> 4;
	addrlen = (remote_tcp && remote_isnt_localhost) ? (use_ipv6 ? 16 : 4) : 0;

	length += (remote_tcp ? 2 : 0) + addrlen;

	/* There should be no extra data if only polling forwarding status */
	if (poll_status) {
		length = 17;
	}

	CHECK_LEN(read, length);

	strncpy(fromaddr, format_addr(&q->from, q->fromlen), 100);

	DEBUG(2, "Received login request for user %d from %s",
				userid, fromaddr);

	DEBUG(6, "Login: length=%d, flags=0x%02x, seed=0x%08x, hash=0x%016llx%016llx",
			  length, flags, u->seed, *(unsigned long long *) (unpacked + 1),
			  *(unsigned long long *) (unpacked + 9));

	if (check_user_and_ip(userid, q, server.check_ip) != 0) {
		write_dns(dns_fd, q, "BADIP", 5, 'T');
		syslog(LOG_WARNING, "rejected login request from user #%d from %s; expected source %s",
			userid, fromaddr, format_addr(&u->host, u->hostlen));
		DEBUG(1, "Rejected login request from user %d: BADIP", userid);
		return;
	}

	/* Check remote host/port options */
	if ((addrlen > 0 && !server.allow_forward_remote) ||
		(remote_tcp && !server.allow_forward_local_port)) {
		login_ok = 0;
		reason = "requested bad TCP forward options";
	}

	u->last_pkt = time(NULL);
	login_calculate(logindata, 16, server.password, u->seed);

	if (memcmp(logindata, unpacked + 1, 16) != 0) {
		login_ok = 0;
		reason = "bad password";
	}

	if (remote_tcp) {
		port = ntohs(*(uint16_t *) (unpacked + 17));
		if (addrlen > 0) {
			if (use_ipv6) {
				addr6->sin6_family = AF_INET6;
				addr6->sin6_port = htons(port);
				u->remoteforward_addr_len = sizeof(*addr6);
				memcpy(&addr6->sin6_addr, unpacked + 19, MIN(sizeof(*addr6), addrlen));
			} else {
				addr->sin_family = AF_INET;
				addr->sin_port = htons(port);
				u->remoteforward_addr_len = sizeof(*addr);
				memcpy(&addr->sin_addr, unpacked + 19, MIN(sizeof(*addr), addrlen));
			}

			DEBUG(1, "User %d requested TCP connection to %s:%hu, %s.", userid,
				  format_addr(&u->remoteforward_addr, u->remoteforward_addr_len),
				  port, login_ok ? "allowed" : "rejected");
		} else {
			addr->sin_family = AF_INET;
			addr->sin_port = htons(port);
			addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			DEBUG(1, "User %d requested TCP connection to localhost:%hu, %s.", userid,
				  port, login_ok ? "allowed" : "rejected");
		}
	}

	if (poll_status && login_ok) {
		if (addrlen > 0 || (flags ^ 0x10)) {
			login_ok = 0;
			reason = "invalid flags";
		}
	}

	if (!login_ok) {
		write_dns(dns_fd, q, "LNAK", 4, 'T');
		if (--u->authenticated >= 0)
			u->authenticated = -1;
		int tries = abs(u->authenticated);
		DEBUG(1, "rejected login from user %d (%s), tries: %d, reason: %s",
			  userid, fromaddr, tries, reason);
		syslog(LOG_WARNING, "rejected login request from user #%d from %s, %s; incorrect attempts: %d",
			userid, fromaddr, reason, tries);
		return;
	}

	/* Store user auth OK, count number of logins */
	u->authenticated++;
	if (u->authenticated > 1 && !poll_status)
		syslog(LOG_WARNING, "duplicate login request from user #%d from %s",
			   userid, fromaddr);

	if (remote_tcp) {
		int tcp_fd;

		DEBUG(1, "User %d connected from %s, starting TCP connection to %s.", userid,
			  fromaddr, format_addr(&u->remoteforward_addr, sizeof(struct sockaddr_storage)));
		syslog(LOG_NOTICE, "accepted password from user #%d, connecting TCP forward", userid);

		/* Open socket and connect to TCP forward host:port */
		tcp_fd = open_tcp_nonblocking(&u->remoteforward_addr, &errormsg);
		if (tcp_fd < 0) {
			if (!errormsg)
				errormsg = "Error opening socket.";
			goto tcp_forward_error;
		}

		/* connection in progress */
		out[0] = 'W';
		read = 1;
		write_dns(dns_fd, q, out, read + 1, u->downenc);
		u->remote_tcp_fd = tcp_fd;
		u->remote_forward_connected = 2; /* connecting */
		return;
	} else if (poll_status) {
		/* Check TCP forward connection status and update user data */
		int retval;

		/* Check for connection errors */
		if ((retval = check_tcp_error(u->remote_tcp_fd, &errormsg)) != 0) {
			/* if unacceptable error, tell user */
			if (retval != EINPROGRESS)
				goto tcp_forward_error;
		}

		if (retval == EINPROGRESS)
			u->remote_forward_connected = 2;

		read = 1;
		out[1] = 0;

		/* check user TCP forward status flag, which is updated in server_tunnel
		 * when the file descriptor becomes writable (ie, connection established */
		if (u->remote_forward_connected == 1) {
			out[0] = 'C';
			DEBUG(2, "User %d TCP forward connection established: %s", userid, errormsg);
		} else if (u->remote_forward_connected == 2) {
			out[0] = 'W';
			DEBUG(3, "User %d TCP connection in progress: %s", userid, errormsg);
		}

		write_dns(dns_fd, q, out, read + 1, u->downenc);
		return;
	} else {
		out[0] = 'I';

		/* Send ip/mtu/netmask info */
		tempip.s_addr = server.my_ip;
		tmp[0] = strdup(inet_ntoa(tempip));
		tempip.s_addr = u->tun_ip;
		tmp[1] = strdup(inet_ntoa(tempip));

		read = snprintf(out + 1, sizeof(out) - 1, "-%s-%s-%d-%d",
						tmp[0], tmp[1], server.mtu, server.netmask);

		DEBUG(1, "User %d connected from %s, tun_ip %s.", userid,
			  fromaddr, tmp[1]);
		syslog(LOG_NOTICE, "accepted password from user #%d, given IP %s", userid, tmp[1]);

		free(tmp[1]);
		free(tmp[0]);
		write_dns(dns_fd, q, out, read + 1, u->downenc);
		return;
	}
tcp_forward_error:
	DEBUG(1, "Failed to connect TCP forward for user %d: %s", userid, errormsg);
	out[0] = 'E';
	strncpy(out + 1, errormsg, sizeof(out) - 1);
	read = strlen(out);
	write_dns(dns_fd, q, out, read + 1, u->downenc);
}

void
handle_dns_ip_request(int dns_fd, struct query *q, int userid)
{
	char reply[17];
	int length;
	reply[0] = 'I';
	if (q->from.ss_family == AF_INET) {
		if (server.ns_ip != INADDR_ANY) {
			/* If set, use assigned external ip (-n option) */
			memcpy(&reply[1], &server.ns_ip, sizeof(server.ns_ip));
		} else {
			/* otherwise return destination ip from packet */
			struct sockaddr_in *addr = (struct sockaddr_in *) &q->destination;
			memcpy(&reply[1], &addr->sin_addr, sizeof(struct in_addr));
		}
		length = 1 + sizeof(struct in_addr);
	} else {
		struct sockaddr_in6 *addr = (struct sockaddr_in6 *) &q->destination;
		memcpy(&reply[1], &addr->sin6_addr, sizeof(struct in6_addr));
		length = 1 + sizeof(struct in6_addr);
	}

	write_dns(dns_fd, q, reply, length, 'T');
}

void
handle_dns_upstream_codec_switch(int dns_fd, struct query *q, int userid,
								 uint8_t *unpacked, size_t read)
{
	int codec;
	struct encoder *enc;

	codec = unpacked[0];

	switch (codec) {
	case 5: /* 5 bits per byte = base32 */
		enc = b32;
		user_switch_codec(userid, enc);
		write_dns(dns_fd, q, enc->name, strlen(enc->name), users[userid].downenc);
		break;
	case 6: /* 6 bits per byte = base64 */
		enc = b64;
		user_switch_codec(userid, enc);
		write_dns(dns_fd, q, enc->name, strlen(enc->name), users[userid].downenc);
		break;
	case 26: /* "2nd" 6 bits per byte = base64u, with underscore */
		enc = b64u;
		user_switch_codec(userid, enc);
		write_dns(dns_fd, q, enc->name, strlen(enc->name), users[userid].downenc);
		break;
	case 7: /* 7 bits per byte = base128 */
		enc = b128;
		user_switch_codec(userid, enc);
		write_dns(dns_fd, q, enc->name, strlen(enc->name), users[userid].downenc);
		break;
	default:
		write_dns(dns_fd, q, "BADCODEC", 8, users[userid].downenc);
		break;
	}
}

void
handle_dns_set_options(int dns_fd, struct query *q, int userid,
					   uint8_t *unpacked, size_t read)
{
	uint8_t bits = 0;
	char *encname = "BADCODEC";

	int tmp_lazy, tmp_downenc, tmp_comp;

	/* Temporary variables: don't change anything until all options parsed */
	tmp_lazy = users[userid].lazy;
	tmp_comp = users[userid].down_compression;
	tmp_downenc = users[userid].downenc;

	switch (unpacked[0] & 0x7C) {
	case (1 << 6): /* Base32 */
		tmp_downenc = 'T';
		encname = "Base32";
		bits = 5;
		break;
	case (1 << 5): /* Base64 */
		tmp_downenc = 'S';
		encname = "Base64";
		bits = 6;
		break;
	case (1 << 4): /* Base64u */
		tmp_downenc = 'U';
		encname = "Base64u";
		bits = 26;
		break;
	case (1 << 3): /* Base128 */
		tmp_downenc = 'V';
		encname = "Base128";
		bits = 7;
		break;
	case (1 << 2): /* Raw */
		tmp_downenc = 'R';
		encname = "Raw";
		bits = 8;
		break;
	default: /* Invalid (More than 1 encoding bit set) */
		write_dns(dns_fd, q, "BADCODEC", 8, users[userid].downenc);
		return;
	}

	tmp_comp = (unpacked[0] & 2) >> 1; /* compression flag */
	tmp_lazy = (unpacked[0] & 1); /* lazy mode flag */

	/* Automatically switch to raw encoding if PRIVATE or NULL request */
	if ((q->type == T_NULL || q->type == T_PRIVATE) && !bits) {
		users[userid].downenc = 'R';
		bits = 8;
		DEBUG(2, "Assuming raw data encoding with NULL/PRIVATE requests for user %d.", userid);
	}
	if (bits) {
		int f = users[userid].fragsize;
		window_buffer_resize(users[userid].outgoing, users[userid].outgoing->length,
				(bits * f) / 8 - DOWNSTREAM_PING_HDR);
		users[userid].downenc_bits = bits;
	}

	DEBUG(1, "Options for user %d: down compression %d, data bits %d/maxlen %u (enc '%c'), lazy %d.",
		  userid, tmp_comp, bits, users[userid].outgoing->maxfraglen, tmp_downenc, tmp_lazy);

	/* Store any changes */
	users[userid].down_compression = tmp_comp;
	users[userid].downenc = tmp_downenc;
	users[userid].lazy = tmp_lazy;

	write_dns(dns_fd, q, encname, strlen(encname), users[userid].downenc);
}

void
handle_dns_fragsize_probe(int dns_fd, struct query *q, int userid,
						  uint8_t *unpacked, size_t read)
/* Downstream fragsize probe packet */
{
	int req_frag_size;

	req_frag_size = ntohs(*(uint16_t *) unpacked);
	DEBUG(3, "Got downstream fragsize probe from user %d, required fragsize %d", userid, req_frag_size);

	if (req_frag_size < 2 || req_frag_size > MAX_FRAGSIZE) {
		write_dns(dns_fd, q, "BADFRAG", 7, users[userid].downenc);
	} else {
		char buf[MAX_FRAGSIZE];
		int i;
		unsigned int v = ((unsigned int) rand()) & 0xff;

		memset(buf, 0, sizeof(buf));
		buf[0] = (req_frag_size >> 8) & 0xff;
		buf[1] = req_frag_size & 0xff;
		/* make checkable pseudo-random sequence */
		buf[2] = 107;
		for (i = 3; i < MAX_FRAGSIZE; i++, v = (v + 107) & 0xff)
			buf[i] = v;
		write_dns(dns_fd, q, buf, req_frag_size, users[userid].downenc);
	}
}

void
handle_dns_set_fragsize(int dns_fd, struct query *q, int userid,
						uint8_t *unpacked, size_t read)
	/* Downstream fragsize packet */
{
	int max_frag_size;
	max_frag_size = ntohs(*(uint16_t *)unpacked);

	if (max_frag_size < 2 || max_frag_size > MAX_FRAGSIZE) {
		write_dns(dns_fd, q, "BADFRAG", 7, users[userid].downenc);
	} else {
		users[userid].fragsize = max_frag_size;
		window_buffer_resize(users[userid].outgoing, users[userid].outgoing->length,
				(users[userid].downenc_bits * max_frag_size) / 8 - DOWNSTREAM_PING_HDR);
		write_dns(dns_fd, q, (char *)unpacked, 2, users[userid].downenc);

		DEBUG(1, "Setting max downstream data length to %u bytes for user %d; %d bits (%c)",
			  users[userid].outgoing->maxfraglen, userid, users[userid].downenc_bits, users[userid].downenc);
	}
}

void
handle_dns_ping(int dns_fd, struct query *q, int userid,
				uint8_t *unpacked, size_t read)
{
	int dn_seq, up_seq, dn_winsize, up_winsize, dn_ack;
	int respond, set_qtimeout, set_wtimeout, tcp_disconnect;
	unsigned qtimeout_ms, wtimeout_ms;

	CHECK_LEN(read, UPSTREAM_PING);

	/* Check if query is cached */
	if (qmem_is_cached(dns_fd, userid, q))
		return;

	/* Unpack flags/options from ping header */
	dn_ack = ((unpacked[9] >> 2) & 1) ? unpacked[0] : -1;
	up_winsize = unpacked[1];
	dn_winsize = unpacked[2];
	up_seq = unpacked[3];
	dn_seq = unpacked[4];

	/* Query timeout and window frag timeout */
	qtimeout_ms = ntohs(*(uint16_t *) (unpacked + 5));
	wtimeout_ms = ntohs(*(uint16_t *) (unpacked + 7));
	respond = unpacked[9] & 1;
	set_qtimeout = (unpacked[9] >> 3) & 1;
	set_wtimeout = (unpacked[9] >> 4) & 1;
	tcp_disconnect = (unpacked[9] >> 5) & 1;

	DEBUG(3, "PING pkt user %d, down %d/%d, up %d/%d, ACK %d, %sqtime %u ms, "
		  "%swtime %u ms, respond %d, tcp_close %d (flags %02X)",
				userid, dn_seq, dn_winsize, up_seq, up_winsize, dn_ack,
				set_qtimeout ? "SET " : "", qtimeout_ms, set_wtimeout ? "SET " : "",
				wtimeout_ms, respond, tcp_disconnect, unpacked[9]);

	if (tcp_disconnect) {
		/* close user's TCP forward connection and mark user as inactive */
		if (users[userid].remoteforward_addr_len == 0) {
			DEBUG(1, "User %d attempted TCP disconnect but didn't request TCP forwarding!", userid);
		} else {
			DEBUG(1, "User %d closed remote TCP forward", userid);
			close_socket(users[userid].remote_tcp_fd);
			users[userid].active = 0;
		}
	}

	if (set_qtimeout) {
		/* update user's query timeout if timeout flag set */
		users[userid].dns_timeout = ms_to_timeval(qtimeout_ms);

		/* if timeout is 0, we do not enable lazy mode but it is effectively the same */
		int newlazy = !(qtimeout_ms == 0);
		if (newlazy != users[userid].lazy)
			DEBUG(2, "User %d: not changing lazymode to %d with timeout %u",
				  userid, newlazy, qtimeout_ms);
	}

	if (set_wtimeout) {
		/* update sending window fragment ACK timeout */
		users[userid].outgoing->timeout = ms_to_timeval(wtimeout_ms);
	}

	qmem_append(userid, q);

	if (respond) {
		/* ping handshake - set windowsizes etc, respond NOW using this query
		 * NOTE: still added to qmem (for cache) even though responded to immediately */
		DEBUG(2, "PING HANDSHAKE set windowsizes (old/new) up: %d/%d, dn: %d/%d",
			  users[userid].outgoing->windowsize, dn_winsize, users[userid].incoming->windowsize, up_winsize);
		users[userid].outgoing->windowsize = dn_winsize;
		users[userid].incoming->windowsize = up_winsize;
		send_data_or_ping(userid, q, 1, 1, NULL);
		return;
	}

	/* if respond flag not set, query waits in qmem and is used later */
	user_process_incoming_data(userid, dn_ack);
}

void
handle_dns_data(int dns_fd, struct query *q, uint8_t *domain, int domain_len, int userid)
{
	uint8_t unpacked[20];
	fragment f;
	size_t len;

	/* Need 6 char header + >=1 char data */
	CHECK_LEN(domain_len, UPSTREAM_HDR + 1);

	/* Check if cached */
	if (qmem_is_cached(dns_fd, userid, q)) {
		/* if is cached, by this point it has already been answered */
		return;
	}

	qmem_append(userid, q);
	/* Decode upstream data header - see docs/proto_XXXXXXXX.txt */
	/* First byte (after userid) = CMC (ignored); skip 2 bytes */
	len = sizeof(unpacked);
	b32->decode(unpacked, &len, (uint8_t *)domain + 2, 5);

	f.seqID = unpacked[0];
	unpacked[2] >>= 4; /* Lower 4 bits are unused */
	f.ack_other = ((unpacked[2] >> 3) & 1) ? unpacked[1] : -1;
	f.compressed = (unpacked[2] >> 2) & 1;
	f.start = (unpacked[2] >> 1) & 1;
	f.end = unpacked[2] & 1;

	uint8_t data[users[userid].incoming->maxfraglen];
	f.data = data;

	/* Decode remainder of data with user encoding into fragment */
	f.len = unpack_data(f.data, users[userid].incoming->maxfraglen,
				(uint8_t *)domain + UPSTREAM_HDR,
				domain_len - UPSTREAM_HDR, users[userid].encoder);

	DEBUG(3, "frag seq %3u, datalen %5lu, ACK %3d, compression %1d, s%1d e%1d",
				f.seqID, f.len, f.ack_other, f.compressed, f.start, f.end);

	/* if already waiting for an ACK to be sent back upstream (on incoming buffer) */
	if (users[userid].next_upstream_ack >= 0) {
		/* Shouldn't normally happen; will always be reset after sending a packet. */
		DEBUG(1, "[WARNING] next_upstream_ack == %d for user %d.",users[userid].next_upstream_ack, userid);
	}

	window_process_incoming_fragment(users[userid].incoming, &f);
	users[userid].next_upstream_ack = f.seqID;

	user_process_incoming_data(userid, f.ack_other);

	/* Nothing to do. ACK for this fragment is sent later in qmem_max_wait,
	 * using an old query. This is left in qmem until needed/times out */
}

void
handle_null_request(int dns_fd, struct query *q, int domain_len)
/* Handles a NULL DNS request. See doc/proto_XXXXXXXX.txt for details on iodine protocol. */
{
	char cmd, userchar;
	int userid = -1;
	uint8_t in[QUERY_NAME_SIZE + 1];

	/* Everything here needs at least 5 chars in the name:
	 * cmd, userid and more data or at least 3 bytes CMC */
	if (domain_len < 5)
		return;

	/* Duplicate domain name to prevent changing original query */
	memcpy(in, q->name, QUERY_NAME_SIZE + 1);
	in[QUERY_NAME_SIZE] = 0; /* null terminate */

	cmd = toupper(in[0]);
	DEBUG(3, "NULL request length %d/%" L "u, command '%c'", domain_len, sizeof(in), cmd);

	/* Commands that do not care about userid: also these need to be backwards
	 * compatible with older versions of iodine (at least down to 00000502) */
	if (cmd == 'V') { /* Version check - before userid is assigned*/
		handle_dns_version(dns_fd, q, in, domain_len);
		return;
	}
	else if (cmd == 'Z') { /* Upstream codec check - user independent */
		/* Reply with received hostname as data (encoded in base32) */
		write_dns(dns_fd, q, (char *)in, domain_len, 'T');
		return;
	}
	else if (cmd == 'Y') { /* Downstream codec check - user independent */
		handle_dns_downstream_codec_check(dns_fd, q, in, domain_len);
		return;
	}

	/* Get userid from query (always 2nd byte in hex except for data packets) */
	if (isxdigit(cmd)) {
		/* Upstream data packet - first byte is userid in hex */
		userchar = cmd;
		cmd = 'd'; /* flag for data packet - not part of protocol */
	} else {
		userchar = toupper(in[1]);
	}

	if (isxdigit(userchar)) {
		userid = (userchar >= 'A' && userchar <= 'F') ?
			(userchar - 'A' + 10) : (userchar - '0');
	} else {
		/* Invalid user ID or bad DNS query */
		write_dns(dns_fd, q, "BADLEN", 5, 'T');
	}

	/* Login request - after version check successful, do not check auth yet */
	if (cmd == 'L') {
		handle_dns_login(dns_fd, q, in, domain_len, userid);
		return;
	}

	/* Check user IP and authentication status */
	if (check_authenticated_user_and_ip(userid, q, server.check_ip) != 0) {
		write_dns(dns_fd, q, "BADIP", 5, 'T');
		return;
	}

	if (cmd == 'd') { /* Upstream data packet */
		handle_dns_data(dns_fd, q, in, domain_len, userid);
		return;
	} else if (cmd == 'I') { /* IP request packet - no base32 data */
		handle_dns_ip_request(dns_fd, q, userid);
	}

	/* Following commands have everything after cmd and userid in base32
	 *  All bytes that are not valid base32 are decoded to 0 */

	uint8_t unpacked[512];
	size_t raw_len;
	raw_len = unpack_data(unpacked, sizeof(unpacked), (uint8_t *)in + 2, domain_len - 2, b32);
	if (raw_len < 3) /* always at least 3 bytes after decoding at least 5 bytes */
		return; /* Just in case. */

	switch (cmd) {
		case 'S':
			handle_dns_upstream_codec_switch(dns_fd, q, userid, unpacked, raw_len);
			break;
		case 'O':
			handle_dns_set_options(dns_fd, q, userid, unpacked, raw_len);
			break;
		case 'R':
			handle_dns_fragsize_probe(dns_fd, q, userid, unpacked, raw_len);
			break;
		case 'N':
			handle_dns_set_fragsize(dns_fd, q, userid, unpacked, raw_len);
			break;
		case 'P':
			handle_dns_ping(dns_fd, q, userid, unpacked, raw_len);
			break;
		default:
			DEBUG(2, "Invalid DNS query! cmd = %c, hostname = '%*s'",
				  cmd, domain_len, in);
	}
}

void
handle_ns_request(int dns_fd, struct query *q)
/* Mostly identical to handle_a_request() below */
{
	char buf[64*1024];
	int len;

	if (server.ns_ip != INADDR_ANY) {
		/* If ns_ip set, overwrite destination addr with it.
		 * Destination addr will be sent as additional record (A, IN) */
		struct sockaddr_in *addr = (struct sockaddr_in *) &q->destination;
		memcpy(&addr->sin_addr, &server.ns_ip, sizeof(server.ns_ip));
	}

	len = dns_encode_ns_response(buf, sizeof(buf), q, server.topdomain);
	if (len < 1) {
		warnx("dns_encode_ns_response doesn't fit");
		return;
	}

	DEBUG(2, "TX: NS reply client %s ID %5d, type %d, name %s, %d bytes",
			format_addr(&q->from, q->fromlen), q->id, q->type, q->name, len);
	if (sendto(dns_fd, buf, len, 0, (struct sockaddr*)&q->from, q->fromlen) <= 0) {
		warn("ns reply send error");
	}
}

void
handle_a_request(int dns_fd, struct query *q, int fakeip)
/* Mostly identical to handle_ns_request() above */
{
	char buf[64*1024];
	int len;

	if (fakeip) {
		in_addr_t ip = inet_addr("127.0.0.1");
		struct sockaddr_in *addr = (struct sockaddr_in *) &q->destination;
		memcpy(&addr->sin_addr, &ip, sizeof(ip));

	} else if (server.ns_ip != INADDR_ANY) {
		/* If ns_ip set, overwrite destination addr with it.
		 * Destination addr will be sent as additional record (A, IN) */
		struct sockaddr_in *addr = (struct sockaddr_in *) &q->destination;
		memcpy(&addr->sin_addr, &server.ns_ip, sizeof(server.ns_ip));
	}

	len = dns_encode_a_response(buf, sizeof(buf), q);
	if (len < 1) {
		warnx("dns_encode_a_response doesn't fit");
		return;
	}

	DEBUG(2, "TX: A reply client %s ID %5d, type %d, name %s, %d bytes",
			format_addr(&q->from, q->fromlen), q->id, q->type, q->name, len);
	if (sendto(dns_fd, buf, len, 0, (struct sockaddr*)&q->from, q->fromlen) <= 0) {
		warn("a reply send error");
	}
}
