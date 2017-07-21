/*
 * Copyright (c) 2006-2014 Erik Ekman <yarrick@kryo.se>,
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

#ifndef __USER_H__
#define __USER_H__

#include "window.h"
#include "server.h"

#define USERS 16

struct tun_user {
	uint8_t server_chall[16];
	uint8_t hmac_key[16];
	struct timeval dns_timeout;
	struct sockaddr_storage host;
	struct sockaddr_storage remoteforward_addr;
	struct frag_buffer *incoming;
	struct frag_buffer *outgoing;
	struct encoder *encoder;
	struct qmem_buffer qmem; // TODO dynamic allocation
	size_t fragsize;
	socklen_t hostlen;
	socklen_t remoteforward_addr_len; /* 0 if no remote forwarding enabled */
	time_t last_pkt;
	in_addr_t tun_ip;
	uint32_t cmc_up;
	uint32_t cmc_down;
	int remote_tcp_fd;
	int remote_forward_connected; /* 0 if not connected, -1 if error or 1 if OK */
	int next_upstream_ack;
	enum connection conn;
	char use_hmac;
	char lazy;
	char id;
	uint8_t downenc;
	char downenc_bits;
	char down_compression;
	char active;
	char authenticated;
	char authenticated_raw;
};

extern struct tun_user *users;
extern int created_users;

int user_sending(int user);
int all_users_waiting_to_send();
int user_active(int i);
int is_valid_user(int userid);

int init_users(in_addr_t, int);
const char* users_get_first_ip();
int find_user_by_ip(uint32_t);
int find_available_user();
int set_user_tcp_fds(fd_set *fds, int);

#endif
