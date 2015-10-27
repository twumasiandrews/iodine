/*
 * Copyright (c) 2015 Frekk van Blagh <frekk@frekkworks.com>
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

#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include <err.h>
#include <string.h>
#include <stdlib.h>

#include "common.h"
#include "window.h"

int window_debug = 0;

struct frag_buffer *
window_buffer_init(size_t length, unsigned windowsize, unsigned fragsize, int dir)
{
	struct frag_buffer *buf;
	buf = calloc(sizeof(struct frag_buffer), 1);
	if (!buf) {
		errx(1, "Failed to allocate window buffer memory!");
	}
	if (dir != WINDOW_RECVING && dir != WINDOW_SENDING) {
		errx(1, "Invalid window direction!");
	}
	if (fragsize > MAX_FRAGSIZE) {
		errx(fragsize, "Fragsize too large! Please recompile with larger MAX_FRAGSIZE!");
	}

	buf->frags = calloc(length, sizeof(fragment));
	if (!buf->frags) {
		errx(1, "Failed to allocate fragment buffer!");
	}
	buf->length = length;
	buf->windowsize = windowsize;
	buf->maxfraglen = fragsize;
	buf->window_end = AFTER(buf, windowsize);
	buf->direction = dir;
	buf->timeout.tv_sec = 5;
	buf->timeout.tv_usec = 0;

	return buf;
}

void
window_buffer_reset(struct frag_buffer *w)
{
	w->chunk_start = 0;
	w->cur_seq_id = 0;
	w->last_write = 0;
	w->numitems = 0;
	w->oos = 0;
	w->resends = 0;
	w->start_seq_id = 0;
	w->window_start = 0;
	w->window_end = AFTER(w, w->windowsize);
}

void
window_buffer_resize(struct frag_buffer *w, size_t length)
{
	if (w->length == length) return;
	if (w->numitems > 0) {
		WDEBUG("Resizing window buffer with things still in it! This will cause problems!");
	}
	if (w->frags) free(w->frags);
	w->frags = calloc(length, sizeof(fragment));
	if (!w->frags) {
		errx(1, "Failed to resize window buffer!");
	}
	w->length = length;
	window_buffer_reset(w);
}

void
window_buffer_destroy(struct frag_buffer *w)
{
	if (!w) return;
	if (w->frags) free(w->frags);
	free(w);
}

void
window_buffer_clear(struct frag_buffer *w)
{
	if (!w) return;

	memset(w->frags, 0, w->length * sizeof(fragment));
	window_buffer_reset(w);
}

/* Returns number of available fragment slots (NOT BYTES) */
size_t
window_buffer_available(struct frag_buffer *w)
{
	return w->length - w->numitems;
}

/* Places a fragment in the window after the last one */
int
window_append_fragment(struct frag_buffer *w, fragment *src)
{
	if (window_buffer_available(w) < 1) return 0;
	memcpy(&w->frags[w->last_write], src, sizeof(fragment));
	w->last_write = WRAP(w->last_write + 1);
	w->numitems ++;
	return 1;
}

/* Handles fragment received from the sending side (RECV)
 * Returns index of fragment in window or <0 if dropped
 * The next ACK MUST be for this fragment */
ssize_t
window_process_incoming_fragment(struct frag_buffer *w, fragment *f)
{
	/* Check if packet is in window */
	unsigned startid, endid;
	fragment *fd;
	startid = w->start_seq_id;
	endid = (w->start_seq_id + w->windowsize) % MAX_SEQ_ID;
	if (!INWINDOW_SEQ(startid, endid, f->seqID)) {
		WDEBUG("Dropping frag with seqID %u: not in window (%u-%u)\n", f->seqID, startid, endid);
		w->oos++;
		return -1;
	}
	/* Place fragment into correct location in buffer */
	ssize_t dest = WRAP(w->window_start + SEQ_OFFSET(startid, f->seqID));
	WDEBUG("   Putting frag seq %u into frags[%lu + %u = %lu]",
		   f->seqID, w->window_start, SEQ_OFFSET(startid, f->seqID), dest);
	/* Check if fragment already received */
	fd = &w->frags[dest];
	if (fd->len != 0) {
		WDEBUG("Received duplicate frag, dropping. (prev %u/new %u)", fd->seqID, f->seqID);
		if (f->seqID == fd->seqID)
			return -1;
	}
	memcpy(fd, f, sizeof(fragment));
	w->numitems ++;

	fd->retries = 0;
	fd->ack_other = -1;

	/* We assume this packet gets ACKed immediately on return of this function */
	fd->acks = 1;

	return dest;
}

/* Reassembles first complete sequence of fragments into data. (RECV)
 * Returns length of data reassembled, or 0 if no data reassembled */
size_t
window_reassemble_data(struct frag_buffer *w, uint8_t *data, size_t maxlen, int *compression)
{
	size_t woffs, fraglen, datalen = 0;
	uint8_t *dest; //, *fdata_start;
	dest = data;
	if (w->direction != WINDOW_RECVING)
		return 0;
	if (w->frags[w->chunk_start].start == 0 && w->numitems > 0) {
		WDEBUG("chunk_start (%lu)pointing to non-start fragment (seq %u, len %lu)!",
			  w->chunk_start, w->frags[w->chunk_start].seqID, w->frags[w->chunk_start].len);
		return 0;
	}
	if (compression) *compression = 1;

	fragment *f;
	size_t i, curseq;
	int end = 0;
	curseq = w->frags[w->chunk_start].seqID;
	for (i = 0; i < w->numitems; ++i) {
		woffs = WRAP(w->chunk_start + i);
		f = &w->frags[woffs];
		fraglen = f->len;
		if (fraglen == 0 || !f->data || f->seqID != curseq) {
			WDEBUG("data missing! Not reassembling!");
			return 0;
		}

		WDEBUG("   Fragment seq %u, data length %lu, data offset %lu, total len %lu, maxlen %lu",
				f->seqID, fraglen, dest - data, datalen, maxlen);
		memcpy(dest, f->data, MIN(fraglen, maxlen));
		dest += fraglen;
		datalen += fraglen;
		if (compression) {
			*compression &= f->compressed & 1;
			if (f->compressed != *compression) {
				WDEBUG("Inconsistent compression flags in chunk. Not reassembling!");
				return 0;
			}
		}
		if (fraglen > maxlen) {
			WDEBUG("Data buffer too small! Reassembled %lu bytes.", datalen);
			return 0;
		}

		/* Move window along to avoid weird issues */
		window_tick(w);

		if (f->end == 1) {
			WDEBUG("Found end of chunk! (seqID %u, chunk len %lu, datalen %lu)", f->seqID, i, datalen);
			end = 1;
			break;
		}

		maxlen -= fraglen;
		curseq = (curseq + 1) % MAX_SEQ_ID;
	}
	if (end == 0) { /* no end of chunk found but reached end of data */
		return 0;
	}
	WDEBUG("Reassembling %lu bytes of data from %lu frags; compression %d!", datalen, i + 1, *compression);
	/* Clear all used fragments */
	size_t p;
	ITER_FORWARD(w->chunk_start, WRAP(w->chunk_start + i + 1), w->length, p,
						memset(&w->frags[p], 0, sizeof(fragment));
					);
	w->chunk_start = WRAP(woffs + 1);
	w->numitems -= i + 1;
	return datalen;
}

/* Returns number of fragments that can be sent immediately; effectively
 * the same as window_get_next_sending_fragment but without changing anything. */
size_t
window_sending(struct frag_buffer *w)
{
	struct timeval timeout, now;
	fragment *f;
	size_t tosend = 0;

	if (w->numitems == 0)
		return 0;

	gettimeofday(&now, NULL);

	for (size_t i = 0; i < w->windowsize; i++) {
		f = &w->frags[WRAP(w->window_start + i)];
		if (f->len == 0 || f->acks >= 1) continue;

		timeradd(&w->timeout, &f->lastsent, &timeout);
		if (f->retries < 1 || !timercmp(&now, &timeout, <)) {
			/* Fragment not sent or timed out (to be re-sent) */
			tosend++;
		}
	}
	return tosend;
}

/* Returns next fragment to be sent or NULL if nothing (SEND)
 * This also handles packet resends, timeouts etc. */
fragment *
window_get_next_sending_fragment(struct frag_buffer *w, int *other_ack)
{
	struct timeval timeout, now;
	fragment *f = NULL;

	if (*other_ack >= MAX_SEQ_ID || *other_ack < 0)
		*other_ack = -1;

	gettimeofday(&now, NULL);

	for (size_t i = 0; i < w->windowsize; i++) {
		f = &w->frags[WRAP(w->window_start + i)];
		if (f->acks >= 1) continue;

		timeradd(&w->timeout, &f->lastsent, &timeout);

		if (f->retries >= 1 && !timercmp(&now, &timeout, <)) {
			/* Fragment sent before, not ACK'd */
			WDEBUG("Sending fragment %u again, %u retries so far, %u resent overall\n", f->seqID, f->retries, w->resends);
			w->resends ++;
			goto found;
		} else if (f->retries == 0 && f->len > 0) {
			/* Fragment not sent */
			goto found;
		}
	}
	if (f)
		WDEBUG("Not sending any fragments (last frag checked: retries %u, seqid %u, len %lu)",
				f->retries, f->seqID, f->len);
	return NULL;

	found:
	/* store other ACK into fragment for sending; ignore any previous values.
	   Don't resend ACKs because by the time we do, the other end will have
	   resent the corresponding fragment so may as well not cause trouble. */
	f->ack_other = *other_ack, *other_ack = -1;
	f->start &= 1;
	f->end &= 1;
	f->retries++;
	gettimeofday(&f->lastsent, NULL);
	return f;
}

/* Gets the seqid of next fragment to be ACK'd (RECV) */
int
window_get_next_ack(struct frag_buffer *w)
{
	fragment *f;
	for (size_t i = 0; i < w->windowsize; i++) {
		f = &w->frags[WRAP(w->window_start + i)];
		if (f->len > 0 && f->acks <= 0) {
			f->acks = 1;
			return f->seqID;
		}
	}
	return -1;
}

/* Sets the fragment with seqid to be ACK'd (SEND) */
void
window_ack(struct frag_buffer *w, int seqid)
{
	fragment *f;
	if (seqid < 0 || seqid > MAX_SEQ_ID) return;
	for (size_t i = 0; i < w->windowsize; i++) {
		f = &w->frags[AFTER(w, i)];
		if (f->seqID == seqid && f->len > 0) { /* ACK first non-empty frag */
			if (f->acks > 0)
				WDEBUG("DUPE ACK: %d ACKs for seqId %u", f->acks, seqid);
			f->acks ++;
			WDEBUG("   ACK frag seq %u, ACKs %u, len %lu, s %u e %u", f->seqID, f->acks, f->len, f->start, f->end);
			break;
		}
	}
}

/* Function to be called after all other processing has been done
 * when anything happens (moves window etc) (SEND/RECV) */
void
window_tick(struct frag_buffer *w)
{
	unsigned old_start_id;
	for (size_t i = 0; i < w->windowsize; i++) {
		if (w->frags[w->window_start].acks >= 1) {
			old_start_id = w->start_seq_id;
			w->start_seq_id = (w->start_seq_id + 1) % MAX_SEQ_ID;
			WDEBUG("moving window forwards; %lu-%lu (%u) to %lu-%lu (%u) len=%lu",
					w->window_start, w->window_end, old_start_id, AFTER(w, 1),
					AFTER(w, w->windowsize + 1), w->start_seq_id, w->length);
			if (w->direction == WINDOW_SENDING) {
				WDEBUG("Clearing old fragments in SENDING window.");
				w->numitems --; /* Clear old fragments */
				memset(&w->frags[w->window_start], 0, sizeof(fragment));
			}
			w->window_start = AFTER(w, 1);

			w->window_end = AFTER(w, w->windowsize);
		} else break;
	}
}

/* Splits data into fragments and adds to the end of the window buffer for sending
 * All fragment meta-data is created here (SEND) */
int
window_add_outgoing_data(struct frag_buffer *w, uint8_t *data, size_t len, int compressed)
{
	// Split data into thingies of <= fragsize
	size_t n = ((len - 1) / w->maxfraglen) + 1;
	if (!data || n == 0 || len == 0 || n > window_buffer_available(w)) {
		WDEBUG("Failed to append fragment (buffer too small!)");
		return -1;
	}
	compressed &= 1;
	size_t offset = 0;
	static fragment f;
	WDEBUG("add data len %lu, %lu frags, max fragsize %u", len, n, w->maxfraglen);
	for (size_t i = 0; i < n; i++) {
		memset(&f, 0, sizeof(f));
		f.len = MIN(len - offset, w->maxfraglen);
		memcpy(f.data, data + offset, f.len);
		f.seqID = w->cur_seq_id;
		f.start = (i == 0) ? 1 : 0;
		f.end = (i == n - 1) ? 1 : 0;
		f.compressed = compressed;
		f.ack_other = -1;
		window_append_fragment(w, &f);
		w->cur_seq_id = (w->cur_seq_id + 1) % MAX_SEQ_ID;
		WDEBUG("     fragment len %lu, seqID %u, s %u, end %u, dOffs %lu", f.len, f.seqID, f.start, f.end, offset);
		offset += f.len;
	}
	return n;
}