/*-
 * Suricata ICAP service
 *
 * Copyright (c) 2026, Soner Tari <sonertari@gmail.com>.
 * All rights reserved.
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

#include "srv_suricata.h"
#include "conn_table.h"

#include <netinet/in.h>

#define SURI_CONN_HASH_BUCKETS 512  /* Power of 2 for fast masking */
#define SURI_CONN_TTL_SEC       60  /* Expire unaccessed sessions after 60s */

struct suri_conn_val {
    uint32_t client_seq;
    uint32_t server_seq;
    uint16_t icap_client_port;  /* Synthetic ICAP port created in REQMOD */
    time_t   last_seen;
};

struct suri_conn_node {
    struct suri_conn_key key;
    struct suri_conn_val val;
    struct suri_conn_node *next;
};

struct suri_conn_bucket {
    pthread_rwlock_t lock;      /* Concurrent reads, exclusive writes per bucket */
    struct suri_conn_node *head;
};

struct suri_conn_table {
    struct suri_conn_bucket buckets[SURI_CONN_HASH_BUCKETS];
};

static struct suri_conn_table g_conn_table;

void suri_conn_table_init(void)
{
    for (int i = 0; i < SURI_CONN_HASH_BUCKETS; i++) {
        pthread_rwlock_init(&g_conn_table.buckets[i].lock, NULL);
        g_conn_table.buckets[i].head = NULL;
    }
}

void suri_conn_table_destroy(void)
{
    for (int i = 0; i < SURI_CONN_HASH_BUCKETS; i++) {
        struct suri_conn_bucket *b = &g_conn_table.buckets[i];

        /* Acquire write lock to prevent concurrent worker thread access during teardown */
        pthread_rwlock_wrlock(&b->lock);

        struct suri_conn_node *curr = b->head;
        while (curr != NULL) {
            struct suri_conn_node *next = curr->next;
            suri_log(7, "Destroy connection client seq: %u, server seq: %u, icap client port: %u\n",
                curr->val.client_seq, curr->val.server_seq, ntohs(curr->val.icap_client_port));
            free(curr);
            curr = next;
        }

        b->head = NULL;

        /* Unlock before destroying the lock structure */
        pthread_rwlock_unlock(&b->lock);
        pthread_rwlock_destroy(&b->lock);
    }
}

static inline uint32_t suri_6tuple_hash(const struct suri_conn_key *k)
{
    /* Fold 64-bit stream_id into 32 bits */
    uint32_t stream_mix = (uint32_t)(k->stream_id ^ (k->stream_id >> 32));

    /* Combine IP addresses, ports, protocol, and stream ID */
    uint32_t h = k->src_ip ^ k->dst_ip;
    h ^= ((uint32_t)k->src_port << 16) | k->dst_port;
    h ^= stream_mix;
    h ^= (uint32_t)k->proto;

    /* Thomas Wang 32-bit integer mix */
    h = (h ^ 61) ^ (h >> 16);
    h = h + (h << 3);
    h = h ^ (h >> 4);
    h = h * 0x27d4eb2d;
    h = h ^ (h >> 15);

    return h & (SURI_CONN_HASH_BUCKETS - 1);
}

static inline int suri_conn_key_equal(const struct suri_conn_key *a, const struct suri_conn_key *b)
{
    // Always memset a/b to 0 before comparison, as memcmp does not account for potential padding bytes in the struct.
    return (memcmp(a, b, sizeof(struct suri_conn_key)) == 0);
    // return (a->src_ip == b->src_ip &&
    //         a->dst_ip == b->dst_ip &&
    //         a->src_port == b->src_port &&
    //         a->dst_port == b->dst_port &&
    //         a->stream_id == b->stream_id &&
    //         a->proto == b->proto);
}

void suri_conn_table_set(const struct suri_conn_key *key, uint32_t client_seq, uint32_t server_seq, uint16_t icap_client_port)
{
    uint32_t idx = suri_6tuple_hash(key);
    struct suri_conn_bucket *b = &g_conn_table.buckets[idx];

    pthread_rwlock_wrlock(&b->lock);

    struct suri_conn_node *curr = b->head;
    struct suri_conn_node *prev = NULL;
    time_t now = time(NULL);

    while (curr) {
        /* Purge expired node while iterating */
        if (now - curr->val.last_seen > SURI_CONN_TTL_SEC) {
            struct suri_conn_node *stale = curr;
            if (prev) {
                prev->next = curr->next;
            } else {
                b->head = curr->next;
            }
            curr = curr->next;

            suri_log(7, "Purge stale connection for key hash index: %u, client seq: %u, server seq: %u, icap client port: %u\n",
                idx, stale->val.client_seq, stale->val.server_seq, ntohs(stale->val.icap_client_port));
            free(stale);
            continue;
        }

        /* Key match: update sequence numbers */
        if (suri_conn_key_equal(&curr->key, key)) {
            curr->val.client_seq = client_seq;
            curr->val.server_seq = server_seq;
            curr->val.icap_client_port = icap_client_port;
            curr->val.last_seen = now;

            suri_log(7, "Update connection for key hash index: %u, client seq: %u, server seq: %u, icap client port: %u\n",
                idx, curr->val.client_seq, curr->val.server_seq, ntohs(curr->val.icap_client_port));
            pthread_rwlock_unlock(&b->lock);
            return;
        }

        prev = curr;
        curr = curr->next;
    }

    suri_log(7, "Set connection for key hash index: %u, client seq: %u, server seq: %u, icap client port: %u\n",
        idx, client_seq, server_seq, ntohs(icap_client_port));

    /* Key not found: insert new node */
    struct suri_conn_node *new_node = malloc(sizeof(struct suri_conn_node));
    memset(new_node, 0, sizeof(struct suri_conn_node));
    if (new_node) {
        new_node->key = *key;
        new_node->val.client_seq = client_seq;
        new_node->val.server_seq = server_seq;
        new_node->val.icap_client_port = icap_client_port;
        new_node->val.last_seen = now;
        new_node->next = b->head;
        b->head = new_node;
    }

    pthread_rwlock_unlock(&b->lock);
}

int suri_conn_table_get(const struct suri_conn_key *key, uint32_t *client_seq, uint32_t *server_seq, uint16_t *icap_client_port)
{
    uint32_t idx = suri_6tuple_hash(key);
    struct suri_conn_bucket *b = &g_conn_table.buckets[idx];

    suri_log(9, "Get connection for key hash index: %u\n", idx);

    pthread_rwlock_rdlock(&b->lock);

    struct suri_conn_node *curr = b->head;
    time_t now = time(NULL);
    int found = 0;

    while (curr) {
        if (suri_conn_key_equal(&curr->key, key)) {
            if (now - curr->val.last_seen <= SURI_CONN_TTL_SEC) {
                suri_log(7, "Get connection for key hash index: %u, client seq: %u, server seq: %u, icap client port: %u\n",
                    idx, curr->val.client_seq, curr->val.server_seq, ntohs(curr->val.icap_client_port));
                if (client_seq) *client_seq = curr->val.client_seq;
                if (server_seq) *server_seq = curr->val.server_seq;
                if (icap_client_port) *icap_client_port = curr->val.icap_client_port;
                found = 1;
            }
            break;
        }
        curr = curr->next;
    }

    if (!found) {
        suri_log(7, "Cannot find connection for key hash index: %u\n", idx);
    }

    pthread_rwlock_unlock(&b->lock);
    return found;
}

void suri_conn_table_delete(const struct suri_conn_key *key)
{
    uint32_t idx = suri_6tuple_hash(key);
    struct suri_conn_bucket *b = &g_conn_table.buckets[idx];

    pthread_rwlock_wrlock(&b->lock);

    struct suri_conn_node *curr = b->head;
    struct suri_conn_node *prev = NULL;

    while (curr) {
        if (suri_conn_key_equal(&curr->key, key)) {
            suri_log(7, "Delete connection for key hash index: %u, client seq: %u, server seq: %u, icap client port: %u\n",
                idx, curr->val.client_seq, curr->val.server_seq, ntohs(curr->val.icap_client_port));
            if (prev) {
                prev->next = curr->next;
            } else {
                b->head = curr->next;
            }
            free(curr);
            break;
        }
        prev = curr;
        curr = curr->next;
    }

    pthread_rwlock_unlock(&b->lock);
}
