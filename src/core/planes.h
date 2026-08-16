#ifndef NEXCACHE_PLANES_H
#define NEXCACHE_PLANES_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Thread plane enumeration
 * As inspired by Pelikan Data/Control plane separation.
 * Performance-sensitive and non-performance-sensitive paths do not contend.
 */
typedef enum {
    PLANE_DATA,
    PLANE_ADMIN,
    PLANE_SNAPSHOT,
    PLANE_REPLICATION,
    PLANE_TIERING,
    PLANE_OBSERVABILITY,
    PLANE_EXPIRATION,
    PLANE_COUNT /* Total number of planes */
} ThreadPlane;

/**
 * @brief Initialize a thread plane and set its scheduling properties.
 *
 * STUB — does NOT actually do any of this yet: plane_init only records
 * cpu_core/priority into an internal struct (g_planes[]) and marks it
 * "initialized". It never calls sched_setaffinity/pthread_attr_setaffinity_np,
 * never sets SCHED_FIFO, and never creates a thread — despite what the
 * parameters below imply. No code in this codebase calls plane_init or
 * plane_send_message (verified with a global grep), so this is currently
 * unreachable in addition to being unimplemented. Do not assume CPU
 * affinity or RT scheduling are in effect because this was called.
 *
 * @param plane The plane to initialize
 * @param cpu_core CPU affinity core (-1 for no affinity) — recorded but not applied
 * @param priority RT priority (SCHED_FIFO), 0 for normal SCHED_OTHER — recorded but not applied
 */
void plane_init(ThreadPlane plane, int cpu_core, int priority);

/**
 * @brief Send a cross-plane message lock-free.
 * Data plane communicates with control plane via non-blocking rings.
 *
 * STUB — silently drops every message. No ring buffer (lock-free or
 * otherwise) is implemented; this function does nothing but validate its
 * arguments. Do not call this expecting the message to arrive anywhere.
 *
 * @param from Source plane
 * @param to Destination plane
 * @param msg Pointer to message data
 * @param msg_size Size of message data
 */
void plane_send_message(ThreadPlane from, ThreadPlane to, void *msg, size_t msg_size);

#endif /* NEXCACHE_PLANES_H */
