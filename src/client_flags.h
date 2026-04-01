#include <stdint.h>

/* NEX-VERA M3.3: ABI-Shielded 128-bit Client Flags.
 * Using packed union to enforce absolute stability across platforms. */
#pragma pack(push, 1)
typedef struct ClientFlags {
    union {
        struct {
            uint64_t primary : 1;
            uint64_t replica : 1;
            uint64_t monitor : 1;
            uint64_t multi : 1;
            uint64_t blocked : 1;
            uint64_t dirty_cas : 1;
            uint64_t close_after_reply : 1;
            uint64_t unblocked : 1;
            uint64_t script : 1;
            uint64_t asking : 1;
            uint64_t close_asap : 1;
            uint64_t unix_socket : 1;
            uint64_t dirty_exec : 1;
            uint64_t primary_force_reply : 1;
            uint64_t force_aof : 1;
            uint64_t force_repl : 1;
            uint64_t pre_psync : 1;
            uint64_t readonly : 1;
            uint64_t pubsub : 1;
            uint64_t prevent_aof_prop : 1;
            uint64_t prevent_repl_prop : 1;
            uint64_t prevent_prop : 1;
            uint64_t pending_write : 1;
            uint64_t pending_read : 1;
            uint64_t buf_encoded : 1;
            uint64_t reply_off : 1;
            uint64_t reply_skip_next : 1;
            uint64_t reply_skip : 1;
            uint64_t lua_debug : 1;
            uint64_t pushing : 1;
            uint64_t module_auth_has_result : 1;
            uint64_t module_prevent_aof_prop : 1;
            uint64_t module_prevent_repl_prop : 1;
            uint64_t reexecuting_command : 1;
            uint64_t replication_done : 1;
            uint64_t authenticated : 1;
            uint64_t ever_authenticated : 1;
            uint64_t import_source : 1;
            uint64_t buffered_reply : 1;
            uint64_t keyspace_notified : 1;
            uint64_t protected_rdb_channel : 1;
            uint64_t repl_rdb_channel : 1;
            uint64_t dont_cache_primary : 1;
            uint64_t fake : 1;
            /* Missing flags identified by lint */
            uint64_t module : 1;
            uint64_t tracking : 1;
            uint64_t tracking_broken_redir : 1;
            uint64_t tracking_bcast : 1;
            uint64_t tracking_optin : 1;
            uint64_t tracking_optout : 1;
            uint64_t tracking_caching : 1;
            uint64_t tracking_noloop : 1;
            uint64_t in_to_table : 1;
            uint64_t protocol_error : 1;
            uint64_t close_after_command : 1;
            uint64_t deny_blocking : 1;
            uint64_t repl_rdbonly : 1;
            uint64_t no_evict : 1;
            uint64_t allow_oom : 1;
            uint64_t no_touch : 1;
            uint64_t is_protected : 1;
            uint64_t executing_command : 1;
            uint64_t pending_command : 1;
        };
        uint64_t raw[2];
    };
} ClientFlags;
#pragma pack(pop)
