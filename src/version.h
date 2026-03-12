/* These macros are used where the server name is printed in logs and replies.
 * Note the difference in the first letter "N" vs "n". SERVER_TITLE is used in
 * readable text like log messages and SERVER_NAME is used in INFO fields and
 * similar. */
#define SERVER_NAME "nexcache"
#define SERVER_TITLE "NexCache"
#define NEXCACHE_VERSION "1.0.0"
#define NEXCACHE_VERSION_NUM 0x00010000

/* The release stage is used in order to provide release status information.
 * In stable branch the status is always "dev".
 * During release process the status will be set to rc1,rc2...rcN.
 * When the version is released the status will be "ga". */
#define NEXCACHE_RELEASE_STAGE "ga"

/* NexCache OSS compatibility version for clients that check for specific versions. */
#define NEXCACHE_COMPAT_VERSION "7.2.4"
#define NEXCACHE_COMPAT_VERSION_NUM 0x00070204
