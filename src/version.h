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

/* NexCache OSS compatibility version for clients that check for specific versions.
 * NEX-FIX: was stuck at 7.2.4 while commands.def already declared (and geo.c/
 * t_string.c already implement) features tagged with later "since" versions
 * (e.g. SET IFEQ since 8.1.0, GEOSEARCH BYPOLYGON since 9.0.0) -- bumped to
 * match what is actually implemented, so version-gated help/arg filtering
 * (see cliLegacyInitCommandHelpEntry -> removeUnsupportedArgs) doesn't hide
 * working functionality from clients that check this version. */
#define NEXCACHE_COMPAT_VERSION "9.0.0"
#define NEXCACHE_COMPAT_VERSION_NUM 0x00090000
