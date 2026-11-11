/* Shared one-time library setup for the rspamd harnesses (mirrors test/rspamd_cxx_unit.cxx). */
#ifndef MAYHEM_FUZZ_INIT_H
#define MAYHEM_FUZZ_INIT_H

#include "config.h"
#include "rspamd.h"
#include "libserver/url.h"
#include "libutil/mem_pool.h"
#include "lua/lua_common.h"

static struct rspamd_config *fuzz_cfg = NULL;

static inline void
fuzz_rspamd_init(void)
{
	/*
	 * The MIME parser type-detects parts through lualib/lua_magic, which needs lualib and the contrib Lua
	 * modules on the module path (what `make run-test` sets), set before the Lua state is created.
	 */
#ifdef MAYHEM_SRCDIR
	setenv("LUA_PATH",
		   MAYHEM_SRCDIR "/lualib/?.lua;" MAYHEM_SRCDIR "/lualib/?/?.lua;" MAYHEM_SRCDIR "/lualib/?/init.lua;" MAYHEM_SRCDIR "/contrib/lua-?/?.lua",
		   0);
#endif
	rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), NULL, 0);
	struct rspamd_main *rspamd_main =
		(struct rspamd_main *) rspamd_mempool_alloc0(pool, sizeof(*rspamd_main));

	rspamd_main->server_pool = pool;
	fuzz_cfg = rspamd_config_new(RSPAMD_CONFIG_INIT_DEFAULT);
	fuzz_cfg->libs_ctx = rspamd_init_libs();
	rspamd_main->cfg = fuzz_cfg;
	fuzz_cfg->cfg_pool = pool;
	rspamd_main->logger = rspamd_log_open_emergency(pool, RSPAMD_LOG_FLAG_RSPAMADM);
	rspamd_log_set_log_level(rspamd_main->logger, G_LOG_LEVEL_CRITICAL);
	rspamd_lua_set_path((lua_State *) fuzz_cfg->lua_state, NULL, NULL);
	rspamd_lua_set_globals(fuzz_cfg, (lua_State *) fuzz_cfg->lua_state);
	rspamd_url_init(NULL);
}

#endif
