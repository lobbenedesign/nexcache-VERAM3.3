/*
 * Copyright (c) NexCache Contributors
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "../../nexcachemodule.h"
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <string.h>
#if defined(__GLIBC__) && !defined(USE_LIBC)
#include <malloc.h>
#endif
#include <errno.h>

#include "engine_structs.h"
#include "function_lua.h"
#include "script_lua.h"
#include "debug_lua.h"


#define LUA_ENGINE_NAME "LUA"
#define REGISTRY_ERROR_HANDLER_NAME "__ERROR_HANDLER__"

/* Adds server.debug() function used by lua debugger
 *
 * Log a string message into the output console.
 * Can take multiple arguments that will be separated by commas.
 * Nothing is returned to the caller. */
static int luaServerDebugCommand(lua_State *lua) {
    if (!ldbIsActive()) return 0;
    int argc = lua_gettop(lua);
    NexCacheModuleString *log = NexCacheModule_CreateStringPrintf(NULL, "<debug> line %d: ", ldbGetCurrentLine());
    while (argc--) {
        log = ldbCatStackValue(log, lua, -1 - argc);
        if (argc != 0) {
            NexCacheModule_StringAppendBuffer(NULL, log, ", ", 2);
        }
    }
    ldbLog(log);
    return 0;
}

/* Adds server.breakpoint() function used by lua debugger.
 *
 * Allows to stop execution during a debugging session from within
 * the Lua code implementation, like if a breakpoint was set in the code
 * immediately after the function. */
static int luaServerBreakpointCommand(lua_State *lua) {
    if (ldbIsActive()) {
        ldbSetBreakpointOnNextLine(1);
        lua_pushboolean(lua, 1);
    } else {
        lua_pushboolean(lua, 0);
    }
    return 1;
}

/* Adds server.replicate_commands()
 *
 * DEPRECATED: Now do nothing and always return true.
 * Turn on single commands replication if the script never called
 * a write command so far, and returns true. Otherwise if the script
 * already started to write, returns false and stick to whole scripts
 * replication, which is our default. */
int luaServerReplicateCommandsCommand(lua_State *lua) {
    lua_pushboolean(lua, 1);
    return 1;
}

static void luaStateInstallErrorHandler(lua_State *lua) {
    /* Add a helper function we use for pcall error reporting.
     * Note that when the error is in the C function we want to report the
     * information about the caller, that's what makes sense from the point
     * of view of the user debugging a script. */
    lua_pushstring(lua, REGISTRY_ERROR_HANDLER_NAME);
    char *errh_func = "local dbg = debug\n"
                      "debug = nil\n"
                      "local error_handler = function (err)\n"
                      "  local i = dbg.getinfo(2,'nSl')\n"
                      "  if i and i.what == 'C' then\n"
                      "    i = dbg.getinfo(3,'nSl')\n"
                      "  end\n"
                      "  if type(err) ~= 'table' then\n"
                      "    err = {err='ERR ' .. tostring(err)}"
                      "  end"
                      "  if i then\n"
                      "    err['source'] = i.source\n"
                      "    err['line'] = i.currentline\n"
                      "  end"
                      "  return err\n"
                      "end\n"
                      "return error_handler";
    luaL_loadbuffer(lua, errh_func, strlen(errh_func), "@err_handler_def");
    lua_pcall(lua, 0, 1, 0);
    lua_settable(lua, LUA_REGISTRYINDEX);
}

static void luaStateLockGlobalTable(lua_State *lua) {
    /* Lock the global table from any changes */
    lua_pushvalue(lua, LUA_GLOBALSINDEX);
    luaSetErrorMetatable(lua);
    /* Recursively lock all tables that can be reached from the global table */
    luaSetTableProtectionRecursively(lua);
    lua_pop(lua, 1);
    /* Set metatables of basic types (string, number, nil etc.) readonly. */
    luaSetTableProtectionForBasicTypes(lua);
}


static void initializeEvalLuaState(lua_State *lua) {
    /* register debug commands. we only need to add it under 'server' as 'nexcache'
     * is effectively aliased to 'server' table at this point. */
    lua_getglobal(lua, "server");

    /* server.breakpoint */
    lua_pushstring(lua, "breakpoint");
    lua_pushcfunction(lua, luaServerBreakpointCommand);
    lua_settable(lua, -3);

    /* server.debug */
    lua_pushstring(lua, "debug");
    lua_pushcfunction(lua, luaServerDebugCommand);
    lua_settable(lua, -3);

    /* server.replicate_commands */
    lua_pushstring(lua, "replicate_commands");
    lua_pushcfunction(lua, luaServerReplicateCommandsCommand);
    lua_settable(lua, -3);

    lua_setglobal(lua, "server");

    /* Duplicate the function with __server__err__handler and
     * __nexcache__err_handler name for backwards compatibility. */
    lua_pushstring(lua, REGISTRY_ERROR_HANDLER_NAME);
    lua_gettable(lua, LUA_REGISTRYINDEX);
    lua_setglobal(lua, "__server__err__handler");
    lua_getglobal(lua, "__server__err__handler");
    lua_setglobal(lua, "__nexcache__err__handler");
}

static uint32_t parse_semver(const char *version) {
    unsigned int major = 0, minor = 0, patch = 0;
    sscanf(version, "%u.%u.%u", &major, &minor, &patch);
    return ((major & 0xFF) << 16) | ((minor & 0xFF) << 8) | (patch & 0xFF);
}

static void get_version_info(NexCacheModuleCtx *ctx,
                             char **nexcache_version,
                             uint32_t *nexcache_version_num,
                             char **server_name) {
    NexCacheModuleServerInfoData *info = NexCacheModule_GetServerInfo(ctx, "server");
    NexCacheModule_Assert(info != NULL);

    const char *rv = NexCacheModule_ServerInfoGetFieldC(info, "nexcache_version");
    *nexcache_version = lm_strcpy(rv);
    *nexcache_version_num = parse_semver(*nexcache_version);

    const char *sn = NexCacheModule_ServerInfoGetFieldC(info, "server_name");
    *server_name = lm_strcpy(sn);

    NexCacheModule_FreeServerInfo(ctx, info);
}

static void initializeLuaState(luaEngineCtx *lua_engine_ctx,
                               NexCacheModuleScriptingEngineSubsystemType type) {
    lua_State *lua = lua_open();

    if (type == VMSE_EVAL) {
        lua_engine_ctx->eval_lua = lua;
    } else {
        NexCacheModule_Assert(type == VMSE_FUNCTION);
        lua_engine_ctx->function_lua = lua;
    }

    luaRegisterServerAPI(lua_engine_ctx, lua);
    luaStateInstallErrorHandler(lua);

    if (type == VMSE_EVAL) {
        initializeEvalLuaState(lua);
        luaStateLockGlobalTable(lua);
    } else {
        luaStateLockGlobalTable(lua);
        luaFunctionInitializeLuaState(lua_engine_ctx, lua);
    }
}

static struct luaEngineCtx *createEngineContext(NexCacheModuleCtx *ctx) {
    luaEngineCtx *lua_engine_ctx = NexCacheModule_Alloc(sizeof(*lua_engine_ctx));

    get_version_info(ctx,
                     &lua_engine_ctx->nexcache_version,
                     &lua_engine_ctx->nexcache_version_num,
                     &lua_engine_ctx->server_name);

    lua_engine_ctx->lua_enable_insecure_api = 0;

    initializeLuaState(lua_engine_ctx, VMSE_EVAL);
    initializeLuaState(lua_engine_ctx, VMSE_FUNCTION);

    return lua_engine_ctx;
}

static void destroyEngineContext(luaEngineCtx *lua_engine_ctx) {
    lua_close(lua_engine_ctx->eval_lua);
    lua_close(lua_engine_ctx->function_lua);
    NexCacheModule_Free(lua_engine_ctx->nexcache_version);
    NexCacheModule_Free(lua_engine_ctx->server_name);
    NexCacheModule_Free(lua_engine_ctx->nexcache_version);
    NexCacheModule_Free(lua_engine_ctx);
}

static NexCacheModuleScriptingEngineMemoryInfo luaEngineGetMemoryInfo(NexCacheModuleCtx *module_ctx,
                                                                    NexCacheModuleScriptingEngineCtx *engine_ctx,
                                                                    NexCacheModuleScriptingEngineSubsystemType type) {
    NEXCACHEMODULE_NOT_USED(module_ctx);
    luaEngineCtx *lua_engine_ctx = engine_ctx;
    NexCacheModuleScriptingEngineMemoryInfo mem_info = {0};

    if (type == VMSE_EVAL || type == VMSE_ALL) {
        mem_info.used_memory += luaMemory(lua_engine_ctx->eval_lua);
    }
    if (type == VMSE_FUNCTION || type == VMSE_ALL) {
        mem_info.used_memory += luaMemory(lua_engine_ctx->function_lua);
    }

    mem_info.engine_memory_overhead = NexCacheModule_MallocSize(engine_ctx);

    return mem_info;
}

static NexCacheModuleScriptingEngineCompiledFunction **luaEngineCompileCode(NexCacheModuleCtx *module_ctx,
                                                                          NexCacheModuleScriptingEngineCtx *engine_ctx,
                                                                          NexCacheModuleScriptingEngineSubsystemType type,
                                                                          const char *code,
                                                                          size_t code_len,
                                                                          size_t timeout,
                                                                          size_t *out_num_compiled_functions,
                                                                          NexCacheModuleString **err) {
    luaEngineCtx *lua_engine_ctx = (luaEngineCtx *)engine_ctx;
    NexCacheModuleScriptingEngineCompiledFunction **functions = NULL;

    if (type == VMSE_EVAL) {
        lua_State *lua = lua_engine_ctx->eval_lua;

        if (luaL_loadbuffer(
                lua, code, code_len, "@user_script")) {
            *err = NexCacheModule_CreateStringPrintf(module_ctx, "Error compiling script (new function): %s", lua_tostring(lua, -1));
            lua_pop(lua, 1);
            return functions;
        }

        NexCacheModule_Assert(lua_isfunction(lua, -1));
        int function_ref = luaL_ref(lua, LUA_REGISTRYINDEX);

        luaFunction *script = NexCacheModule_Calloc(1, sizeof(luaFunction));
        *script = (luaFunction){
            .lua = lua,
            .function_ref = function_ref,
        };

        NexCacheModuleScriptingEngineCompiledFunction *func = NexCacheModule_Alloc(sizeof(*func));
        *func = (NexCacheModuleScriptingEngineCompiledFunction){
            .name = NULL,
            .function = script,
            .desc = NULL,
            .f_flags = 0};

        *out_num_compiled_functions = 1;
        functions = NexCacheModule_Calloc(1, sizeof(NexCacheModuleScriptingEngineCompiledFunction *));
        *functions = func;
    } else {
        functions = luaFunctionLibraryCreate(lua_engine_ctx->function_lua,
                                             code,
                                             timeout,
                                             out_num_compiled_functions,
                                             err);
    }

    return functions;
}

static void luaEngineFunctionCall(NexCacheModuleCtx *module_ctx,
                                  NexCacheModuleScriptingEngineCtx *engine_ctx,
                                  NexCacheModuleScriptingEngineServerRuntimeCtx *server_ctx,
                                  NexCacheModuleScriptingEngineCompiledFunction *compiled_function,
                                  NexCacheModuleScriptingEngineSubsystemType type,
                                  NexCacheModuleString **keys,
                                  size_t nkeys,
                                  NexCacheModuleString **args,
                                  size_t nargs) {
    luaEngineCtx *lua_engine_ctx = (luaEngineCtx *)engine_ctx;
    lua_State *lua = type == VMSE_EVAL ? lua_engine_ctx->eval_lua : lua_engine_ctx->function_lua;
    luaFunction *script = compiled_function->function;
    int lua_function_ref = script->function_ref;

    /* Push the pcall error handler function on the stack. */
    lua_pushstring(lua, REGISTRY_ERROR_HANDLER_NAME);
    lua_gettable(lua, LUA_REGISTRYINDEX);

    lua_rawgeti(lua, LUA_REGISTRYINDEX, lua_function_ref);
    NexCacheModule_Assert(!lua_isnil(lua, -1));

    luaCallFunction(module_ctx,
                    server_ctx,
                    type,
                    lua,
                    keys,
                    nkeys,
                    args,
                    nargs,
                    type == VMSE_EVAL ? ldbIsActive() : 0,
                    lua_engine_ctx->lua_enable_insecure_api);

    lua_pop(lua, 1); /* Remove the error handler. */
}

static void resetLuaContext(void *context) {
    lua_State *lua = context;
    lua_gc(lua, LUA_GCCOLLECT, 0);
    lua_close(lua);

#if defined(__GLIBC__) && !defined(USE_LIBC)
    /* The lua interpreter may hold a lot of memory internally, and lua is
     * using libc. libc may take a bit longer to return the memory to the OS,
     * so after lua_close, we call malloc_trim try to purge it earlier.
     *
     * We do that only when the server itself does not use libc. When Lua and the server
     * use different allocators, one won't use the fragmentation holes of the
     * other, and released memory can take a long time until it is returned to
     * the OS. */
    malloc_trim(0);
#endif
}

static int isLuaInsecureAPIEnabled(NexCacheModuleCtx *module_ctx) {
    int result = 0;
    NexCacheModuleCallReply *reply = NexCacheModule_Call(module_ctx, "CONFIG", "ccE", "GET", "lua-enable-insecure-api");
    if (NexCacheModule_CallReplyType(reply) == NEXCACHEMODULE_REPLY_ERROR) {
        NexCacheModule_Log(module_ctx,
                         "warning",
                         "Unable to determine 'lua-enable-insecure-api' configuration value: %s",
                         NexCacheModule_CallReplyStringPtr(reply, NULL));
        NexCacheModule_FreeCallReply(reply);
        return 0;
    }
    NexCacheModule_Assert(NexCacheModule_CallReplyType(reply) == NEXCACHEMODULE_REPLY_ARRAY &&
                        NexCacheModule_CallReplyLength(reply) == 2);
    NexCacheModuleCallReply *val = NexCacheModule_CallReplyArrayElement(reply, 1);
    NexCacheModule_Assert(NexCacheModule_CallReplyType(val) == NEXCACHEMODULE_REPLY_STRING);
    const char *val_str = NexCacheModule_CallReplyStringPtr(val, NULL);
    result = strncmp(val_str, "yes", 3) == 0;
    NexCacheModule_FreeCallReply(reply);
    return result;
}

static NexCacheModuleScriptingEngineCallableLazyEnvReset *luaEngineResetEnv(NexCacheModuleCtx *module_ctx,
                                                                          NexCacheModuleScriptingEngineCtx *engine_ctx,
                                                                          NexCacheModuleScriptingEngineSubsystemType type,
                                                                          int async) {
    NEXCACHEMODULE_NOT_USED(module_ctx);
    luaEngineCtx *lua_engine_ctx = (luaEngineCtx *)engine_ctx;
    NexCacheModule_Assert(type == VMSE_EVAL || type == VMSE_FUNCTION);
    lua_State *lua = type == VMSE_EVAL ? lua_engine_ctx->eval_lua : lua_engine_ctx->function_lua;
    NexCacheModule_Assert(lua);
    NexCacheModuleScriptingEngineCallableLazyEnvReset *callback = NULL;

    if (async) {
        callback = NexCacheModule_Calloc(1, sizeof(*callback));
        *callback = (NexCacheModuleScriptingEngineCallableLazyEnvReset){
            .context = lua,
            .engineLazyEnvResetCallback = resetLuaContext,
        };
    } else {
        resetLuaContext(lua);
    }

    lua_engine_ctx->lua_enable_insecure_api = isLuaInsecureAPIEnabled(module_ctx);

    initializeLuaState(lua_engine_ctx, type);

    return callback;
}

static size_t luaEngineFunctionMemoryOverhead(NexCacheModuleCtx *module_ctx,
                                              NexCacheModuleScriptingEngineCompiledFunction *compiled_function) {
    NEXCACHEMODULE_NOT_USED(module_ctx);
    return NexCacheModule_MallocSize(compiled_function->function) +
           (compiled_function->name ? NexCacheModule_MallocSize(compiled_function->name) : 0) +
           (compiled_function->desc ? NexCacheModule_MallocSize(compiled_function->desc) : 0) +
           NexCacheModule_MallocSize(compiled_function);
}

static void luaEngineFreeFunction(NexCacheModuleCtx *module_ctx,
                                  NexCacheModuleScriptingEngineCtx *engine_ctx,
                                  NexCacheModuleScriptingEngineSubsystemType type,
                                  NexCacheModuleScriptingEngineCompiledFunction *compiled_function) {
    NEXCACHEMODULE_NOT_USED(module_ctx);
    NexCacheModule_Assert(type == VMSE_EVAL || type == VMSE_FUNCTION);

    luaEngineCtx *lua_engine_ctx = engine_ctx;
    lua_State *lua = type == VMSE_EVAL ? lua_engine_ctx->eval_lua : lua_engine_ctx->function_lua;
    NexCacheModule_Assert(lua);

    luaFunction *script = (luaFunction *)compiled_function->function;
    if (lua == script->lua) {
        /* The lua context is still the same, which means that we're not
         * resetting the whole eval context, and therefore, we need to
         * delete the function from the lua context.
         */
        lua_unref(lua, script->function_ref);
    }
    NexCacheModule_Free(script);

    if (compiled_function->name) {
        NexCacheModule_Free(compiled_function->name);
    }
    if (compiled_function->desc) {
        NexCacheModule_Free(compiled_function->desc);
    }
    NexCacheModule_Free(compiled_function);
}

static NexCacheModuleScriptingEngineDebuggerEnableRet luaEngineDebuggerEnable(NexCacheModuleCtx *module_ctx,
                                                                            NexCacheModuleScriptingEngineCtx *engine_ctx,
                                                                            NexCacheModuleScriptingEngineSubsystemType type,
                                                                            const NexCacheModuleScriptingEngineDebuggerCommand **commands,
                                                                            size_t *commands_len) {
    NEXCACHEMODULE_NOT_USED(module_ctx);

    if (type != VMSE_EVAL) {
        return VMSE_DEBUG_NOT_SUPPORTED;
    }

    ldbEnable();

    luaEngineCtx *lua_engine_ctx = engine_ctx;
    ldbGenerateDebuggerCommandsArray(lua_engine_ctx->eval_lua,
                                     commands,
                                     commands_len);

    return VMSE_DEBUG_ENABLED;
}

static void luaEngineDebuggerDisable(NexCacheModuleCtx *module_ctx,
                                     NexCacheModuleScriptingEngineCtx *engine_ctx,
                                     NexCacheModuleScriptingEngineSubsystemType type) {
    NEXCACHEMODULE_NOT_USED(module_ctx);
    NEXCACHEMODULE_NOT_USED(engine_ctx);
    NEXCACHEMODULE_NOT_USED(type);
    ldbDisable();
}

static void luaEngineDebuggerStart(NexCacheModuleCtx *module_ctx,
                                   NexCacheModuleScriptingEngineCtx *engine_ctx,
                                   NexCacheModuleScriptingEngineSubsystemType type,
                                   NexCacheModuleString *source) {
    NEXCACHEMODULE_NOT_USED(module_ctx);
    NEXCACHEMODULE_NOT_USED(engine_ctx);
    NEXCACHEMODULE_NOT_USED(type);
    ldbStart(source);
}

static void luaEngineDebuggerEnd(NexCacheModuleCtx *module_ctx,
                                 NexCacheModuleScriptingEngineCtx *engine_ctx,
                                 NexCacheModuleScriptingEngineSubsystemType type) {
    NEXCACHEMODULE_NOT_USED(module_ctx);
    NEXCACHEMODULE_NOT_USED(engine_ctx);
    NEXCACHEMODULE_NOT_USED(type);
    ldbEnd();
}

static struct luaEngineCtx *engine_ctx = NULL;

int NexCacheModule_OnLoad(NexCacheModuleCtx *ctx,
                        NexCacheModuleString **argv,
                        int argc) {
    NEXCACHEMODULE_NOT_USED(argv);
    NEXCACHEMODULE_NOT_USED(argc);

    if (NexCacheModule_Init(ctx, "lua", 1, NEXCACHEMODULE_APIVER_1) == NEXCACHEMODULE_ERR) {
        return NEXCACHEMODULE_ERR;
    }

    NexCacheModule_SetModuleOptions(ctx, NEXCACHEMODULE_OPTIONS_HANDLE_REPL_ASYNC_LOAD |
                                           NEXCACHEMODULE_OPTIONS_HANDLE_ATOMIC_SLOT_MIGRATION);

    engine_ctx = createEngineContext(ctx);

    if (NexCacheModule_LoadConfigs(ctx) == NEXCACHEMODULE_ERR) {
        NexCacheModule_Log(ctx, "warning", "Failed to load LUA module configs");
        destroyEngineContext(engine_ctx);
        engine_ctx = NULL;
        return NEXCACHEMODULE_ERR;
    }

    NexCacheModuleScriptingEngineMethods methods = {
        .version = NEXCACHEMODULE_SCRIPTING_ENGINE_ABI_VERSION,
        .compile_code = luaEngineCompileCode,
        .free_function = luaEngineFreeFunction,
        .call_function = luaEngineFunctionCall,
        .get_function_memory_overhead = luaEngineFunctionMemoryOverhead,
        .reset_env = luaEngineResetEnv,
        .get_memory_info = luaEngineGetMemoryInfo,
        .debugger_enable = luaEngineDebuggerEnable,
        .debugger_disable = luaEngineDebuggerDisable,
        .debugger_start = luaEngineDebuggerStart,
        .debugger_end = luaEngineDebuggerEnd,
    };

    int result = NexCacheModule_RegisterScriptingEngine(ctx,
                                                      LUA_ENGINE_NAME,
                                                      engine_ctx,
                                                      &methods);

    if (result == NEXCACHEMODULE_ERR) {
        NexCacheModule_Log(ctx, "warning", "Failed to register LUA scripting engine");
        destroyEngineContext(engine_ctx);
        engine_ctx = NULL;
        return NEXCACHEMODULE_ERR;
    }

    engine_ctx->lua_enable_insecure_api = isLuaInsecureAPIEnabled(ctx);

    return NEXCACHEMODULE_OK;
}

int NexCacheModule_OnUnload(NexCacheModuleCtx *ctx) {
    if (NexCacheModule_UnregisterScriptingEngine(ctx, LUA_ENGINE_NAME) != NEXCACHEMODULE_OK) {
        NexCacheModule_Log(ctx, "error", "Failed to unregister engine");
        return NEXCACHEMODULE_ERR;
    }

    destroyEngineContext(engine_ctx);
    engine_ctx = NULL;

    return NEXCACHEMODULE_OK;
}
