#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/md.h"

#include "mbedtls/platform.h"

#include <string.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

static void to_hex(const unsigned char *input, unsigned char output[], size_t len)
{
    for (int i = 0; i < len; i++)
        sprintf(output + 2 * i, "%.2x", input[i]);
}

static void from_hex(const unsigned char *input, unsigned char output[], size_t len)
{
    unsigned int u;
    for (int i = 0; i < len / 2; i++)
    {
        sscanf(input + i * 2, "%2x", &u);
        output[i] = u;
    }
}

int l_sha256sum(lua_State *L)
{
    size_t len;
    lua_settop(L, 2);
    const unsigned char *buffer = luaL_checklstring(L, 1, &len);
    const int hex = lua_toboolean(L, 2);
    unsigned char output[32];
    mbedtls_sha256(buffer, len, output, 0);
    if (hex)
    {
        unsigned char hexOutput[64];
        to_hex(output, hexOutput, 32);
        lua_pushlstring(L, hexOutput, 64);
    }
    else
    {
        lua_pushlstring(L, output, 32);
    }
    return 1;
}

int l_sha512sum(lua_State *L)
{
    size_t len;
    lua_settop(L, 2);
    const unsigned char *buffer = luaL_checklstring(L, 1, &len);
    const int hex = lua_toboolean(L, 2);
    unsigned char output[64];
    mbedtls_sha512(buffer, len, output, 0);
    if (hex)
    {
        unsigned char hexOutput[128];
        to_hex(output, hexOutput, 64);
        lua_pushlstring(L, hexOutput, 128);
    }
    else
    {
        lua_pushlstring(L, output, 64);
    }
    return 1;
}

int l_equals(lua_State *L)
{
    size_t len1, len2;
    lua_settop(L, 3);
    const unsigned char *hash1 = luaL_checklstring(L, 1, &len1);
    const unsigned char *hash2 = luaL_checklstring(L, 1, &len2);
    const int hex = lua_toboolean(L, 2);
    int equals = 0;
    if (len1 != len2)
    {
        lua_pushboolean(L, equals);
        return 1;
    }
    if (hex)
    {
        unsigned char *_hash1 = malloc(len1 / 2);
        unsigned char *_hash2 = malloc(len2 / 2);

        from_hex(hash1, _hash1, len1);
        from_hex(hash2, _hash2, len2);

        int cmp = memcmp(hash1, hash2, len1);
        lua_pushboolean(L, cmp == 0);

        free((void *)_hash1);
        free((void *)_hash2);
    }
    else
    {
        int cmp = memcmp(hash1, hash2, len1);
        lua_pushboolean(L, cmp == 0);
    }
    return 1;
}

int l_sha256_init(lua_State *L)
{
    lua_settop(L, 0);
    mbedtls_sha256_context *ctx = lua_newuserdata(L, sizeof(mbedtls_sha256_context));
    mbedtls_sha256_init(ctx);
    mbedtls_sha256_starts_ret(ctx, 0);
    return 1;
}

int l_sha256_update(lua_State *L)
{
    lua_settop(L, 2);
    size_t len;
    mbedtls_sha256_context *ctx = lua_touserdata(L, 1);
    const char *buffer = luaL_checklstring(L, 2, &len);
    mbedtls_sha256_update_ret(ctx, buffer, len);
    return 1;
}

int l_sha256_finish(lua_State *L)
{
    lua_settop(L, 2);
    mbedtls_sha256_context *ctx = lua_touserdata(L, 1);
    const int hex = lua_toboolean(L, 2);
    unsigned char output[32];
    mbedtls_sha256_finish_ret(ctx, output);
    mbedtls_sha256_free(ctx);
    if (hex)
    {
        unsigned char hexOutput[64];
        to_hex(output, hexOutput, 32);
        lua_pushlstring(L, hexOutput, 64);
    }
    else
    {
        lua_pushlstring(L, output, 32);
    }
    return 1;
}

int l_sha512_init(lua_State *L)
{
    lua_settop(L, 0);
    mbedtls_sha512_context *ctx = lua_newuserdata(L, sizeof(mbedtls_sha512_context));
    mbedtls_sha512_init(ctx);
    mbedtls_sha512_starts_ret(ctx, 0);
    return 1;
}

int l_sha512_update(lua_State *L)
{
    lua_settop(L, 2);
    size_t len;
    mbedtls_sha512_context *ctx = lua_touserdata(L, 1);
    const char *buffer = luaL_checklstring(L, 2, &len);
    mbedtls_sha512_update_ret(ctx, buffer, len);
    return 1;
}

int l_sha512_finish(lua_State *L)
{
    lua_settop(L, 2);
    mbedtls_sha512_context *ctx = lua_touserdata(L, 1);
    const int hex = lua_toboolean(L, 2);
    unsigned char output[64];
    mbedtls_sha512_finish_ret(ctx, output);
    mbedtls_sha512_free(ctx);
    if (hex)
    {
        unsigned char hexOutput[128];
        to_hex(output, hexOutput, 64);
        lua_pushlstring(L, hexOutput, 128);
    }
    else
    {
        lua_pushlstring(L, output, 64);
    }
    return 1;
}

static const struct luaL_Reg lua_hash[] = {
    {"sha256sum", l_sha256sum},
    {"sha512sum", l_sha512sum},
    {"equals", l_equals},
    {"sha256_init", l_sha256_init},
    {"sha256_update", l_sha256_update},
    {"sha256_finish", l_sha256_finish},
    {"sha512_init", l_sha512_init},
    {"sha512_update", l_sha512_update},
    {"sha512_finish", l_sha512_finish},
    {NULL, NULL}};

int luaopen_lmbed_hash(lua_State *L)
{
    lua_newtable(L);
    luaL_setfuncs(L, lua_hash, 0);
    return 1;
}