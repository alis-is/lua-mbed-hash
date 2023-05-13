#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"

#include "mbedtls/platform.h"

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
#include <string.h>

char char_to_hex(unsigned char value) {
  static const char hex_chars[] = "0123456789abcdef";
  return hex_chars[value & 0xf];
}

static void to_hex(const unsigned char *const input,
                   unsigned char *const output, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    output[2 * i] = char_to_hex(input[i] >> 4);
    output[2 * i + 1] = char_to_hex(input[i]);
  }
}
static char hex_char_to_lower(const char ch) {
  if (ch >= 'A' && ch <= 'F')
    return 'a' + (ch - 'A');
  return ch;
}

int l_sha256sum(lua_State *L) {
  size_t len;
  lua_settop(L, 2);
  const unsigned char *buffer =
      (const unsigned char *)luaL_checklstring(L, 1, &len);
  const int hex = lua_toboolean(L, 2);
  unsigned char output[32];
  mbedtls_sha256(buffer, len, output, 0);
  if (hex) {
    unsigned char hexOutput[64];
    to_hex(output, hexOutput, 32);
    lua_pushlstring(L, (const char *)hexOutput, 64);
  } else {
    lua_pushlstring(L, (const char *)output, 32);
  }
  return 1;
}

int l_sha512sum(lua_State *L) {
  size_t len;
  lua_settop(L, 2);
  const unsigned char *buffer =
      (const unsigned char *)luaL_checklstring(L, 1, &len);
  const int hex = lua_toboolean(L, 2);
  unsigned char output[64];
  mbedtls_sha512(buffer, len, output, 0);
  if (hex) {
    unsigned char hexOutput[128];
    to_hex(output, hexOutput, 64);
    lua_pushlstring(L, (const char *)hexOutput, 128);
  } else {
    lua_pushlstring(L, (const char *)output, 64);
  }
  return 1;
}

int l_equals(lua_State *L) {
  size_t len1, len2;
  lua_settop(L, 3);
  const unsigned char *hash1 =
      (const unsigned char *)luaL_checklstring(L, 1, &len1);
  const unsigned char *hash2 =
      (const unsigned char *)luaL_checklstring(L, 2, &len2);
  const int hex = lua_toboolean(L, 3);
  if (hex) {
    // skip leading 0x
    if (*hash1 == '0' && (*(hash1 + 1) == 'x' || *(hash2 + 1) == 'X')) {
      hash1 += 2;
      len1 -= 2;
    }
    if (*hash2 == '0' && (*(hash2 + 1) == 'x' || *(hash2 + 1) == 'X')) {
      hash2 += 2;
      len2 -= 2;
    }
  }
  if (len1 != len2) {
    lua_pushboolean(L, 0);
    return 1;
  }
  if (hex) {
    for (int i = 0; i < len1; i++) {
      char ch1 = hex_char_to_lower(*(hash1 + i));
      char ch2 = hex_char_to_lower(*(hash2 + i));
      if (ch1 != ch2) {
        lua_pushboolean(L, 0);
        return 1;
      }
    }

    lua_pushboolean(L, 1);
    return 1;
  }
  int cmp = memcmp(hash1, hash2, len1);
  lua_pushboolean(L, cmp == 0);
  return 1;
}

int l_sha256_init(lua_State *L) {
  lua_settop(L, 0);
  mbedtls_sha256_context *ctx =
      lua_newuserdata(L, sizeof(mbedtls_sha256_context));
  mbedtls_sha256_init(ctx);
  mbedtls_sha256_starts(ctx, 0);
  return 1;
}

int l_sha256_update(lua_State *L) {
  lua_settop(L, 2);
  size_t len;
  mbedtls_sha256_context *ctx = lua_touserdata(L, 1);
  const unsigned char *buffer =
      (const unsigned char *)luaL_checklstring(L, 2, &len);
  mbedtls_sha256_update(ctx, buffer, len);
  return 1;
}

int l_sha256_finish(lua_State *L) {
  lua_settop(L, 2);
  mbedtls_sha256_context *ctx = lua_touserdata(L, 1);
  const int hex = lua_toboolean(L, 2);
  unsigned char output[32];
  mbedtls_sha256_finish(ctx, output);
  mbedtls_sha256_free(ctx);
  if (hex) {
    unsigned char hexOutput[64];
    to_hex(output, hexOutput, 32);
    lua_pushlstring(L, (const char *)hexOutput, 64);
  } else {
    lua_pushlstring(L, (const char *)output, 32);
  }
  return 1;
}

int l_sha512_init(lua_State *L) {
  lua_settop(L, 0);
  mbedtls_sha512_context *ctx =
      lua_newuserdata(L, sizeof(mbedtls_sha512_context));
  mbedtls_sha512_init(ctx);
  mbedtls_sha512_starts(ctx, 0);
  return 1;
}

int l_sha512_update(lua_State *L) {
  lua_settop(L, 2);
  size_t len;
  mbedtls_sha512_context *ctx = lua_touserdata(L, 1);
  const unsigned char *buffer =
      (const unsigned char *)luaL_checklstring(L, 2, &len);
  mbedtls_sha512_update(ctx, buffer, len);
  return 1;
}

int l_sha512_finish(lua_State *L) {
  lua_settop(L, 2);
  mbedtls_sha512_context *ctx = lua_touserdata(L, 1);
  const int hex = lua_toboolean(L, 2);
  unsigned char output[64];
  mbedtls_sha512_finish(ctx, output);
  mbedtls_sha512_free(ctx);
  if (hex) {
    unsigned char hexOutput[128];
    to_hex(output, hexOutput, 64);
    lua_pushlstring(L, (const char *)hexOutput, 128);
  } else {
    lua_pushlstring(L, (const char *)output, 64);
  }
  return 1;
}

static const struct luaL_Reg lua_hash[] = {{"sha256sum", l_sha256sum},
                                           {"sha512sum", l_sha512sum},
                                           {"equals", l_equals},
                                           {"sha256_init", l_sha256_init},
                                           {"sha256_update", l_sha256_update},
                                           {"sha256_finish", l_sha256_finish},
                                           {"sha512_init", l_sha512_init},
                                           {"sha512_update", l_sha512_update},
                                           {"sha512_finish", l_sha512_finish},
                                           {NULL, NULL}};

int luaopen_lmbed_hash(lua_State *L) {
  lua_newtable(L);
  luaL_setfuncs(L, lua_hash, 0);
  return 1;
}