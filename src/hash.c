#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/error.h"

#include "mbedtls/platform.h"

#include "hash.h"
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

int l_sha256_sum(lua_State *L) {
  size_t len;
  lua_settop(L, 2);
  const unsigned char *buffer =
      (const unsigned char *)luaL_checklstring(L, 1, &len);
  const int hex = lua_toboolean(L, 2);
  unsigned char output[32];
  int ret = mbedtls_sha256(buffer, len, output, 0);
  if (ret != 0) {
    char error_buf[100];                                 // Error buffer
    mbedtls_strerror(ret, error_buf, sizeof(error_buf)); // Translate error code
    lua_pushnil(L);
    lua_pushstring(L, error_buf);
    return 2;
  }
  if (hex) {
    unsigned char hexOutput[64];
    to_hex(output, hexOutput, 32);
    lua_pushlstring(L, (const char *)hexOutput, 64);
  } else {
    lua_pushlstring(L, (const char *)output, 32);
  }
  return 1;
}

int l_sha512_sum(lua_State *L) {
  size_t len;
  lua_settop(L, 2);
  const unsigned char *buffer =
      (const unsigned char *)luaL_checklstring(L, 1, &len);
  const int hex = lua_toboolean(L, 2);
  unsigned char output[64];
  int ret = mbedtls_sha512(buffer, len, output, 0);
  if (ret != 0) {
    char error_buf[100];                                 // Error buffer
    mbedtls_strerror(ret, error_buf, sizeof(error_buf)); // Translate error code
    lua_pushnil(L);
    lua_pushstring(L, error_buf);
    return 2;
  }

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
  SHA256_CONTEXT *context = lua_newuserdata(L, sizeof(SHA256_CONTEXT));
  context->ctx = malloc(sizeof(mbedtls_sha256_context));
  context->closed = 0;
  if (context->ctx == NULL) {
    lua_pushnil(L);
    lua_pushstring(L, "failed to allocate memory");
    return 2;
  }
  mbedtls_sha256_init(context->ctx);
  int ret = mbedtls_sha256_starts(context->ctx, 0);
  if (ret != 0) {
    char error_buf[100];                                 // Error buffer
    mbedtls_strerror(ret, error_buf, sizeof(error_buf)); // Translate error code
    lua_pushnil(L);
    lua_pushstring(L, error_buf);
    return 2;
  }
  luaL_getmetatable(L, SHA256_CONTEXT_METATABLE);
  lua_setmetatable(L, -2);
  return 1;
}

int l_sha256_update(lua_State *L) {
  lua_settop(L, 2);
  size_t len;
  SHA256_CONTEXT *context = luaL_checkudata(L, 1, SHA256_CONTEXT_METATABLE);
  if (context->closed) {
    lua_pushnil(L);
    lua_pushstring(L, "context already closed");
    return 2;
  }
  const unsigned char *buffer =
      (const unsigned char *)luaL_checklstring(L, 2, &len);
  int ret = mbedtls_sha256_update(context->ctx, buffer, len);
  if (ret != 0) {
    char error_buf[100];                                 // Error buffer
    mbedtls_strerror(ret, error_buf, sizeof(error_buf)); // Translate error code
    lua_pushnil(L);
    lua_pushstring(L, error_buf);
    return 2;
  }
  return 1;
}

int l_sha256_finish(lua_State *L) {
  lua_settop(L, 2);
  SHA256_CONTEXT *context = luaL_checkudata(L, 1, SHA256_CONTEXT_METATABLE);
  if (context->closed) {
    lua_pushnil(L);
    lua_pushstring(L, "context already closed");
    return 2;
  }
  const int hex = lua_toboolean(L, 2);
  unsigned char output[32];
  int ret = mbedtls_sha256_finish(context->ctx, output);
  if (ret != 0) {
    char error_buf[100];                                 // Error buffer
    mbedtls_strerror(ret, error_buf, sizeof(error_buf)); // Translate error code
    lua_pushnil(L);
    lua_pushstring(L, error_buf);
    return 2;
  }
  mbedtls_sha256_free(context->ctx);
  context->closed = 1;
  if (hex) {
    unsigned char hexOutput[64];
    to_hex(output, hexOutput, 32);
    lua_pushlstring(L, (const char *)hexOutput, 64);
  } else {
    lua_pushlstring(L, (const char *)output, 32);
  }
  return 1;
}

int l_sha256_close(lua_State *L) {
  SHA256_CONTEXT *context = luaL_checkudata(L, 1, SHA256_CONTEXT_METATABLE);
  if (context->closed) {
    return 0;
  }
  mbedtls_sha256_free(context->ctx);
  context->closed = 1;
  return 0;
}

int l_sha512_init(lua_State *L) {
  lua_settop(L, 0);
  SHA512_CONTEXT *context = lua_newuserdata(L, sizeof(SHA512_CONTEXT));
  context->ctx = malloc(sizeof(mbedtls_sha512_context));
  context->closed = 0;
  if (context->ctx == NULL) {
    lua_pushnil(L);
    lua_pushstring(L, "failed to allocate memory");
    return 2;
  }
  mbedtls_sha512_init(context->ctx);
  int ret = mbedtls_sha512_starts(context->ctx, 0);
  if (ret != 0) {
    char error_buf[100];                                 // Error buffer
    mbedtls_strerror(ret, error_buf, sizeof(error_buf)); // Translate error code
    lua_pushnil(L);
    lua_pushstring(L, error_buf);
    return 2;
  }
  luaL_getmetatable(L, SHA512_CONTEXT_METATABLE);
  lua_setmetatable(L, -2);
  return 1;
}

int l_sha512_update(lua_State *L) {
  lua_settop(L, 2);
  size_t len;
  SHA512_CONTEXT *context = luaL_checkudata(L, 1, SHA512_CONTEXT_METATABLE);
  if (context->closed) {
    lua_pushnil(L);
    lua_pushstring(L, "context already closed");
    return 2;
  }
  const unsigned char *buffer =
      (const unsigned char *)luaL_checklstring(L, 2, &len);
  int ret = mbedtls_sha512_update(context->ctx, buffer, len);
  if (ret != 0) {
    char error_buf[100];                                 // Error buffer
    mbedtls_strerror(ret, error_buf, sizeof(error_buf)); // Translate error code
    lua_pushnil(L);
    lua_pushstring(L, error_buf);
    return 2;
  }
  return 1;
}

int l_sha512_finish(lua_State *L) {
  lua_settop(L, 2);
  SHA512_CONTEXT *context = luaL_checkudata(L, 1, SHA512_CONTEXT_METATABLE);
  if (context->closed) {
    lua_pushnil(L);
    lua_pushstring(L, "context already closed");
    return 2;
  }
  const int hex = lua_toboolean(L, 2);
  unsigned char output[64];
  int ret = mbedtls_sha512_finish(context->ctx, output);
  if (ret != 0) {
    char error_buf[100];                                 // Error buffer
    mbedtls_strerror(ret, error_buf, sizeof(error_buf)); // Translate error code
    lua_pushnil(L);
    lua_pushstring(L, error_buf);
    return 2;
  }
  mbedtls_sha512_free(context->ctx);
  context->closed = 1;
  if (hex) {
    unsigned char hexOutput[128];
    to_hex(output, hexOutput, 64);
    lua_pushlstring(L, (const char *)hexOutput, 128);
  } else {
    lua_pushlstring(L, (const char *)output, 64);
  }
  return 1;
}

int l_sha512_close(lua_State *L) {
  SHA512_CONTEXT *context = luaL_checkudata(L, 1, SHA512_CONTEXT_METATABLE);
  if (context->closed) {
    return 0;
  }
  mbedtls_sha512_free(context->ctx);
  context->closed = 1;
  return 0;
}

int create_sha256_meta(lua_State *L) {
  luaL_newmetatable(L, SHA256_CONTEXT_METATABLE);

  /* Method table */
  lua_newtable(L);
  lua_pushcfunction(L, l_sha256_update);
  lua_setfield(L, -2, "update");

  lua_pushcfunction(L, l_sha256_finish);
  lua_setfield(L, -2, "finish");

  lua_pushstring(L, SHA256_CONTEXT_METATABLE);
  lua_setfield(L, -2, "__type");

  /* Metamethods */
  lua_setfield(L, -2, "__index");
  lua_pushcfunction(L, l_sha256_close);
  lua_setfield(L, -2, "__gc");
  lua_pushcfunction(L, l_sha256_close);
  lua_setfield(L, -2, "__close");

  return 1;
}

int create_sha512_meta(lua_State *L) {
  luaL_newmetatable(L, SHA512_CONTEXT_METATABLE);

  /* Method table */
  lua_newtable(L);
  lua_pushcfunction(L, l_sha512_update);
  lua_setfield(L, -2, "update");

  lua_pushcfunction(L, l_sha512_finish);
  lua_setfield(L, -2, "finish");

  lua_pushstring(L, SHA512_CONTEXT_METATABLE);
  lua_setfield(L, -2, "__type");

  /* Metamethods */
  lua_setfield(L, -2, "__index");
  lua_pushcfunction(L, l_sha512_close);
  lua_setfield(L, -2, "__gc");
  lua_pushcfunction(L, l_sha512_close);
  lua_setfield(L, -2, "__close");

  return 1;
}