#include "lua.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"

/*
---#DES 'SHA256_CONTEXT'
---
---The SHA256_CONTEXT class represents a context for SHA256 hash calculations.
---It provides methods for adding data to the context (`hash.sha256update`) 
---and for finalizing the calculation and producing the final hash (`hash.sha256finish`).
---A SHA256_CONTEXT can be closed explicitly with `hash.sha256close`.
---@class SHA256_CONTEXT
*/
#define SHA256_CONTEXT_METATABLE "SHA256_CONTEXT"
/*
---#DES 'SHA512_CONTEXT'
---
---The SHA512_CONTEXT class represents a context for SHA512 hash calculations.
---It provides methods for adding data to the context (`hash.sha512update`) 
---and for finalizing the calculation and producing the final hash (`hash.sha512finish`).
---A SHA512_CONTEXT can be closed explicitly with `hash.sha512close`.
---@class SHA512_CONTEXT
*/
#define SHA512_CONTEXT_METATABLE "SHA512_CONTEXT"

/*
---#DES 'hash.sha256sum'
---
---Calculates SHA256 hash of the given data.
---@param data string: the data to calculate the hash for.
---@param hex boolean: whether to return the hash as a hexadecimal string.
---@return string|nil, nil|string: the calculated hash, or nil and an error message in case of errors.
*/
int l_sha256sum(lua_State *L);
/*
---#DES 'hash.sha512sum'
---
---Calculates SHA512 hash of the given data.
---@param data string: the data to calculate the hash for.
---@param hex boolean: whether to return the hash as a hexadecimal string.
---@return string|nil, nil|string: the calculated hash, or nil and an error message in case of errors.
*/
int l_sha512sum(lua_State *L);
/*
---#DES 'hash.equals'
---
---Compares two hashes for equality.
---@param hash1 string: the first hash to compare.
---@param hash2 string: the second hash to compare.
---@param hex boolean: whether the hashes are hexadecimal strings.
---@return boolean: true if the hashes are equal, false otherwise.
*/
int l_equals(lua_State *L);

/*
---#DES 'hash.sha256init'
---
---Creates a new SHA256 context.
---If an error occurs during the initialization, 
---the function returns nil and an error message.
---@return SHA256_CONTEXT|nil, nil|string: the new SHA256 context, or nil and an error message in case of errors.
*/
int l_sha256_init(lua_State *L);
/*
---#DES 'SHA256_CONTEXT:update'
---
---Updates this SHA256_CONTEXT with new data. 
---If this context is already closed or an error occurs during the update, 
---the function returns nil and an error message. 
---Otherwise, it returns this SHA256_CONTEXT.
---@param data string: the data to add to this context.
---@return SHA256_CONTEXT|nil, nil|string: this updated context, or nil and an error message in case of errors.
*/
int l_sha256_update(lua_State *L);
/*
---#DES 'SHA256_CONTEXT:finish'
---
---Finalizes this SHA256_CONTEXT and produces the final hash. 
---If this context is already closed or an error occurs during the finalization, 
---the function returns nil and an error message. 
---Otherwise, it returns the final hash.
---@param hex boolean: whether to return the hash as a hexadecimal string.
---@return string|nil, nil|string: the final hash, or nil and an error message in case of errors.
*/
int l_sha256_finish(lua_State *L);

/*
---#DES 'hash.sha512init'
---
---Creates a new SHA512 context.
---If an error occurs during the initialization, 
---the function returns nil and an error message.
---@return SHA512_CONTEXT|nil, nil|string: the new SHA512 context, or nil and an error message in case of errors.
*/
int l_sha512_init(lua_State *L);
/*
---#DES 'SHA512_CONTEXT:update'
---
---Updates this SHA512_CONTEXT with new data. 
---If this context is already closed or an error occurs during the update, 
---the function returns nil and an error message. 
---Otherwise, it returns this SHA512_CONTEXT.
---@param data string: the data to add to this context.
---@return SHA512_CONTEXT|nil, nil|string: this updated context, or nil and an error message in case of errors.
*/
int l_sha512_update(lua_State *L);
/*
---#DES 'SHA512_CONTEXT:finish'
---
---Finalizes this SHA512_CONTEXT and produces the final hash. 
---If this context is already closed or an error occurs during the finalization, 
---the function returns nil and an error message. 
---Otherwise, it returns the final hash.
---@param hex boolean: whether to return the hash as a hexadecimal string.
---@return string|nil, nil|string: the final hash, or nil and an error message in case of errors.
*/
int l_sha512_finish(lua_State *L);

typedef struct SHA256_CONTEXT {
  mbedtls_sha256_context *ctx;
  int closed;
} SHA256_CONTEXT;

typedef struct SHA512_CONTEXT {
  mbedtls_sha512_context *ctx;
  int closed;
} SHA512_CONTEXT;

int create_sha256_meta(lua_State *L);
int create_sha512_meta(lua_State *L);