#include "hash.h"
#include "lauxlib.h"
#include "lua.h"

static const struct luaL_Reg lua_hash[] = {
    {"sha256sum", l_sha256sum},
	{"sha512sum", l_sha512sum},
    {"equals", l_equals},
	{"sha256init", l_sha256_init},
    {"sha512init", l_sha512_init},
	{NULL, NULL}};

int luaopen_lmbed_hash(lua_State *L) {
  create_sha256_meta(L);
  create_sha512_meta(L);

  lua_newtable(L);
  luaL_setfuncs(L, lua_hash, 0);
  return 1;
}