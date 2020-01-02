#ifdef _WIN32
  #define HASH_EXPORT __declspec (dllexport)
#else
  #define HASH_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

HASH_EXPORT int luaopen_lmbed_hash (lua_State *L);

#ifdef __cplusplus
}
#endif