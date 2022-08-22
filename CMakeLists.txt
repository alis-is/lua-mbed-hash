project (lhash)

include_directories(${CMAKE_BINARY_DIR}/modules/mbedtls/include)
file(GLOB lhash_sources ./src/**.c)
set(lhash ${lhash_sources})

add_library(lhash ${lhash})
target_link_libraries(lhash mbedtls)