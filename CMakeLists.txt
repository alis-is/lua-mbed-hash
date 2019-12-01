cmake_minimum_required (VERSION 2.6)
project (lhash)

include_directories(${CMAKE_BINARY_DIR}/modules/mbedtls/include)
file(GLOB lhash_sources ./src/**.c)
SET(lhash ${lhash_sources})

ADD_LIBRARY (lhash ${lhash})
TARGET_LINK_LIBRARIES (lhash mbedtls)