cmake_minimum_required(VERSION 2.8)

set(APP_NAME AsynchCrypt)
project (${APP_NAME})

option(DEBUG_MODE "Debug or release?" ON)

if(DEBUG_MODE)
    set(CMAKE_BUILD_TYPE DEBUG)
    add_definitions(-D_DEBUG)
else(DEBUG_MODE)
  set(CMAKE_BUILD_TYPE RELEASE)
endif(DEBUG_MODE)

if (MSVC)
    set(CMAKE_C_FLAGS_DEBUG "-DCOCOS2D_DEBUG=1")
    set(CMAKE_CXX_FLAGS_DEBUG ${CMAKE_C_FLAGS_DEBUG})

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_CRT_SECURE_NO_WARNINGS")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_CRT_SECURE_NO_WARNINGS")

elseif (CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
    set(CMAKE_C_FLAGS_DEBUG "-g -Wall -DCOCOS2D_DEBUG=1")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wno-switch -Wno-reorder -Wno-deprecated-declarations -Wno-unused-but-set-variable -Wno-unused-variable -Wno-unused-function")

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

endif()

aux_source_directory(./src MAIN_SRC)
aux_source_directory(./src/tests TESTS_SRC)
aux_source_directory(./src/versions VERSIONS_SRC)
aux_source_directory(./cryptopp CRYPTOPP_SRC)
aux_source_directory(./cryptopp/external EXTERNAL_CRYPTO_SRC)

set(APP_SRC
    ${MAIN_SRC}
    ${TESTS_SRC}
    ${VERSIONS_SRC}
    ${CRYPTOPP_SRC}
    ${EXTERNAL_CRYPTO_SRC}
)

add_executable(${PROJECT_NAME} ${APP_SRC})

