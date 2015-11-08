project(AsynchCrypt)
cmake_minimum_required(VERSION 2.8)

aux_source_directory(. MAIN_SRC)
aux_source_directory(./cryptopp CRYPTOPP_SRC)

set(APP_SRC
    ${MAIN_SRC}
    ${CRYPTOPP_SRC}
)

add_executable(${PROJECT_NAME} ${APP_SRC})

