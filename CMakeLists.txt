project(DigestService C CXX)
cmake_minimum_required(VERSION 3.8)
set (CMAKE_CXX_STANDARD 14)

set(cpprestsdk_DIR /usr/lib/${CMAKE_LIBRARY_ARCHITECTURE}/cmake/)
find_package(cpprestsdk REQUIRED)

#special handling for finding openssl package in ubuntu
find_package(PkgConfig REQUIRED)
pkg_search_module(OPENSSL REQUIRED openssl)

if( OPENSSL_FOUND )
    include_directories(${OPENSSL_INCLUDE_DIRS})
    message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
else()
    # Error; with REQUIRED
endif()

set(SRC_DIGEST_SERVICE
    src/DigestService.cpp
)

add_executable(DigestService ${SRC_DIGEST_SERVICE})
target_include_directories(DigestService PRIVATE ${OPENSSL_INCLUDE_DIRS})
target_link_libraries(DigestService cpprest boost_system crypto ssl)

install(TARGETS DigestService
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib/static)

