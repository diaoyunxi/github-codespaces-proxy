cmake_minimum_required(VERSION 3.16)
project(http-over-wss-proxy VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(HWP_BUILD_TESTS "Build self tests" ON)
option(HWP_SHARED_LIB "Build core as shared library (DLL) additionally" ON)
option(HWP_STATIC_LINK "Link OpenSSL/runtime statically on Windows" ON)

if(MSVC)
  add_compile_options(/W4 /utf-8 /EHsc)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
else()
  add_compile_options(-Wall -Wextra)
endif()

# ---- 依赖：OpenSSL ----
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

set(HWP_CORE_SOURCES
  src/common/util.cpp
  src/common/protocol.cpp
  src/common/ssrf.cpp
  src/common/sha1.cpp
  src/common/base64.cpp
  src/common/tcpsocket.cpp
  src/common/stream.cpp
  src/common/websocket.cpp
)

# ---- 核心静态库 ----
add_library(hwp_core STATIC ${HWP_CORE_SOURCES})
target_include_directories(hwp_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(hwp_core PUBLIC OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
if(WIN32)
  target_link_libraries(hwp_core PUBLIC ws2_32 crypt32)
endif()

# ---- 核心动态库（Windows 上的配套 DLL；Linux 上为 .so）----
if(HWP_SHARED_LIB)
  add_library(hwp_core_shared SHARED ${HWP_CORE_SOURCES})
  target_include_directories(hwp_core_shared PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(hwp_core_shared PUBLIC OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
  if(WIN32)
    target_link_libraries(hwp_core_shared PUBLIC ws2_32 crypt32)
    # 动态库对外交付名为 hwp_core.dll，但导入库(.lib)不能与静态库 hwp_core.lib 重名，
    # 否则 Ninja 会报 "multiple rules generate hwp_core.lib"。
    set_target_properties(hwp_core_shared PROPERTIES
      RUNTIME_OUTPUT_NAME "hwp_core"     # -> hwp_core.dll
      ARCHIVE_OUTPUT_NAME "hwp_core_shared")  # -> hwp_core_shared.lib (导入库)
  else()
    set_target_properties(hwp_core_shared PROPERTIES OUTPUT_NAME "hwp_core")
  endif()
  set_target_properties(hwp_core_shared PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR})
endif()

# ---- 服务端可执行文件 ----
add_executable(http-over-wss-server src/server/main.cpp src/server/session_manager.cpp)
target_link_libraries(http-over-wss-server PRIVATE hwp_core)

# ---- 客户端可执行文件 ----
add_executable(http-over-wss-client
  src/client/main.cpp
  src/client/tunnel.cpp
  src/client/local_proxy.cpp)
target_link_libraries(http-over-wss-client PRIVATE hwp_core)

# ---- Release 优化 ----
if(NOT MSVC)
  target_compile_options(hwp_core PRIVATE -O2)
endif()

# ---- 自测 ----
if(HWP_BUILD_TESTS)
  enable_testing()
  add_executable(hwp_selftest tests/selftest.cpp)
  target_link_libraries(hwp_selftest PRIVATE hwp_core)
  add_test(NAME selftest COMMAND hwp_selftest)

  # 端到端联调（可选，需要 node 起测试目标服务）
  find_program(NODE_EXECUTABLE node)
  option(HWP_BUILD_E2E "Register end-to-end tests (needs node + openssl + curl)" OFF)
  if(HWP_BUILD_E2E AND NODE_EXECUTABLE)
    add_test(NAME e2e
             COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/run_e2e.sh .)
    set_tests_properties(e2e PROPERTIES TIMEOUT 180)
  endif()
endif()

# ---- 安装 ----
include(GNUInstallDirs)
install(TARGETS http-over-wss-server http-over-wss-client
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
if(HWP_SHARED_LIB AND NOT WIN32)
  install(TARGETS hwp_core_shared LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()

# ---- 打包（CPack）----
set(CPACK_PACKAGE_NAME "http-over-wss-proxy")
set(CPACK_PACKAGE_VENDOR "diaoyunxi")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_CONTACT "https://gitee.com/diaoyunxi/proxy")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
    "HTTP CONNECT proxy over WebSocket Secure tunnel (tcp-over-wss), no TUN, no driver")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")

if(UNIX AND NOT APPLE)
  set(CPACK_GENERATOR "DEB")
  set(CPACK_DEBIAN_PACKAGE_MAINTAINER "diaoyunxi")
  set(CPACK_DEBIAN_PACKAGE_SECTION "net")
  set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
  set(CPACK_DEBIAN_PACKAGE_DEPENDS "libssl3 | libssl1.1, libc6 (>= 2.28)")
  set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
  set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
  set(CPACK_PACKAGE_FILE_NAME
      "${CPACK_PACKAGE_NAME}_${CPACK_PACKAGE_VERSION}_amd64")
elseif(WIN32)
  set(CPACK_GENERATOR "ZIP")
  set(CPACK_PACKAGE_FILE_NAME
      "${CPACK_PACKAGE_NAME}_${CPACK_PACKAGE_VERSION}_win-amd64")
endif()
include(CPack)
