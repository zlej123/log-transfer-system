cmake_minimum_required(VERSION 3.16)
project(log_transfer_system CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

option(ENABLE_ASAN "Build with AddressSanitizer + LeakSanitizer" OFF)
option(ENABLE_TSAN "Build with ThreadSanitizer" OFF)

if(MSVC)
  add_compile_options(/W4)
else()
  add_compile_options(-Wall -Wextra)
endif()
if(MSVC AND (ENABLE_ASAN OR ENABLE_TSAN))
  message(FATAL_ERROR "Sanitizer options are supported by GCC/Clang builds")
elseif(ENABLE_ASAN AND ENABLE_TSAN)
  message(FATAL_ERROR "ENABLE_ASAN and ENABLE_TSAN are mutually exclusive")
elseif(ENABLE_ASAN)
  add_compile_options(-fsanitize=address,undefined -g -O1)
  add_link_options(-fsanitize=address,undefined)
elseif(ENABLE_TSAN)
  add_compile_options(-fsanitize=thread -g -O1)
  add_link_options(-fsanitize=thread)
endif()

find_package(Threads REQUIRED)

# Vendored TLS 1.2+ and SHA-256 implementation (offline/reproducible build).
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "" FORCE)
add_subdirectory(third_party/mbedtls EXCLUDE_FROM_ALL)


# ---------------------------------------------------------------- Linux server
add_executable(log_server
  server/main.cpp
  server/parser.cpp)
target_link_libraries(log_server PRIVATE Threads::Threads mbedtls mbedx509 mbedcrypto)

# --------------------------------------------------- headless CLI test client
add_executable(log_client_cli
  client/cli/main.cpp)
target_link_libraries(log_client_cli PRIVATE Threads::Threads mbedtls mbedx509 mbedcrypto)
if(WIN32)
  target_link_libraries(log_client_cli PRIVATE ws2_32)
endif()

# ------------------------------------------------------------- test log maker
add_executable(loggen
  tools/loggen.cpp)

# ------------------------------------------------------- Windows GUI client
# (built when targeting Windows: native MSVC/MinGW, or the provided
#  scripts/build_windows_client.sh zig cross-compile)
if(WIN32)
  set(IMGUI_DIR ${CMAKE_SOURCE_DIR}/third_party/imgui)
  add_executable(log_client_gui WIN32
    client/gui/main.cpp
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/backends/imgui_impl_win32.cpp
    ${IMGUI_DIR}/backends/imgui_impl_dx11.cpp)
  target_include_directories(log_client_gui PRIVATE
    ${IMGUI_DIR} ${IMGUI_DIR}/backends)
  target_link_libraries(log_client_gui PRIVATE
    d3d11 d3dcompiler_47 dxguid dwmapi gdi32 comdlg32 ole32 uuid shell32
    ws2_32 Threads::Threads mbedtls mbedx509 mbedcrypto)
  if(MSVC)
    target_compile_definitions(log_client_gui PRIVATE UNICODE _UNICODE)
  else()
    target_link_options(log_client_gui PRIVATE -municode -mwindows -Wl,--subsystem,windows)
  endif()
endif()

# ------------------------------------------------------------------ tests
enable_testing()
add_executable(test_parser
  tests/test_parser.cpp
  server/parser.cpp)
add_test(NAME parser_unit COMMAND test_parser)
add_executable(test_protocol tests/test_protocol.cpp)
add_executable(test_checksum_rejection tests/test_checksum_rejection.cpp)
target_link_libraries(test_checksum_rejection PRIVATE Threads::Threads mbedtls mbedx509 mbedcrypto)
add_executable(test_result_retry tests/test_result_retry.cpp)
target_link_libraries(test_result_retry PRIVATE Threads::Threads mbedtls mbedx509 mbedcrypto)
target_link_libraries(test_protocol PRIVATE mbedcrypto)
add_test(NAME protocol_unit COMMAND test_protocol)
if(NOT WIN32)
  add_executable(test_thread_pool tests/test_thread_pool.cpp)
  target_link_libraries(test_thread_pool PRIVATE Threads::Threads)
  add_test(NAME thread_pool_unit COMMAND test_thread_pool)
  add_executable(test_upload_store tests/test_upload_store.cpp)
  target_link_libraries(test_upload_store PRIVATE mbedcrypto)
  add_test(NAME upload_store_unit COMMAND test_upload_store)
endif()
if(NOT WIN32)
  add_test(NAME e2e
    COMMAND bash ${CMAKE_SOURCE_DIR}/tests/run_e2e.sh
            $<TARGET_FILE_DIR:log_server>)
  set_tests_properties(e2e PROPERTIES TIMEOUT 240)
endif()
