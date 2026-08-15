cmake_minimum_required(VERSION 3.16)
project(log_transfer_system CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

option(ENABLE_ASAN "Build with AddressSanitizer + LeakSanitizer" OFF)

add_compile_options(-Wall -Wextra)
if(ENABLE_ASAN)
  add_compile_options(-fsanitize=address,undefined -g -O1)
  add_link_options(-fsanitize=address,undefined)
endif()

find_package(Threads REQUIRED)

# ---------------------------------------------------------------- Linux server
add_executable(log_server
  server/main.cpp
  server/parser.cpp)
target_link_libraries(log_server PRIVATE Threads::Threads)

# --------------------------------------------------- headless CLI test client
add_executable(log_client_cli
  client/cli/main.cpp)
target_link_libraries(log_client_cli PRIVATE Threads::Threads)
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
    d3d11 d3dcompiler dxguid dwmapi gdi32 comdlg32 ole32 uuid shell32
    ws2_32 Threads::Threads)
  if(MSVC)
    target_compile_definitions(log_client_gui PRIVATE UNICODE _UNICODE)
  else()
    target_link_options(log_client_gui PRIVATE -municode -mwindows)
  endif()
endif()
