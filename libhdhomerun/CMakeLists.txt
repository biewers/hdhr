cmake_minimum_required(VERSION 3.4)
project(hdhomerun_config)

set(LIBSRCS
    hdhomerun_channels.c
    hdhomerun_channelscan.c
    hdhomerun_control.c
    hdhomerun_debug.c
    hdhomerun_device.c
    hdhomerun_device_selector.c
    hdhomerun_discover.c
    hdhomerun_os_posix.c
    hdhomerun_pkt.c
    hdhomerun_sock_posix.c
    hdhomerun_video.c)

set(CMAKE_CXX_FLAGS
    -fPIC -DDLL_EXPORT
    -O2 -Wall -Wextra -Wmissing-declarations -Wmissing-prototypes -Wstrict-prototypes -Wpointer-arith -Wno-unused-parameter
    -arch i386 -arch x86_64
)
set(CMAKE_LINKER_FLAGS -lpthread)

add_library(hdhomerun SHARED ${LIBSRCS})
add_executable(hdhomerun_config hdhomerun_config.c)
target_link_libraries(hdhomerun_config hdhomerun)
