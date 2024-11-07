cmake_minimum_required(VERSION 3.27)

project(chapter0403UDPReceiver LANGUAGES C VERSION 0.0.1)

message("chapter04-03 UDP Receiver")

add_executable(chapter0403UDPReceiver)

if (WIN32 OR WIN64)
    target_link_libraries(chapter0403UDPReceiver LINK_PRIVATE
            wsock32
            ws2_32
    )
endif ()

target_sources(chapter0403UDPReceiver PRIVATE
        main.c
)