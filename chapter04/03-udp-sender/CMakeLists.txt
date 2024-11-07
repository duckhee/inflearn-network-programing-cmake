cmake_minimum_required(VERSION 3.27)

project(chapter0403UDPSender LANGUAGES C VERSION 0.0.1)

message("chapter04-03 UDP Sender")

add_executable(chapter0403UDPSender)

if (WIN32 OR WIN64)
    target_link_libraries(chapter0403UDPSender LINK_PRIVATE
            wsock32
            ws2_32
    )
endif ()

target_sources(chapter0403UDPSender PRIVATE
        main.c
)