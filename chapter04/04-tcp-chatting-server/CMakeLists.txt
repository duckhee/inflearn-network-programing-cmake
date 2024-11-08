cmake_minimum_required(VERSION 3.27)

project(chapter0404TCPChattingServer LANGUAGES CXX VERSION 0.0.1)

message("chapter04-04 TCP Chatting Server")

add_executable(chapter0404TCPChattingServer)

if (WIN32 OR WIN64)
    target_link_libraries(chapter0404TCPChattingServer LINK_PRIVATE
            wsock32
            ws2_32
    )
endif ()

target_sources(chapter0404TCPChattingServer PRIVATE
        main.cpp
)