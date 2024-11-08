cmake_minimum_required(VERSION 3.27)

project(chapter0404TCPChattingClient LANGUAGES CXX VERSION 0.0.1)

message("chapter04-04 TCP Chatting client")

add_executable(chapter0404TCPChattingClient)

if (WIN32 OR WIN64)
    target_link_libraries(chapter0404TCPChattingClient LINK_PRIVATE
            wsock32
            ws2_32
    )
endif ()

target_sources(chapter0404TCPChattingClient PRIVATE
        main.cpp
)