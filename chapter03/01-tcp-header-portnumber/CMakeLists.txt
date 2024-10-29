cmake_minimum_required(VERSION 3.27)

project(chapter0301TcpHeaderPortNumberGet LANGUAGES C VERSION 0.0.1)

message("chapter03-01 tcp header get port number")

add_executable(chapter0301TcpHeaderPortNumberGet)

target_sources(chapter0301TcpHeaderPortNumberGet PRIVATE
        main.c
)

target_link_libraries(chapter0301TcpHeaderPortNumberGet LINK_PRIVATE
        wsock32
        ws2_32
        ${NPCAP}
)