cmake_minimum_required(VERSION 3.27)

project(chapter0401EthernetReceiver LANGUAGES C VERSION 0.0.1)

message("chapter04-01 ethernet chatting receiver")

add_executable(chapter0401EthernetReceiver)

target_sources(chapter0401EthernetReceiver PRIVATE
        main.c
)

target_link_libraries(chapter0401EthernetReceiver LINK_PRIVATE
        ${NPCAP}
        wsock32
        ws2_32
)