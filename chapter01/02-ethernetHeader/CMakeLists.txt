cmake_minimum_required(VERSION 3.27)

project(chapter0102EthernetHeader LANGUAGES C VERSION 0.0.1)

message("chapter01-02 ethernet header ")

add_executable(chapter0102EthernetHeader)

target_sources(chapter0102EthernetHeader PRIVATE
        main.c
)

target_link_libraries(chapter0102EthernetHeader LINK_PRIVATE
        wsock32
        ws2_32
        ${NPCAP}
)

