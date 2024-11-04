cmake_minimum_required(VERSION 3.27)

project(chapter0401EthernetChattingSender LANGUAGES C VERSION 0.0.1)

message("chapter04-01 ethernet chatting sender")

add_executable(chapter0401EthernetChattingSender)

target_sources(chapter0401EthernetChattingSender PRIVATE
        main.c
)

target_link_libraries(chapter0401EthernetChattingSender LINK_PRIVATE
        ${NPCAP}
        wsock32
        ws2_32
)