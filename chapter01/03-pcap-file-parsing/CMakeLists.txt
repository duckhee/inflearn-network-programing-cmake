cmake_minimum_required(VERSION 3.27)

project(chapter0103PcapFileParsing LANGUAGES C VERSION 0.0.1)

message("chapter01-03 pcap file parsing example")

add_executable(chapter0103PcapFileParsing)

target_sources(chapter0103PcapFileParsing PRIVATE
        main.c
)

target_link_libraries(chapter0103PcapFileParsing LINK_PRIVATE
        wsock32
        ws2_32
        ${NPCAP}
)