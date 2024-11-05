cmake_minimum_required(VERSION 3.27)

project(chapter0402UdpIpChecksum LANGUAGES C VERSION 0.0.1)

message("chapter04-02 udp/ip checksum")

add_executable(chapter0402UdpIpChecksum)


target_sources(chapter0402UdpIpChecksum PRIVATE
        main.c
)


target_link_libraries(chapter0402UdpIpChecksum LINK_PRIVATE
        ${NPCAP}
        wsock32
        ws2_32
)