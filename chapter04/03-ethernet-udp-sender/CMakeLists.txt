cmake_minimum_required(VERSION 3.27)

project(chapter0403EthernetUDPSender LANGUAGES C VERSION 0.0.1)

message("chapter04-03 ethernet udp sender")

add_executable(chapter0403EthernetUDPSender)

if (WIN32 OR WIN64)
    target_link_libraries(chapter0403EthernetUDPSender LINK_PRIVATE
            ${NPCAP}
            wsock32
            ws2_32
    )
endif ()

target_sources(chapter0403EthernetUDPSender PRIVATE
        main.c
)