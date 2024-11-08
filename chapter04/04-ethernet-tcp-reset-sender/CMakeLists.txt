cmake_minimum_required(VERSION 3.27)

project(chapter0404EthernetTCPResetSender LANGUAGES C VERSION 0.0.1)

message("chapter04-04 ethernet TCP Reset Sender")

add_executable(chapter0404EthernetTCPResetSender)

if (WIN32 OR WIN64)
    target_link_libraries(chapter0404EthernetTCPResetSender LINK_PRIVATE
            wsock32
            ws2_32
            ${NPCAP}
    )
endif ()

target_sources(chapter0404EthernetTCPResetSender PRIVATE
        main.c
)