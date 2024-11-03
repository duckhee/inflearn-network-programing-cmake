cmake_minimum_required(VERSION 3.27)

project(chapter0302ChatMonitor LANGUAGES C VERSION 0.0.1)

message("chapter03-02 chatting packet monitor")

add_executable(chapter0302ChatMonitor)


target_sources(chapter0302ChatMonitor PRIVATE
        main.c
)

target_link_libraries(chapter0302ChatMonitor LINK_PRIVATE
        wsock32
        ws2_32
        ${NPCAP}
)