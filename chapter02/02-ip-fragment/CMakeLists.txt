cmake_minimum_required(VERSION 3.27)

project(chapter0202IpFragments LANGUAGES C VERSION 0.0.1)

message("chapter02-02 ip fragments")

add_executable(chapter0202IpFragments)

target_sources(chapter0202IpFragments PRIVATE
        main.c
)

target_link_libraries(chapter0202IpFragments LINK_PRIVATE
        wsock32
        ws2_32
        ${NPCAP}
)