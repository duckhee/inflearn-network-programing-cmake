cmake_minimum_required(VERSION 3.27)

project(chapter0201IpHeaderAnalyticsBasic LANGUAGES C VERSION 0.0.1)

message("chapter02-01 ip header basic analytics")

add_executable(chapter0201IpHeaderAnalyticsBasic)

target_sources(chapter0201IpHeaderAnalyticsBasic PRIVATE
        main.c
)

target_link_libraries(chapter0201IpHeaderAnalyticsBasic LINK_PRIVATE
        wsock32
        ws2_32
    ${NPCAP}
)