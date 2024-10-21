cmake_minimum_required(VERSION 3.27)

project(chapter0101SampleBasicDump LANGUAGES C VERSION 0.0.1)

message("chapter01-01 basic dump")

add_executable(chapter0101SampleBasicDump)

target_sources(chapter0101SampleBasicDump PRIVATE
        main.c
)

target_link_libraries(chapter0101SampleBasicDump LINK_PRIVATE
        ws2_32
        wsock32
        ${NPCAP}
)