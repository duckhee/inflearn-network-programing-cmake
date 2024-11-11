cmake_minimum_required(VERSION 3.27)

project(chapter0405HttpTrafficExtraction LANGUAGES C VERSION 0.0.1)

message("chapter04-05 HTTP Traffic extraction")

add_executable(chapter0405HttpTrafficExtraction)

if (WIN32 OR WIN64)
    target_link_libraries(chapter0405HttpTrafficExtraction LINK_PRIVATE
            wsock32
            ws2_32
            ${NPCAP}
    )
endif ()

target_sources(chapter0405HttpTrafficExtraction PRIVATE
        main.c
)
