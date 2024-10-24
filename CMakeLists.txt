cmake_minimum_required(VERSION 3.27)

project(inflearn_network_programing)

# window 사용 시 해당 npcap 이용하도록 조건문
if (WIN32 OR WIN64)

    include_directories(library/Include)

    #find_library(wpcap NAMES wpcap.lib HINTS library/LIBS/x64 REQUIRED)

    #find_library(Packet NAMES Packet.lib HINTS library/LIBS/x64 REQUIRED)

    # 라이브러리를 직접 추가할 때 사용을 한다.
    find_library(NPCAP REQUIRED
            NAMES wpcap.lib Packet.lib
            PATHS library/LIBS/x64
    )
endif ()

add_subdirectory(chapter01)
add_subdirectory(chapter02)