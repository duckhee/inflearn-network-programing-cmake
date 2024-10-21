cmake_minimum_required(VERSION 3.27)

project(inflearn_network_programing)


include_directories(library/Include)

#find_library(wpcap NAMES wpcap.lib HINTS library/Dll/x64 REQUIRED)

#find_library(Packet NAMES Packet.lib HINTS library/Dll/x64 REQUIRED)

# 라이브러리를 직접 추가할 때 사용을 한다.
find_library(NPCAP REQUIRED
        NAMES wpcap.lib Packet.lib
        PATHS library/Dll/x64
)

add_subdirectory(chapter01)
