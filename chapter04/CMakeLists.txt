cmake_minimum_required(VERSION 3.27)


add_subdirectory(01-ethernet-chatting-receiver)
add_subdirectory(01-ethernet-chatting-sender)
add_subdirectory(02-udp-ip-checksum)

add_subdirectory(03-ethernet-udp-sender)
add_subdirectory(03-udp-receiver)
add_subdirectory(03-udp-sender)

add_subdirectory(04-ethernet-tcp-reset-sender)
add_subdirectory(04-tcp-chatting-server)
add_subdirectory(04-tcp-chatting-client)

add_subdirectory(05-http-traffic-extraction)