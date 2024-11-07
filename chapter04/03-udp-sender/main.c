#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <WinSock2.h>
#include <ws2tcpip.h>

void ErrorHandler(const char *error);

int main(int argc, char **argv) {
    WSADATA wsaData;
    SOCKET hSocket;
    SOCKADDR_IN remoteAddr;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        ErrorHandler("winsocket Initialized Failed...");
    }

    hSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (hSocket == INVALID_SOCKET) {
        ErrorHandler("SOCKET Create Failed...");
    }

    remoteAddr.sin_family = PF_INET;
    remoteAddr.sin_port = htons(26001);
    inet_pton(PF_INET, "<IP>", &remoteAddr.sin_addr.S_un.S_addr);

    char szBuffer[128] = {0,};

    while (TRUE) {
        memset(szBuffer, '\0', sizeof(szBuffer));
        gets_s(szBuffer, sizeof(szBuffer));
        if (strcmp(szBuffer, "exit") == 0) {
            break;
        }
        sendto(hSocket, szBuffer, sizeof(szBuffer), 0, (SOCKADDR *) &remoteAddr, sizeof(remoteAddr));
    }

    closesocket(hSocket);
    WSACleanup();
    return 0;
}

void ErrorHandler(const char *error) {
    fprintf(stderr, "ERROR : %s\r\n", error);
    fflush(stderr);
    WSACleanup();
    exit(1);
}