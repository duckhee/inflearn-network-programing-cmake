#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <WinSock2.h>
#include <ws2tcpip.h>

void ErrorHandler(const char *error);

int main(int argc, char **argv) {
    WSADATA wsaData;
    SOCKET hSocket;
    SOCKET hClient;
    SOCKADDR_IN addr = {0,};
    SOCKADDR_IN remoteAddr = {0,};
    int remoteAddrLen = sizeof(remoteAddr);
    int nReceiveSize = 0;
    char szIp[128] = {0,};
    char szBuffer[128] = {0,};

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        ErrorHandler("WIN SOCKET Initialized Failed...");
    }

    hSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (hSocket == INVALID_SOCKET) {
        ErrorHandler("create socket Failed...");
    }

    addr.sin_family = PF_INET;
    addr.sin_port = htons(26001);
    addr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);

    int isBind = bind(hSocket, (SOCKADDR *) &addr, sizeof(addr));

    if (isBind == SOCKET_ERROR) {
        ErrorHandler("socket binding Error...");
    }

    while ((nReceiveSize = recvfrom(hSocket, szBuffer, sizeof(szBuffer), 0, (SOCKADDR *) &remoteAddr, &remoteAddrLen)) >
           0) {

        inet_ntop(PF_INET, &remoteAddr.sin_addr, szIp, sizeof(szIp));
        printf("%s receive[%dbyte] : %s\r\n", szIp, nReceiveSize, szBuffer);
        memset(szBuffer, '\0', sizeof(szBuffer));
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