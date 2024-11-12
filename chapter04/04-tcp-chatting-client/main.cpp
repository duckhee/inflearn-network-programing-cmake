#include <iostream>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <Windows.h>

DWORD WINAPI ThreadReceiver(LPVOID pParam);

void ErrorHandler(const char *msg);

int main(int argc, char *argv[]) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        ErrorHandler("Failed Window socket Initialize...");
    }

    SOCKET hClient = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (hClient == INVALID_SOCKET) {
        ErrorHandler("Failed Socket Creation...");
    }

    SOCKADDR_IN serverAddr = {0,};
    serverAddr.sin_family = PF_INET;
    inet_pton(PF_INET, "192.168.45.51", &serverAddr.sin_addr);
    serverAddr.sin_port = htons(25000);

    if (::connect(hClient, (SOCKADDR *) &serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        ErrorHandler("Failed Socket Connection...");
    }

    DWORD dwThreadID = 0;
    HANDLE hThread = ::CreateThread(
            NULL,
            0,
            ThreadReceiver,
            (LPVOID) hClient,
            0,
            &dwThreadID
    );

    ::CloseHandle(hThread);

    char szBuffer[128];
    puts("채팅을 시작합니다. 메시지를 입력하세요.");

    while (true) {
        memset(szBuffer, 0, sizeof(szBuffer));
        gets_s(szBuffer);
        if (strcmp(szBuffer, "EXIT") == 0) {
            break;
        }

        ::send(hClient, szBuffer, (int) strlen(szBuffer) + 1, 0);
    }

    ::closesocket(hClient);
    ::Sleep(100);
    ::WSACleanup();

    return 0;
}


DWORD WINAPI ThreadReceiver(LPVOID pParam) {
    SOCKET hClient = (SOCKET) pParam;
    char szBuffer[128] = {0,};
    while (::recv(hClient, szBuffer, sizeof(szBuffer), 0) > 0) {
        printf(" -> %s\r\n", szBuffer);
        memset(szBuffer, '\0', sizeof(szBuffer));
    }
    puts("수신 스레드가 끝났습니다.");
    return 0;
}

void ErrorHandler(const char *msg) {
    fprintf(stderr, "ERROR : %s\r\n", msg);
    fflush(stderr);
    exit(1);
}
