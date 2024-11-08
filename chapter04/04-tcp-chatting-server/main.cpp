#include <iostream>
#include <string>
#include <WinSock2.h>
#include <ws2tcpip.h>

#include <Windows.h>
#include <list>
#include <iterator>

/** Client 추가 및 제거 시 Lock을 하기 위한 Critical Section */
CRITICAL_SECTION g_criticalSection;

/** server socket */
SOCKET g_hServerSocket;
/** client socket */
std::list<SOCKET> g_clientList;

void ErrorHandler(const char* msg);

BOOL AddClient(SOCKET hClientSocket);

void SendChattingMessage(const char* pszMsg);

BOOL CtrlHandler(DWORD dwType);

DWORD WINAPI SenderThread(PVOID pParam);

int main(int argc, char* argv[])
{
    WSAData wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        ErrorHandler("Win Socket Initialized Failed...");
    }
    /** 임계구간 사용을 하기 위한 Critical section 초기화 */
    ::InitializeCriticalSection(&g_criticalSection);

    if (::SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE) == FALSE)
    {
        puts("ERROR: Ctrl + C 처리를 등록할 수 없습니다.");
    }

    g_hServerSocket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_hServerSocket == INVALID_SOCKET)
    {
        ErrorHandler("Socket Creation Failed...");
    }

    SOCKADDR_IN serverAddr = {0,};
    serverAddr.sin_family = PF_INET;
    serverAddr.sin_port = htons(25000);
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (::bind(g_hServerSocket, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        ErrorHandler("Bind Failed...");
    }

    if (::listen(g_hServerSocket, SOMAXCONN) == SOCKET_ERROR)
    {
        ErrorHandler("Listen Failed...");
    }

    puts("*** The Server has Started. ***");

    SOCKADDR_IN clientAddr = {0,};
    int clientAddrLen = sizeof(clientAddr);
    SOCKET hClient = 0;
    DWORD dwThreadID = 0;
    HANDLE hThread;

    /** client 연결 후 Thread 생성 */
    while ((hClient = ::accept(g_hServerSocket, (SOCKADDR*)&clientAddr, &clientAddrLen)) != INVALID_SOCKET)
    {
        if (AddClient(hClient) == FALSE)
        {
            puts("ERROR : 더 이상 클라이언트 연결을 처리할 수 없습니다.");
            CtrlHandler(CTRL_C_EVENT);
            break;
        }

        /** client Thread 생성 */
        hThread = ::CreateThread(
                NULL, // 보안에 대한 속성 정의 -> NULL의 경우 부모 보안 속성을 상속
                0, // Thread가 가질 Stack Size 0의 경우 기본 값인 1MB
                SenderThread, // Thread가 동작할 기능에 대한 함수
                (LPVOID)hClient, // Thread에 넘겨줄 parameter
                0, // Thread 생성에 대한 설정 -> 0의 경우 기본 값 사용
                &dwThreadID // 생성된 Thread ID 저장할 변수
        );

        ::CloseHandle(hThread);
    }

    puts("*** The server has shutdown. ***");
    WSACleanup();
    return 0;
}


void ErrorHandler(const char* msg)
{
    fprintf(stderr, "ERROR : %s\r\n", msg);
    fflush(stderr);
    exit(1);
}


BOOL AddClient(SOCKET hClientSocket)
{
    /** client 추가하기 전에 Lock을 이용한 동기화 */
    ::EnterCriticalSection(&g_criticalSection);
    /** 한개의 Thread에서만 접근이 가능하기 때문에 해당 값에 대한 보장이 된다. */
    g_clientList.push_back(hClientSocket);
    /** client 추가 후 lock 반환 */
    ::LeaveCriticalSection(&g_criticalSection);
    return true;
}

void SendChattingMessage(const char* pszMsg)
{
    /** message size */
    int msgSize = strlen(pszMsg);
    /** iterator로 반복을 하기 위한 iterator 생성 */
    std::list<SOCKET>::iterator it;

    /** 데이터 전송 중에 client 추가 및 삭제가 되지 않도록 하기 위한 Lock */
    ::EnterCriticalSection(&g_criticalSection);
    /** client list 순회 */
    for (it = g_clientList.begin(); it != g_clientList.end(); ++it)
    {
        /** client 마다 데이터 전송 */
        ::send(*it, pszMsg, sizeof(char) * msgSize + 1, 0);
    }
    /** 데이터 전송 중에 client 추가 및 삭제가 되지 않도록 하기 위한 Lock 반환 */
    ::LeaveCriticalSection(&g_criticalSection);
}

BOOL CtrlHandler(DWORD dwType)
{
    if (dwType == CTRL_C_EVENT)
    {
        /** 종료 신호를 보내기 위해서 client 순회 접근을 위한 iterator */
        std::list<SOCKET>::iterator it;
        /** 서버의 연결을 위한 소켓 종료 요청 */
        ::shutdown(g_hServerSocket, SD_BOTH);
        /** socket을 닫기 위해서 list 접근 해당 값에 대한 Lock 걸기 */
        ::EnterCriticalSection(&g_criticalSection);
        for (it = g_clientList.begin(); it != g_clientList.end(); ++it)
        {
            /** client socket 닫기 */
            ::closesocket(*it);
        }
        /** socket을 닫은 후 list 접근 해당 값에 대한 Lock 해제 */
        ::LeaveCriticalSection(&g_criticalSection);

        puts("All Session are closed.");
        /** client 연결 종료 대기하기 위한 sleep */
        ::Sleep(100);
        /** Critical section에 대한 자원 반환 */
        ::DeleteCriticalSection(&g_criticalSection);
        /** 서버 소켓 종료 */
        ::closesocket(g_hServerSocket);
        ::WSACleanup();
        exit(0);
        return true;
    }
    return false;
}

/** Multi Thread 형식의 데이터 보내는 것 -> client 수만큼 Thread가 생성이 된다. */
DWORD WINAPI SenderThread(PVOID pParam)
{
    char msgBuffer[128] = {0,};
    int nReceive = 0;
    SOCKET hClient = (SOCKET)pParam;
    char ipBuffer[128];

    SOCKADDR_IN remoteAddr;
    socklen_t remoteAddrLen = sizeof(remoteAddr);
    /** client 에 대한 정보 가져오기 */
    getpeername(hClient, (struct sockaddr*)&remoteAddr, &remoteAddrLen);
    /** IP 주소 가져오기 */
    inet_ntop(PF_INET, &remoteAddr.sin_addr, ipBuffer, sizeof(ipBuffer));

    puts("*** new client ***");
    while ((nReceive = ::recv(hClient, msgBuffer, sizeof(msgBuffer), 0) > 0))
    {
        printf("%s: %s\r\n", ipBuffer, msgBuffer);
        SendChattingMessage(msgBuffer);
        memset(msgBuffer, '\0', sizeof(msgBuffer));
    }
    puts("Closed By Client");
    ::EnterCriticalSection(&g_criticalSection);
    g_clientList.remove(hClient);
    ::LeaveCriticalSection(&g_criticalSection);

    ::closesocket(hClient);
    return 0;
}
