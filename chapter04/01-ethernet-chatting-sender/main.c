#include <stdio.h>
#include <time.h>
#include <winsock2.h>
#include <pcap.h>


#pragma comment(lib, "ws2_32")
#pragma comment(lib, "wpcap")
#pragma comment(lib, "Packet")


#pragma pack(push, 1)
typedef struct _EtherHeader
{
    unsigned char dstMac[6];
    unsigned char srcMac[6];
    unsigned short type;
} EtherHeader_t;

typedef struct _IpHeader
{
    unsigned char verIhl;
    unsigned char tos;
    unsigned short length;
    unsigned short id;
    unsigned short flagOffset;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    unsigned char srcIp[4];
    unsigned char dstIp[4];
} IPHeader_t;

typedef struct _TcpHeader
{
    unsigned short srcPort;
    unsigned short dstPort;
    unsigned int seq;
    unsigned int ack;
    unsigned char data;
    unsigned char flags;
    unsigned short windowSize;
    unsigned short checksum;
    unsigned short urgent;
} TcpHeader_t;
#pragma pack(pop)

#ifdef _WIN32
#include <tchar.h>

BOOL LoadNpcapDlls()
{
    _TCHAR npcap_dir[512];
    UINT len;
    len = GetSystemDirectory(npcap_dir, 480);
    if (!len)
    {
        fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
        return FALSE;
    }
    _tcscat_s(npcap_dir, 512, _T("\\Npcap"));
    if (SetDllDirectory(npcap_dir) == 0)
    {
        fprintf(stderr, "Error in SetDllDirectory : %x", GetLastError());
        return FALSE;
    }
    return TRUE;
}
#endif

int main(int argc, char* argv[])
{
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int inum;
    int i = 0;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (!LoadNpcapDlls())
    {
        fprintf(stderr, "Couldn't load Npcap\n");
        exit(1);
    }

    /** pcap initialized -> char setting  */
    if (0 != pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf))
    {
        fprintf(stderr, "Failed to initialize pcap lib: %s\n", errbuf);
        return 2;
    }


    /* Retrieve the device list */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* Print the list */
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0)
    {
        printf("\nNo interfaces found! Make sure Npcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (1-%d):", i);
    scanf_s("%d%*c", &inum);

    if (inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Jump to the selected adapter */
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    /* Open the device */
    /* Open the adapter */
    if ((adhandle = pcap_open_live(d->name, // name of the device
                                   0, // portion of the packet to capture. 0 == no capture.
                                   0,
            // 무차별 전달할 수 있도록 설정하는 것 (none-promiscuous mode) 자기 자신에 해당이 되는 것만 패킷을 보도록 하는 것(promiscuous mode)
                                   1000, // read timeout
                                   errbuf // error buffer
    )) == NULL)
    {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\nlistening on %s...\n", d->description);

    printf("[Ethernet message sender]\n");

    /** 목록 조회를 한 객체 헤제 */
    pcap_freealldevs(alldevs);

    /** 전송할 데이터를 생성할 frame */
    unsigned char frameData[1514] = {0};
    int msgSize = 0;
    /** Ethernet 헤더 설정 */
    EtherHeader_t* pEtherHeader = (EtherHeader_t*)frameData;
    /** broad cast를 위한 MAC 설정 */
    pEtherHeader->dstMac[0] = 0xFF;
    pEtherHeader->dstMac[1] = 0xFF;
    pEtherHeader->dstMac[2] = 0xFF;
    pEtherHeader->dstMac[3] = 0xFF;
    pEtherHeader->dstMac[4] = 0xFF;
    pEtherHeader->dstMac[5] = 0xFF;
    /** 사용자 정의한 비 표준 타입 */
    pEtherHeader->type = 0x0000;
    /** 데이터를 넣어줄 위치 이동 */
    char* pData = (char*)frameData + sizeof(EtherHeader_t);
    char szInput[1024] = {0};

    while (1)
    {
        /** 초기화 */
        memset(pData, 0, 1514 - sizeof(EtherHeader_t));
        /** 메시지를 담아줄 데이터 초기화 */
        memset(szInput, 0, sizeof(szInput));
        /** 수신 받은 메세지 출력 알림 */
        printf("Message: ");
        /** 데이터 입력 대기  */
        gets_s(szInput, sizeof(szInput));
        /** 종료 신호일 경우 */
        if (strcmp(szInput, "exit") == 0)
            break;
        /** 데이터 길이 확인 */
        msgSize = strlen(szInput);
        /** 전송을 위한 값 써주기 */
        strcpy_s(pData, msgSize + 1, szInput);

        /* Send down the packet */
        if (pcap_sendpacket(adhandle, // Adapter
                            frameData, // buffer with the packet
                            sizeof(EtherHeader_t) + msgSize // size
        ) != 0)
        {
            fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(adhandle));
            break;
        }
    }

    pcap_close(adhandle);
    return 0;
}
