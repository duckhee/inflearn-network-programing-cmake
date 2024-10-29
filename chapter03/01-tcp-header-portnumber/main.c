#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <pcap.h>
#include <time.h>
#include <tchar.h>
#include <WinSock2.h>


#pragma comment(lib, "ws2_32")
#pragma comment(lib, "wpcap")


#pragma pack(push, 1)

typedef struct _EthernetHeader
{
    unsigned char dstMac[6]; // 목적지에 대한 MAC 주소
    unsigned char srcMac[6]; // 출발지에 대한 MAC 주소
    unsigned short type; // 다음 Layer protocol에 대한 값
} EthernetHeader_t;

typedef struct _IpHeader
{
    unsigned char verIhl; // IP Version 정보와 IP Header에 대한 길이 값
    unsigned char tos; // 서비스에 대한 quality에 대한 값
    unsigned short length; // 전체 IP Packet에 대한 길이를 나타내는 값이다.
    unsigned short id; // IP에 대한 식별자 값
    unsigned short fragOffset; // IP에 단편화에 대한 정보 및 offset 값
    unsigned char ttl; // 해당 값이 유효한지 값
    unsigned char protocol; // L4에 대한 protocol 정보 값
    unsigned short checksum; // 해당 값이 유효한지를 나타내는 계산 값
    unsigned char srcIp[4]; // 출발지에 대한 IP 주소
    unsigned char dstIp[4]; // 목적지에 대한 IP 주소
} IpHeader_t;

typedef struct _TcpHeader
{
    unsigned short srcPort; // 출발지 포트 번호
    unsigned short dstPort; // 목적지 포트 번호
    unsigned int seq; // sequence 번호
    unsigned int ack; // acknowledge number
    unsigned char data; // tcp에 대한 Header 길이 정보
    unsigned char flags; // tcp에 대한 flag 값
    unsigned short windowSize; // 수신 버퍼의 여유 공간 정보
    unsigned short checksum; // TCP 데이터가 유효한 값인지 확인하는 값
    unsigned short urgentPointer; // 긴급하게 처리할 데이터 값
} TcpHeader_t;

#pragma pack(1)

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
        fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
        return FALSE;
    }

    return TRUE;
}


void DispatcherHandler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

int main(int argc, char* argv[])
{
    pcap_t* pHandler;
    char errorLog[PCAP_ERRBUF_SIZE];

    if (!LoadNpcapDlls())
    {
        fprintf(stderr, "Couldn't load npcap\r\n");
        exit(1);
    }

    /** pcap file 열기 */
    if ((pHandler = pcap_open_offline("C:\\SampleTraces\\http-browse-ok.pcap", errorLog)) == NULL)
    {
        fprintf(stderr, "\nUnable to open the file %s.\n",
                "C:\\SampleTraces\\http-browse-ok.pcap");
        return -1;
    }

    pcap_loop(pHandler, 0, DispatcherHandler, NULL);
    pcap_close(pHandler);
    return 0;
}


void DispatcherHandler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
    /** Ethernet Header 가져오기 */
    EthernetHeader_t* pEtherHeader = (EthernetHeader_t*)pkt_data;
    /** L3 Frame Protocol IP 인지 확인 */
    if (pEtherHeader->type != 0x0008)
    {
        return;
    }

    IpHeader_t* pIpHeader = (IpHeader_t*)(pkt_data + sizeof(EthernetHeader_t));
    /** TCP Protocol인지 확인 */
    if (pIpHeader->protocol != 6)
    {
        return;
    }

    /** IP Header에 대한 길이 구하기 */
    int ipLen = (pIpHeader->verIhl & 0x0F) * 4;

    /** TCP Header 위치 찾기 */
    TcpHeader_t* pTcpHeader = (TcpHeader_t*)(pkt_data + sizeof(EthernetHeader_t) + ipLen);

    printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
           pIpHeader->srcIp[0], pIpHeader->srcIp[1],
           pIpHeader->srcIp[2], pIpHeader->srcIp[3],
           ntohs(pTcpHeader->srcPort),
           pIpHeader->dstIp[0], pIpHeader->dstIp[1],
           pIpHeader->dstIp[2], pIpHeader->dstIp[3],
           ntohs(pTcpHeader->dstPort)
    );

    if (pTcpHeader->flags == 0x02)
    {
        puts("SYN");
    }
    else if (pTcpHeader->flags == 0x12)
    {
        puts("SYN + ACK");
    }
    else if (pTcpHeader->flags == 0x10)
    {
        puts("ACK");
    }

    if (pTcpHeader->flags & 0x04)
    {
        puts("*RST");
    }
}
