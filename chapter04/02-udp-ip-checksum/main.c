#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>
#pragma comment(lib, "wpcap")
#pragma comment(lib, "ws2_32")

#include <tchar.h>

#pragma pack(push, 1)
typedef struct EtherHeader
{
    unsigned char dstMac[6];
    unsigned char srcMac[6];
    unsigned short type;
} EtherHeader;


typedef struct IpHeader
{
    unsigned char verIhl;
    unsigned char tos;
    unsigned short length;
    unsigned short id;
    unsigned short fragOffset;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    unsigned char srcIp[4];
    unsigned char dstIp[4];
} IpHeader;

typedef struct UdpHeader
{
    unsigned short srcPort;
    unsigned short dstPort;
    unsigned short length;
    unsigned short checksum;
} UdpHeader;

typedef struct PseudoHeader
{
    unsigned int srcIp;
    unsigned int dstIp;
    unsigned char zero;
    unsigned char protocol;
    unsigned short length;
} PseudoHeader;

#pragma pack(pop)

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
        fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
        return FALSE;
    }
    return TRUE;
}

void PacketHandler(u_char* param, const struct pcap_pkthdr* header, const u_char* packet);
unsigned short IpFrameCalculateChecksum(IpHeader* pIpHeader);
unsigned short UpdFrameCalculateChecksum(IpHeader* pIpHeader, UdpHeader* pUdpHeader);

int main(int argc, char* argv[])
{
    pcap_t* pHandler;
    char errorBuf[PCAP_ERRBUF_SIZE];

    if (!LoadNpcapDlls())
    {
        fprintf(stderr, "Couldn't load npcap\r\n");
        exit(1);
    }

    if ((pHandler = pcap_open_offline(
            "C:\\SampleTraces\\udp-echo.pcap",
            errorBuf)) == NULL)
    {
        fprintf(stderr, "\nUnable to open the file %s.\n",
                "C:\\SampleTraces\\udp-echo.pcap");
        return -1;
    }

    pcap_loop(pHandler, 0, PacketHandler, NULL);

    pcap_close(pHandler);

    return 0;
}

void PacketHandler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
    EtherHeader* pEther = (EtherHeader*)pkt_data;
    IpHeader* pIpHeader = (IpHeader*)(pkt_data + sizeof(EtherHeader));

    if (pEther->type != 0x0008)
        return;

    if (pIpHeader->protocol != 17)
        return;

    int ipHeaderLen = (pIpHeader->verIhl & 0x0F) * 4;

    UdpHeader* pUdpHeader =
            (UdpHeader*)(pkt_data + sizeof(EtherHeader) + ipHeaderLen);


    printf("%d.%d.%d.%d -> %d.%d.%d.%d\n",
           pIpHeader->srcIp[0], pIpHeader->srcIp[1],
           pIpHeader->srcIp[2], pIpHeader->srcIp[3],
           pIpHeader->dstIp[0], pIpHeader->dstIp[1],
           pIpHeader->dstIp[2], pIpHeader->dstIp[3]
    );

    printf("IP header checksum: %04X, Calculated checksum: %04X\n",
           pIpHeader->checksum, IpFrameCalculateChecksum(pIpHeader));
    printf("UDP checksum: %04X, Calculated checksum: %04X\n\n",
           pUdpHeader->checksum, UpdFrameCalculateChecksum(pIpHeader, pUdpHeader));
}

unsigned short IpFrameCalculateChecksum(IpHeader* pIpHeader)
{
    unsigned char ihl = (pIpHeader->verIhl & 0x0F) << 2; // 곱하기 4와 동일한 shift 연산
    unsigned short wData[30] = {0,};
    unsigned int dwSum = 0;

    memcpy(wData, (BYTE*)pIpHeader, ihl);
    // ((IpHeader *)wData)->checksum = 0x0000;
    /** 2byte 단위로 짤라서 확인을 하기 때문에 전체 길이를 2byte 단위로 나눠서 사용을 한다. */
    for (int i = 0; i < ihl / 2; i++)
    {
        /** IP Header에 있는 checksum에 대한 field는 제외 */
        if (i != 5)
        {
            dwSum += wData[i];
        }
        /** checkusm으로 표현을 할 수 있는 크기를 넘어갈 경우 버린다.*/
        if (dwSum & 0xFFFF0000)
        {
            dwSum &= 0x0000FFFF;
            dwSum++;
        }
    }

    return ~(dwSum & 0x0000FFFF);
}

unsigned short UpdFrameCalculateChecksum(IpHeader* pIpHeader, UdpHeader* pUdpHeader)
{
    // UDP checksum을 계산하기 위한 가상 헤더 데이터
    PseudoHeader pseudoHeader = {0,};
    unsigned short* pwPseudoHeader = (unsigned short*)&pseudoHeader;
    unsigned short* pwDatagram = (unsigned short*)pUdpHeader;
    int nPseudoHeaderSize = 6; // WORD 6개 배열
    int nDatagramSize = 0; // 헤더 포함 데이터그램 크기 담아줄 변수
    UINT32 dwSum = 0;
    int nLengthOfArray = 0;

    pseudoHeader.srcIp = *(unsigned int*)pIpHeader->srcIp;
    pseudoHeader.dstIp = *(unsigned int*)pIpHeader->dstIp;
    pseudoHeader.zero = 0;
    pseudoHeader.protocol = 17; // UDP protocol number
    pseudoHeader.length = pUdpHeader->length;

    // UDP 데이터 길이
    nDatagramSize = ntohs(pseudoHeader.length);

    if (nDatagramSize % 2)
    {
        nLengthOfArray = nDatagramSize / 2 + 1;
    }
    else
    {
        nLengthOfArray = nDatagramSize / 2;
    }

    // 가상 UDP header에 대한 checksum 계산
    for (int i = 0; i < nPseudoHeaderSize; i++)
    {
        dwSum += pwPseudoHeader[i];
        if (dwSum & 0xFFFF0000)
        {
            dwSum &= 0x0000FFFF;
            dwSum++;
        }
    }

    // 전치 길이를 가지고 checksum 계산
    for (int i = 0; i < nLengthOfArray; i++)
    {
        if (i != 3)
        {
            dwSum += pwDatagram[i];
        }
        if (dwSum & 0xFFFF0000)
        {
            dwSum &= 0x0000FFFF;
            dwSum++;
        }
    }
    return (USHORT)~(dwSum & 0x0000FFFF);
}
