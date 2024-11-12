#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pcap.h>
#include <tchar.h>
#include <WinSock2.h>
#include <Windows.h>

#pragma comment(lib, "wpcap")
#pragma comment(lib, "ws2_32")

#pragma pack(push, 1)

typedef struct _EthernetHeader {
    unsigned char dstMac[6];
    unsigned char srcMac[6];
    unsigned short type;
} EthernetHeader_t;

typedef struct _IpHeader {
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
} IpHeader_t;

typedef struct _TcpHeader {
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

typedef struct _UdpHeader {
    unsigned short srcPort;
    unsigned short dstPort;
    unsigned short length;
    unsigned short checksum;
} UdpHeader_t;

typedef struct _PseudoHeader {
    unsigned int srcIp;
    unsigned int dstIp;
    unsigned char zero;
    unsigned char protocol;
    unsigned short length;
} PseudoHeader_t;

#pragma pack(pop)

BOOL LoadDllNpcap() {
    _TCHAR npcap_dir[512];
    UINT len;
    len = GetSystemDirectory(npcap_dir, 512);
    if (!len) {
        fprintf(stderr, "Error in GetSystemDirectory : %d\r\n", GetLastError());
        return FALSE;
    }

    _tscanf_s(npcap_dir, 512, _T("\\Npcap"));
    if (SetDllDirectory(npcap_dir) == 0) {
        fprintf(stderr, "Error in SetDllDirectory : %d\r\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

unsigned short CalculateChecksumIP(IpHeader_t *pIpHeader);

unsigned short CalculateChecksumTCP(IpHeader_t *pIpHeader, TcpHeader_t *pTcpHeader);

int main(int argc, char **argv) {
    pcap_if_t *allDevice;
    pcap_if_t *pDevice;
    pcap_t *pHandler;
    unsigned int deviceCounter = 0;
    unsigned int selectDevice;
    char pcapError[PCAP_ERRBUF_SIZE] = {0,};

    //packet을 보내기 위해서는 pcap에 대한 초기화를 해줘야 한다.
    if (pcap_init(PCAP_CHAR_ENC_LOCAL, pcapError)) {
        fprintf(stderr, "Failed to initialize pcap lib: %s\n", pcapError);
        fflush(stderr);
        return 2;
    }

    if (pcap_findalldevs(&allDevice, pcapError) == -1) {
        fprintf(stderr, "can not found NIC....\r\n");
        fflush(stderr);
        return -1;
    }

    for (pDevice = allDevice; pDevice != NULL; pDevice = pDevice->next) {
        printf("%d. %s ", ++deviceCounter, pDevice->name);
        if (pDevice->description) {
            printf("(%s)\r\n", pDevice->description);
        } else {
            printf("(No Description available)\r\n");
        }
    }

    if (deviceCounter == 0) {
        printf("\r\nNo Interface found! Make sure Npcap is installed\r\n");
        return -1;
    }

    printf("Enter the interface number(1 - %d) : ", deviceCounter);
    scanf_s("%d%*c", &selectDevice);

    if (selectDevice < 1 || selectDevice > deviceCounter) {
        printf("\r\nInterface number out of range\r\n");
        pcap_freealldevs(allDevice);
        return -1;
    }

    for (pDevice = allDevice, deviceCounter = 0;
         deviceCounter < selectDevice - 1; pDevice = pDevice->next, deviceCounter++);

    if ((pHandler = pcap_open_live(
            pDevice->name,
            0,
            0,
            1000,
            pcapError
    )) == NULL) {
        fprintf(stderr, "failed open device : %s, [ERROR] : %s\r\n", pDevice->name, pcapError);
        fflush(stderr);
        return -1;
    }

    pcap_freealldevs(allDevice);

    unsigned char frameData[1514] = {0,};
    int msgSize = 0;

    EthernetHeader_t *pEthernetHeader = (EthernetHeader_t *) (frameData);

    pEthernetHeader->type = htons(0x0800);
    /** TODO Set Destination Mac Address */
    pEthernetHeader->dstMac[0] = 0x0C;
    pEthernetHeader->dstMac[1] = 0x9A;
    pEthernetHeader->dstMac[2] = 0x3C;
    pEthernetHeader->dstMac[3] = 0xE2;
    pEthernetHeader->dstMac[4] = 0xB6;
    pEthernetHeader->dstMac[5] = 0x02;

    /** TODO Set Source Mac Address */
    pEthernetHeader->srcMac[0] = 0xB0;
    pEthernetHeader->srcMac[1] = 0x47;
    pEthernetHeader->srcMac[2] = 0xE9;
    pEthernetHeader->srcMac[3] = 0x75;
    pEthernetHeader->srcMac[4] = 0x2E;
    pEthernetHeader->srcMac[5] = 0x20;

    IpHeader_t *pIpHeader = (IpHeader_t *) (frameData + sizeof(EthernetHeader_t));

    /** TODO Set Destination IP */
    pIpHeader->dstIp[0] = 192;
    pIpHeader->dstIp[1] = 168;
    pIpHeader->dstIp[2] = 45;
    pIpHeader->dstIp[3] = 51;

    /** TODO Set Source IP */
    pIpHeader->srcIp[0] = 192;
    pIpHeader->srcIp[1] = 168;
    pIpHeader->srcIp[2] = 45;
    pIpHeader->srcIp[3] = 26;

    /** ip version and header size setting */
    int ipHeaderSize = sizeof(IpHeader_t);
    printf("ip Header Size : %d\r\n", ipHeaderSize / 4);
    pIpHeader->verIhl = 0x45;
    pIpHeader->tos = 0x00;
    pIpHeader->length = htons(40);
    pIpHeader->id = 0x3412;
    pIpHeader->fragOffset = htons(0x4000); // DF Set -> 단편화 사용 설정
    pIpHeader->ttl = 0xFF;
    pIpHeader->protocol = 0x06; // TCP protocl setting
    pIpHeader->checksum = 0x0000;

    TcpHeader_t *pTcpHeader = (TcpHeader_t *) (frameData + sizeof(EthernetHeader_t) + ipHeaderSize);

    /** tcp header setting */
    /** TODO TCP Chatting Client Port Matching */
    pTcpHeader->srcPort = htons(64972);
    pTcpHeader->dstPort = htons(25000);
    /** TODO Checking client last sequence number Using wire shark */
    pTcpHeader->seq = htonl(0x2f81db84);
    pTcpHeader->ack = 0;
    pTcpHeader->data = 0x50;
    /** RESET Flag Setting */
    pTcpHeader->flags = 0x04;
    pTcpHeader->windowSize = 0x00;
    pTcpHeader->urgent = 0;

    pTcpHeader->checksum = 0x0000;

    pIpHeader->checksum = CalculateChecksumIP(pIpHeader);
    pTcpHeader->checksum = CalculateChecksumTCP(pIpHeader, pTcpHeader);

    if (pcap_sendpacket(pHandler, frameData, sizeof(EthernetHeader_t) + sizeof(IpHeader_t) + sizeof(TcpHeader_t)) !=
        0) {
        fprintf(stderr, "\r\nError sending the packet: %s\r\n", pcap_geterr(pHandler));
    }

    pcap_close(pHandler);

    return 0;
}


unsigned short CalculateChecksumIP(IpHeader_t *pIpHeader) {
    unsigned char ihl = (pIpHeader->verIhl & 0x0F) << 2; //*4와 동일
    unsigned short wData[30] = {0};
    unsigned int dwSum = 0;

    memcpy(wData, (BYTE *) pIpHeader, ihl);
    //((IpHeader*)wData)->checksum = 0x0000;

    for (int i = 0; i < ihl / 2; i++) {
        if (i != 5)
            dwSum += wData[i];

        if (dwSum & 0xFFFF0000) {
            dwSum &= 0x0000FFFF;
            dwSum++;
        }
    }

    return ~(dwSum & 0x0000FFFF);
}

unsigned short CalculateChecksumTCP(IpHeader_t *pIpHeader, TcpHeader_t *pTcpHeader) {
    PseudoHeader_t pseudoHeader = {0};
    unsigned short *pwPseudoHeader = (unsigned short *) &pseudoHeader;
    unsigned short *pwDatagram = (unsigned short *) pTcpHeader;
    int nPseudoHeaderSize = 6; //WORD 6개 배열
    int nSegmentSize = 0; //헤더 포함

    UINT32 dwSum = 0;
    int nLengthOfArray = 0;

    pseudoHeader.srcIp = *(unsigned int *) pIpHeader->srcIp;
    pseudoHeader.dstIp = *(unsigned int *) pIpHeader->dstIp;
    pseudoHeader.zero = 0;
    pseudoHeader.protocol = 6;
    pseudoHeader.length = htons(ntohs(pIpHeader->length) - 20);


    nSegmentSize = ntohs(pseudoHeader.length);

    if (nSegmentSize % 2)
        nLengthOfArray = nSegmentSize / 2 + 1;
    else
        nLengthOfArray = nSegmentSize / 2;

    for (int i = 0; i < nPseudoHeaderSize; i++) {
        dwSum += pwPseudoHeader[i];
        if (dwSum & 0xFFFF0000) {
            dwSum &= 0x0000FFFF;
            dwSum++;
        }
    }

    for (int i = 0; i < nLengthOfArray; i++) {
        if (i != 8)
            dwSum += pwDatagram[i];
        if (dwSum & 0xFFFF0000) {
            dwSum &= 0x0000FFFF;
            dwSum++;
        }
    }

    return (USHORT) ~(dwSum & 0x0000FFFF);
}
