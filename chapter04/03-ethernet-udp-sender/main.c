#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <WinSock2.h>
#include <pcap.h>
#include <tchar.h>

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

typedef struct _UdpHeader {
    unsigned int srcPort;
    unsigned int dstPort;
    unsigned short length;
    unsigned short checksum;
} UdpHeader_t;

typedef struct _VirtualUdpHeader {
    unsigned int srcIp;
    unsigned int dstIp;
    unsigned char zero;
    unsigned char protocol;
    unsigned short length;
} PseudoHeader_t;

#pragma pack(pop)

unsigned short ipChecksum(IpHeader_t *pIpHeader);

unsigned short udpChecksum(IpHeader_t *pIpHeader, UdpHeader_t *pUdpHeader);

void PacketHandler(u_char *pParam, const struct pcap_pkthdr *header, const u_char *pkt_data);

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

    unsigned char frameData[1514] = {0};
    int msgSize = 0;
    EthernetHeader_t *pEtherHeader = (EthernetHeader_t *) frameData;
    pEtherHeader->dstMac[0] = 0x00;
    pEtherHeader->dstMac[1] = 0x0C;
    pEtherHeader->dstMac[2] = 0x29;
    pEtherHeader->dstMac[3] = 0x35;
    pEtherHeader->dstMac[4] = 0x0D;
    pEtherHeader->dstMac[5] = 0xE1;

    pEtherHeader->srcMac[0] = 0x00;
    pEtherHeader->srcMac[1] = 0x50;
    pEtherHeader->srcMac[2] = 0x56;
    pEtherHeader->srcMac[3] = 0xC0;
    pEtherHeader->srcMac[4] = 0x00;
    pEtherHeader->srcMac[5] = 0x08;

    pEtherHeader->type = 0x0008;

    IpHeader_t *pIpHeader = (IpHeader_t *) (frameData + sizeof(EthernetHeader_t));
    pIpHeader->verIhl = 0x45;
    pIpHeader->tos = 0x00;
    pIpHeader->length = 0;
    pIpHeader->id = 0x3412;
    pIpHeader->fragOffset = 0x0040; //DF
    pIpHeader->ttl = 0xFF;
    pIpHeader->protocol = 17; // UDP
    pIpHeader->checksum = 0x0000;

    pIpHeader->srcIp[0] = 3;
    pIpHeader->srcIp[1] = 3;
    pIpHeader->srcIp[2] = 3;
    pIpHeader->srcIp[3] = 3;

    pIpHeader->dstIp[0] = 192;
    pIpHeader->dstIp[1] = 168;
    pIpHeader->dstIp[2] = 40;
    pIpHeader->dstIp[3] = 128;

    int ipHeaderLen = 20;
    UdpHeader_t *pUdpHeader =
            (UdpHeader_t *) (frameData + sizeof(EthernetHeader_t) + ipHeaderLen);

    pUdpHeader->srcPort = htons(26780);
    pUdpHeader->dstPort = htons(26001);
    pUdpHeader->length = 0;
    pUdpHeader->checksum = 0x0000;


    char szInput[1024];
    char *pPayload = (char *) (frameData + sizeof(EthernetHeader_t) +
                               ipHeaderLen + sizeof(UdpHeader_t));
    while (1) {
        memset(szInput, 0, sizeof(szInput));
        printf("Message: ");
        gets_s(szInput, sizeof(szInput));
        if (strcmp(szInput, "exit") == 0)
            break;

        msgSize = (int) strlen(szInput);
        strcpy_s(pPayload, msgSize + 1, szInput);

        pUdpHeader->length = htons(
                (unsigned short) sizeof(UdpHeader_t) + msgSize);
        pIpHeader->length = htons(
                (unsigned short) (sizeof(IpHeader_t) +
                                  sizeof(UdpHeader_t) + msgSize));

        pIpHeader->checksum = ipChecksum(pIpHeader);
        pUdpHeader->checksum = udpChecksum(pIpHeader, pUdpHeader);

        /* Send down the packet */
        if (pcap_sendpacket(pHandler,    // Adapter
                            frameData, // buffer with the packet
                            sizeof(EthernetHeader_t) + sizeof(IpHeader_t) +
                            sizeof(UdpHeader_t) + msgSize // size
        ) != 0) {
            fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(pHandler));
            break;
        }
    }

    pcap_close(pHandler);

    return 0;
}

unsigned short ipChecksum(IpHeader_t *pIpHeader) {
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

unsigned short udpChecksum(IpHeader_t *pIpHeader, UdpHeader_t *pUdpHeader) {
    PseudoHeader_t pseudoHeader = {0};
    unsigned short *pwPseudoHeader = (unsigned short *) &pseudoHeader;
    unsigned short *pwDatagram = (unsigned short *) pUdpHeader;
    int nPseudoHeaderSize = 6; //WORD 6개 배열
    int nDatagramSize = 0; //헤더 포함 데이터그램 크기

    UINT32 dwSum = 0;
    int nLengthOfArray = 0;


    pseudoHeader.srcIp = *(unsigned int *) pIpHeader->srcIp;
    pseudoHeader.dstIp = *(unsigned int *) pIpHeader->dstIp;
    pseudoHeader.zero = 0;
    pseudoHeader.protocol = 17;
    pseudoHeader.length = pUdpHeader->length;

    nDatagramSize = ntohs(pseudoHeader.length);

    if (nDatagramSize % 2)
        nLengthOfArray = nDatagramSize / 2 + 1;
    else
        nLengthOfArray = nDatagramSize / 2;

    for (int i = 0; i < nPseudoHeaderSize; i++) {
        dwSum += pwPseudoHeader[i];
        if (dwSum & 0xFFFF0000) {
            dwSum &= 0x0000FFFF;
            dwSum++;
        }
    }

    //((UdpHeader*)wData)->checksum = 0x0000;
    for (int i = 0; i < nLengthOfArray; i++) {
        if (i != 3)
            dwSum += pwDatagram[i];
        if (dwSum & 0xFFFF0000) {
            dwSum &= 0x0000FFFF;
            dwSum++;
        }
    }

    return (USHORT) ~(dwSum & 0x0000FFFF);
}

void PacketHandler(u_char *pParam, const struct pcap_pkthdr *header, const u_char *pkt_data) {

}