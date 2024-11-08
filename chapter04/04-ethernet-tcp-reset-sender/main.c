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
    pcap_if_t *pAllDevice;
    pcap_if_t *pDevice;
    pcap_t *pHandler;
    int deviceCounter = 0;
    int selectDevice = 0;
    char errorLog[PCAP_ERRBUF_SIZE];

    if (!LoadDllNpcap()) {
        fprintf(stderr, "Couldn't load npcap\r\n");
        return -1;
    }

    /** pcap initialized check */
    if (pcap_init(PCAP_CHAR_ENC_LOCAL, errorLog) != 0) {
        fprintf(stderr, "Failed pcap initialized : %s\r\n", errorLog);
        return -1;
    }

    if (pcap_findalldevs(&pAllDevice, errorLog) == -1) {
        fprintf(stderr, "Error in pcap_findalldevice: %s\r\n", errorLog);
        return -1;
    }

    for (pDevice = pAllDevice; pDevice != NULL; pDevice = pDevice->next) {
        printf("%d. %s ", ++deviceCounter, pDevice->name);
        if (pDevice->description) {
            printf("(%s)\r\n", pDevice->description);
        } else {
            printf(" (No description available)\n");
        }
    }

    if (deviceCounter == 0) {
        printf("\nNo interfaces found! Make sure Npcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (1-%d):", deviceCounter);
    scanf_s("%d%*c", &selectDevice);

    if (selectDevice < 1 || selectDevice > deviceCounter) {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(pAllDevice);
        return -1;
    }

    for (pDevice = pAllDevice, deviceCounter = 0;
         deviceCounter < selectDevice - 1; pDevice = pDevice->next, deviceCounter++);

    printf("[Ethernet message sender]\n");

    if ((pHandler = pcap_open_live(pDevice->name, 0, 0, 1000, errorLog)) == NULL) {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", pDevice->name);
        return -1;
    }

    pcap_freealldevs(pAllDevice);

    unsigned char frameData[1514] = {0,};
    int msgSize = 0;

    EthernetHeader_t *pEthernetHeader = (EthernetHeader_t *) (frameData);

    pEthernetHeader->type = htons(0x0800);
    /** TODO Set Destination Mac Address */
    pEthernetHeader->dstMac[0] = 0x00;
    pEthernetHeader->dstMac[1] = 0x00;
    pEthernetHeader->dstMac[2] = 0x00;
    pEthernetHeader->dstMac[3] = 0x00;
    pEthernetHeader->dstMac[4] = 0x00;
    pEthernetHeader->dstMac[5] = 0x00;

    /** TODO Set Source Mac Address */
    pEthernetHeader->srcMac[0] = 0x00;
    pEthernetHeader->srcMac[1] = 0x00;
    pEthernetHeader->srcMac[2] = 0x00;
    pEthernetHeader->srcMac[3] = 0x00;
    pEthernetHeader->srcMac[4] = 0x00;
    pEthernetHeader->srcMac[5] = 0x00;

    IpHeader_t *pIpHeader = (IpHeader_t *) (frameData + sizeof(EthernetHeader_t));

    /** TODO Set Destination IP */
    pIpHeader->dstIp[0] = 0;
    pIpHeader->dstIp[1] = 0;
    pIpHeader->dstIp[2] = 0;
    pIpHeader->dstIp[3] = 0;

    /** TODO Set Source IP */
    pIpHeader->srcIp[0] = 0;
    pIpHeader->srcIp[1] = 0;
    pIpHeader->srcIp[2] = 0;
    pIpHeader->srcIp[3] = 0;

    /** ip version and header size setting */
    int ipHeaderSize = sizeof(IpHeader_t);
    printf("ip Header Size : %d\r\n", ipHeaderSize / 4);
    pIpHeader->verIhl = 0x45;
    pIpHeader->tos = 0x00;
    pIpHeader->length = 20;
    pIpHeader->id = 0x3412;
    pIpHeader->fragOffset = htons(0x4000); // DF Set -> 단편화 사용 설정
    pIpHeader->ttl = 0xFF;
    pIpHeader->protocol = 0x06; // TCP protocl setting
    pIpHeader->checksum = 0x0000;

    TcpHeader_t *pTcpHeader = (TcpHeader_t *)(frameData + sizeof(EthernetHeader_t) + ipHeaderSize);

    /** tcp header setting */
    /** TODO TCP Chatting Client Port Matching */
    pTcpHeader->srcPort = htons(55985);
    pTcpHeader->dstPort = htons(25000);
    /** TODO Checking client last sequence number Using wire shark */
    pTcpHeader->seq = htonl(0x1def89c2);

    pTcpHeader->data = 0x50;
    /** RESET Flag Setting */
    pTcpHeader->flags = 0x04;
    pTcpHeader->windowSize = 0x00;

    pTcpHeader->checksum = 0x0000;

    pIpHeader->checksum = CalculateChecksumIP(pIpHeader);
    pTcpHeader->checksum = CalculateChecksumTCP(pIpHeader, pTcpHeader);

    if(pcap_sendpacket(pHandler, frameData, sizeof(EthernetHeader_t ) + sizeof(IpHeader_t ) +sizeof(TcpHeader_t)) != 0){
        fprintf(stderr, "\r\nError sending the packet: %s\r\n", pcap_geterr(pHandler));
    }

    pcap_close(pHandler);

    return 0;
}