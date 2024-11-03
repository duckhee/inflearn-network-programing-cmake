#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <pcap.h>
#include <tchar.h>
#include <time.h>
#include <WinSock2.h>
#include <windows.h>

#pragma comment(lib, "wpcap")
#pragma comment(lib, "ws2_32")


#pragma pack(push, 1)
typedef struct _EtherHeader {
    unsigned char dstMac[6];
    unsigned char srcMac[6];
    unsigned short type;
} EtherHeader_t;

typedef struct _IpHeader {
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
#pragma pack(pop)


BOOL LoadNpcapDlls() {
    _TCHAR npcap_dir[512];
    UINT len;
    len = GetSystemDirectory(npcap_dir, 480);
    if (!len) {
        fprintf(stderr, "ERROR in GetSystemDirectory : %lx\r\n", GetLastError());
        return FALSE;
    }

    _tcscat_s(npcap_dir, 512, _T("\\Npcap"));
    if (SetDllDirectory(npcap_dir) == 0) {
        fprintf(stderr, "ERROR is SetDllDirectory : %lx\r\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

void packetHandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);


int main(int argc, char **argv) {
    pcap_if_t *allDevices;
    pcap_if_t *pDevice;
    int deviceNumber = 0;
    int selectedIndex = 0;
    pcap_t *pDeviceHandler;

    char errorBuffer[PCAP_ERRBUF_SIZE];

    if (!LoadNpcapDlls()) {
        fprintf(stderr, "Couldn't load npcap\r\n");
        return -1;
    }

    int findAllDeviceNic = pcap_findalldevs(&allDevices, errorBuffer);

    if (findAllDeviceNic == -1) {
        fprintf(stderr, "Error in pcap_findalldevs : %s\r\n", errorBuffer);
        return -1;
    }

    for (pDevice = allDevices; pDevice; pDevice = pDevice->next) {
        printf("%d. %s", ++deviceNumber, pDevice->name);
        if (pDevice->description) {
            printf("(%s)\r\n", pDevice->description);
        } else {
            printf("(No description available)\r\n");
        }
    }

    if (deviceNumber == 0) {
        printf("\r\nNo interface found! Make sure Npcap is installed.\r\n");
        return -1;
    }

    printf("Ether the interface number (1-%d) :", deviceNumber);
    scanf("%d", &selectedIndex);

    if (selectedIndex < 1 || selectedIndex > deviceNumber) {
        printf("\nInterface number out of range. %d\r\n", selectedIndex);
        pcap_freealldevs(allDevices);
        return -1;
    }

    for (pDevice = allDevices, deviceNumber = 0;
         deviceNumber < selectedIndex - 1; pDevice = pDevice->next, deviceNumber++);

    if ((pDeviceHandler = pcap_open_live(pDevice->name, 65536, 1, 1000, errorBuffer)) == NULL) {
        fprintf(stderr, "\nUnable to open the adapter. %s in not supported by npcap\r\n", pDevice->name);
        pcap_freealldevs(allDevices);
        return -1;
    }

    printf("\nlistening on %s...\n", pDevice->description);

    pcap_freealldevs(allDevices);

    pcap_loop(pDeviceHandler, 0, packetHandler, NULL);

    pcap_close(pDeviceHandler);

    return 0;
}

void packetHandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    EtherHeader_t *pEther = (EtherHeader_t *) pkt_data;

    if (pEther->type != htons(0x0800)) {
        return;
    }

    IPHeader_t *pIpHeader = (IPHeader_t *) (pkt_data + sizeof(EtherHeader_t));

    if (pIpHeader->protocol != 6) {
        return;
    }

    int ipHeaderLen = (pIpHeader->verIhl & 0x0f) * 4;

    TcpHeader_t *pTcp = (TcpHeader_t *) (pkt_data + sizeof(EtherHeader_t) + ipHeaderLen);

    if (ntohs(pTcp->srcPort) != 25000 || ntohs(pTcp->dstPort) != 25000) {
        return;
    }
    printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\r\n",
           pIpHeader->srcIp[0], pIpHeader->srcIp[1], pIpHeader->srcIp[2], pIpHeader->srcIp[3], pTcp->srcPort,
           pIpHeader->dstIp[0], pIpHeader->dstIp[1], pIpHeader->dstIp[2], pIpHeader->dstIp[3], pTcp->dstPort
    );

    int tcpHeaderSize = ((pTcp->data >> 4 & 0x0F) * 4);
    char *pPayload = (char *) (pkt_data + sizeof(EtherHeader_t) + ipHeaderLen + tcpHeaderSize);

    printf("Segment size : %d(Frame Length : %d)\r\n",
           ntohs(pIpHeader->length) - ipHeaderLen - tcpHeaderSize,
           header->len);

    char szMessage[2048] = {0};
    memcpy_s(szMessage, sizeof(szMessage), pPayload,
             ntohs(pIpHeader->length) - ipHeaderLen - tcpHeaderSize);
    puts(szMessage);
}