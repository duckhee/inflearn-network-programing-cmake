#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <tchar.h>
#include <pcap.h>
#include <WinSock2.h>
#include <Windows.h>

#pragma comment(lib, "ws2_32")
#pragma comment(lib, "wpcap")

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

BOOL LoadNpcapDlls() {
    _TCHAR npcap_dir[512];
    UINT len;
    len = GetSystemDirectory(npcap_dir, 480);
    if (!len) {
        fprintf(stderr, "Error in GetSystemDirectory : %lx", GetLastError());
        fflush(stderr);
        return FALSE;
    }
    _tcscat_s(npcap_dir, 512, _T("\\Npcap"));
    if (SetDllDirectory(npcap_dir) == 0) {
        fprintf(stderr, "Error in SetDllDirectory %lx", GetLastError());
        fflush(stderr);
        return FALSE;
    }
    return TRUE;
}

void PacketHandler(u_char *pParam, const struct pcap_pkthdr *header, const u_char *pkt_data);


int main(int argc, char **argv) {
    pcap_t *pHandler;
    char errorBuffer[PCAP_ERRBUF_SIZE] = {0,};

    int isInit = pcap_init(PCAP_CHAR_ENC_LOCAL, errorBuffer);
    if (isInit == -1) {
        fprintf(stderr, "Failed Initialized pcap\r\n");
        return -1;
    }

    pHandler = pcap_open_offline("C:\\SampleTraces\\http-browse-ok.pcap", errorBuffer);
    if (pHandler == NULL) {
        fprintf(stderr, "Failed Load Offline File : %s\r\n", "C:\\SampleTraces\\http-browse-ok.pcap");
        fflush(stderr);
        return -1;
    }

    pcap_loop(pHandler, 0, PacketHandler, NULL);

    pcap_close(pHandler);

    return 0;
}

void PacketHandler(u_char *pParam, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    struct tm *lTime;
    char strTime[15];
    time_t local_tv_sec = header->ts.tv_sec;

    lTime = localtime(&local_tv_sec);
    strftime(strTime, 15, "%H:%M:%S", lTime);

    EthernetHeader_t *pEther = (EthernetHeader_t *) (pkt_data);
    if (pEther->type != htons(0x0800)) {
        return;
    }

    IpHeader_t *pIpHeader = (IpHeader_t *) (pkt_data + sizeof(EthernetHeader_t));
    if (pIpHeader->protocol != 0x06) {
        return;
    }

    int ipHeaderLength = (pIpHeader->verIhl & 0x0F) << 2;

    TcpHeader_t *pTcpHeader = (TcpHeader_t *) (pkt_data + sizeof(EthernetHeader_t) + ipHeaderLength);

    int tcpHeaderLength = ((pTcpHeader->data >> 4) * 4);

    if (ntohs(pTcpHeader->dstPort) == 80 && ntohs(pIpHeader->length) > 50) {
        char *pHttpProtocol = ((char *) pTcpHeader) + tcpHeaderLength;
        printf("[%s]%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n%s\n",
               strTime,
               pIpHeader->srcIp[0], pIpHeader->srcIp[1],
               pIpHeader->srcIp[2], pIpHeader->srcIp[3],
               ntohs(pTcpHeader->srcPort),
               pIpHeader->dstIp[0], pIpHeader->dstIp[1],
               pIpHeader->dstIp[2], pIpHeader->dstIp[3],
               ntohs(pTcpHeader->dstPort),
               pHttpProtocol
        );
    }


}