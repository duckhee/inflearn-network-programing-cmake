#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <tchar.h>
#include <time.h>
#include <WinSock2.h>
#include <pcap.h>

#pragma comment(lib, "wpcap")
#pragma comment(lib, "ws2_32")

#define LINE_LEN 16

#define GET_IP_VERSION(x)        (((x) & (0xF0)) >> (4))
#define GET_IP_IHL(x)                (((x) & (0x0F)) * (4))

#pragma pack(push, 1)

typedef struct _verIhl {
    union {
        struct {
#if  (__BYTE_ORDER__ == __LITTLE_ENDIAN__)
            unsigned char ihl: 4;
            unsigned char version: 4;
#else
            unsigned char version : 4;
            unsigned char ihl : 4;
#endif

        };

        unsigned char val;
    };
} verIhl_t;

typedef struct EtherHeader {
    unsigned char dstMac[6];
    unsigned char srcMac[6];
    unsigned short type;
} EtherHeader;

typedef struct IpHeader {
    unsigned char verIhl;
    //verIhl_t verIhl;
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
#pragma pack(pop)


BOOL LoadNpcapDlls() {
    _TCHAR npcap_dir[512];
    UINT len;
    len = GetSystemDirectory(npcap_dir, 480);
    if (!len) {
        fprintf(stderr, "ERROR in GetSystemDirectory : %lx\n", GetLastError());
        return FALSE;
    }
    _tcscat_s(npcap_dir, 512, _T("\\Npcap"));
    if (SetDllDirectory(npcap_dir) == 0) {
        fprintf(stderr, "ERROR in SetDllDirectory : %lx\n", GetLastError());
        return FALSE;
    }
    printf("Load NPCAP \n");
    return TRUE;
}

void DetachedHandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main(int argc, char **argv) {
    pcap_t *pCapHandler;
    char errorBuffer[PCAP_ERRBUF_SIZE];
    if (!LoadNpcapDlls()) {
        fprintf(stderr, "Couldn't load npcap\r\n");
        return -1;
    }


    if ((pCapHandler = pcap_open_offline("C:\\SampleTraces\\ip-fragments.pcap", errorBuffer)) == NULL) {
        fprintf(stderr, "Failed PCAP FIlE Open...\r\n");
        return -1;
    }

    pcap_loop(pCapHandler, 0, DetachedHandler, NULL);

    pcap_close(pCapHandler);
    return 0;
}

void DetachedHandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    EtherHeader *pEthernetHeader = (EtherHeader *) pkt_data;
    IpHeader *pIpHeader = (IpHeader *) (pkt_data + sizeof(EtherHeader));

    /** IPv4 인지 확인 */
    if (pEthernetHeader->type != 0x0008) {
        return;
    }

    /** MF Flag 확인 */
    int isMFSet = pIpHeader->fragOffset & htons((short) 0x2000);
    // htons((unsigned short) 0x1FFF)를 하면 network 순서로 변경을 해준다. - 0x1FFF는 flag에 대한 값을 제외한 현재 데ㅐ이터의 위치 값을 가져오기 위한 & 연산이다.
    int isFlagOffset = ntohs(pIpHeader->fragOffset & htons((unsigned short) 0x1FFF)) > 0;
    if(isMFSet || isFlagOffset){
        printf("ID: %04X, Flags: %04X, Offset: %d, Protocol: 0x%02X\n",
               ntohs(pIpHeader->id),
               ntohs(pIpHeader->fragOffset & htons((short)0xE000)), // 2000일 경우 MF 비트 설정이 되어 있는 상태
               ntohs(pIpHeader->fragOffset & (unsigned short)0xFF1F) * 8, // offset을 이용해서 현재 데이터의 위치를 찾는다. 8을 곲해준 것은 1bye가 기본 offset 단위이기 때문에다.
               pIpHeader->protocol);

        printf("%d.%d.%d.%d -> %d.%d.%d.%d\n",
               pIpHeader->srcIp[0], pIpHeader->srcIp[1],
               pIpHeader->srcIp[2], pIpHeader->srcIp[3],
               pIpHeader->dstIp[0], pIpHeader->dstIp[1],
               pIpHeader->dstIp[2], pIpHeader->dstIp[3]
        );

        printf("\n");
    }
}