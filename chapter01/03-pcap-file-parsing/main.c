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

#pragma pack(push, 1)
typedef struct _EthernetHeader {
    unsigned char dstMac[6];
    unsigned char srcMac[6];
    unsigned short type;
} EthernetHeader_t;
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

    u_int i = 0;

    /* print pkt timestamp and pkt len */
    printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);

    EthernetHeader_t *pEther = (EthernetHeader_t *) pkt_data;

    printf(
            "SRC: %02X-%02X-%02X-%02X-%02X-%02X -> "
            "DST: %02X-%02X-%02X-%02X-%02X-%02X, type:%04X\n",
            pEther->srcMac[0], pEther->srcMac[1], pEther->srcMac[2],
            pEther->srcMac[3], pEther->srcMac[4], pEther->srcMac[5],
            pEther->dstMac[0], pEther->dstMac[1], pEther->dstMac[2],
            pEther->dstMac[3], pEther->dstMac[4], pEther->dstMac[5],
            ntohs(pEther->type));

    /* Print the packet */
    for (i = 1; (i < header->caplen + 1); i++) {
        printf("%.2x ", pkt_data[i - 1]);
        if ((i % LINE_LEN) == 0) printf("\n");
    }

    printf("\n\n");
}