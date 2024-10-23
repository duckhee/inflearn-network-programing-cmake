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

#pragma pack(push, 1)
typedef struct _EthernetHeader {
    unsigned char dstMac[6];
    unsigned char srcMac[6];
    unsigned short type;
} EthernetHeader_t;
#pragma pack(pop)

/** DLL Library Load Function */
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

/** Handler 함수 */
void PacketHandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main(int argc, char **argv) {
    pcap_if_t *allDevices;
    pcap_if_t *pDevice;
    int deviceNumber;
    int i = 0;
    pcap_t *adHandle;
    char errBuf[PCAP_ERRBUF_SIZE];

    if (!LoadNpcapDlls()) {
        fprintf(stderr, "Couldn't load npcap\r\n");
        return -1;
    }

    if (pcap_findalldevs(&allDevices, errBuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\r\n", errBuf);
        return -1;
    }

    for (pDevice = allDevices; pDevice; pDevice = pDevice->next) {
        printf("%d. %s", ++i, pDevice->name);
        if (pDevice->description) {
            printf(" (%s)\r\n", pDevice->description);
        } else {
            printf(" (No description available)\r\n");
        }
    }

    if (i == 0) {
        printf("\nNo interfaces found! Make sure Npcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (1-%d):", i);
    scanf("%d", &deviceNumber);

    if (deviceNumber < 1 || deviceNumber > i) {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(allDevices);
        return -1;
    }

    for (pDevice = allDevices, i = 0; i < deviceNumber - 1; pDevice = pDevice->next, i++);
    if ((adHandle = pcap_open_live(
            pDevice->name,
            65536,
            1,
            1000,
            errBuf
    )) == NULL) {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", pDevice->name);
        /* Free the device list */
        pcap_freealldevs(allDevices);
        return -1;
    }

    printf("\nlistening on %s...\n", pDevice->description);

    pcap_freealldevs(allDevices);

    pcap_loop(adHandle, 0, PacketHandler, NULL);

    pcap_close(adHandle);

    return 0;
}

void PacketHandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    /** 송수신 시간을 출력 하기 위한 시간 구조체 */
    struct tm lTime;
    /** 시간을 문자열로 출력하기 위한 변수 */
    char timestr[16];
    time_t local_tv_sec;

    /** 시간 정보 가져와서 변환 */
    local_tv_sec = header->ts.tv_sec;
    localtime_s(&lTime, &local_tv_sec);
    strftime(timestr, sizeof(timestr), "%H:%M:%S", &lTime);

    /** Ethernet Header Frame 읽어오기 -> packet에 있는 데이터를 가지고 한다. -> pointer를 이용해서 강제 형 변환을 해준다. */
    EthernetHeader_t *pEthernetHeader = (EthernetHeader_t *) pkt_data;
    /** type의 경우 네트워크 순서로 정렬이 되어 있기 때문에 host 순서로 변경을 해줘야 한다.*/
    printf(
            "(%s,%.6ld)[len:%d] Source MAC ADDRESS :  %02X-%02X-%02X-%02X-%02X-%02X -> Destination MAC ADDRESS : %02X-%02X-%02X-%02X-%02X-%02X\nFrame Type : %04X",
            timestr, header->ts.tv_usec, header->len,
            pEthernetHeader->srcMac[0], pEthernetHeader->srcMac[1], pEthernetHeader->srcMac[2],
            pEthernetHeader->srcMac[3], pEthernetHeader->srcMac[4], pEthernetHeader->srcMac[5],
            pEthernetHeader->dstMac[0], pEthernetHeader->dstMac[1], pEthernetHeader->dstMac[2],
            pEthernetHeader->dstMac[3], pEthernetHeader->dstMac[4], pEthernetHeader->dstMac[5],
            htons(pEthernetHeader->type));
}