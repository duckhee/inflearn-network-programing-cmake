#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <time.h>
#include <winsock2.h>
#include <pcap.h>
#include <tchar.h>

#pragma comment(lib, "ws2_32")
#pragma comment(lib, "wpcap")
#pragma comment(lib, "Packet")


#pragma pack(push, 1)
typedef struct _EtherHeader
{
    unsigned char dstMac[6];
    unsigned char srcMac[6];
    unsigned short type;
} EtherHeader_t;

typedef struct _IpHeader
{
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

typedef struct _TcpHeader
{
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
        fprintf(stderr, "Error in SetDllDirectory : %x", GetLastError());
        return FALSE;
    }
    return TRUE;
}

void packetHandler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

int main(int argc, char* argv[])
{
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int inum;
    int i = 0;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (!LoadNpcapDlls())
    {
        fprintf(stderr, "Couldn't load Npcap\n");
        exit(1);
    }


    /* Retrieve the device list */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* Print the list */
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0)
    {
        printf("\nNo interfaces found! Make sure Npcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (1-%d):", i);
    scanf_s("%d", &inum);

    if (inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Jump to the selected adapter */
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    /* Open the device */
    /* Open the adapter */
    if ((adhandle = pcap_open_live(d->name, // name of the device
                                   65536, // portion of the packet to capture.
            // 65536 grants that the whole packet will be captured on all the MACs.
                                   1, // promiscuous mode (nonzero means promiscuous)
                                   1000, // read timeout
                                   errbuf // error buffer
    )) == NULL)
    {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\nlistening on %s...\n", d->description);

    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);

    /* start the capture */
    pcap_loop(adhandle, 0, packetHandler, NULL);

    pcap_close(adhandle);

    return 0;
}

void packetHandler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
    struct tm ltime;
    char timestr[16];
    time_t local_tv_sec;

    /* convert the timestamp to readable format */
    local_tv_sec = header->ts.tv_sec;
    localtime_s(&ltime, &local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

    EtherHeader_t* pEther = (EtherHeader_t*)pkt_data;
    if (pEther->type != 0x0000)
        return;

    char szBuffer[2048] = { 0 };
    memcpy_s(szBuffer, sizeof(szBuffer),
             pkt_data + sizeof(EtherHeader_t),
             header->len - sizeof(EtherHeader_t));

    printf("Ethernet message: %s\n", szBuffer);
}
