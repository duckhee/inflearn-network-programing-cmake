#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <pcap.h>
#include <stdio.h>
#include <time.h>
#ifdef _WIN32
#include <tchar.h>

/** DLL 파일인 동적 라이브러리를 로딩하는 함수이다. */
BOOL LoadNpcapDlls()
{
    /** DLL 라이브러리에 대한 경로를 가져오기 위한 변수 이다.*/
    _TCHAR npcap_dir[512];
    /** 가져온 문자열의 길이를 저장 하기 위한 변수 이다.*/
    UINT len;
    /** Syste에 대한 경로를 가져오는 함수이다. -> GetSystemDirectory 반환을 하는 값은 가져온 경로에 대한 길이를 반환한다. */
    len = GetSystemDirectory(npcap_dir, 480);
    if (!len) {
        fprintf(stderr, "Error in GetSystemDirectory: %lx", GetLastError());
        return FALSE;
    }
    /** 가져온 System 폴더 안에 Npcap 폴더로 이동하기 위한 설정 이다. */
    _tcscat_s(npcap_dir, 512, _T("\\Npcap"));
    /** DLL 파일을 가져오기 위한 라이브러리 위치를 설정 한다. -> DLL 파일을 로딩하는 window 함수인 SetDllDirectory이다. */
    if (SetDllDirectory(npcap_dir) == 0) {
        fprintf(stderr, "Error in SetDllDirectory: %lx", GetLastError());
        return FALSE;
    }
    return TRUE;
}
#endif

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    int i=0;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];

#ifdef _WIN32
    /** 동적 라이브러리를 불러오기 위한 함수를 호출 한다. */
    /* Load Npcap and its functions. */
    if (!LoadNpcapDlls())
    {
        fprintf(stderr, "Couldn't load Npcap\n");
        exit(1);
    }
#endif

    /* Retrieve the device list */
    /** 현재 PC에서 존재하는 NIC에 대한 정보를 가져오는 함수이다. */
    if(pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* Print the list */
    /** 현재 NIC에 대한 목록을 가져온 것에 대한 정보를 출력하기 위한 반복문이다. */
    for(d=alldevs; d; d=d->next)
    {
        /** NIC에 대한 열기 위해서 사요잉 되는 것이 pcap_if_t에 있는 name 값을 가지고 열게 된다. */
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if(i==0)
    {
        printf("\nNo interfaces found! Make sure Npcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (1-%d):",i);
    scanf("%d", &inum);

    /** 입력 받은 값이 잘못 됬을 경우 */
    if(inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /** 원하는 Device가 가지고 있는 위치로 이동하기 위한 반복문 -> Single Linked List 형식으로 되어 있기 때문에 next를 가지고 이동을 한다. */
    /* Jump to the selected adapter */
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

    /* Open the device */
    /* Open the adapter */
    if ((adhandle= pcap_open_live(d->name,	// name of the device
                                  65536,			// portion of the packet to capture. -> 64KB만큼 버퍼를 생성하고 해당 값을 읽는다.
            // 65536 grants that the whole packet will be captured on all the MACs.
                                  1,				// promiscuous mode (nonzero means promiscuous) -> 네트워크로 유입이 되는 모든 값을 읽기 위해서 1로 인자를 넣어준다.
                                  1000,			// read timeout
                                  errbuf			// error buffer
    )) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\nlistening on %s...\n", d->description);

    /* At this point, we don't need any more the device list. Free it */
    /** 원하는 장치에 대해서 접근해서 파일을 열었기 때문에 목록에 대한 정보는 필요가 없으므로 해제한다. */
    pcap_freealldevs(alldevs);

    /* start the capture */
    /** packet에 대한 것을 계속해서 반복하면서 패킷을 계속해서 가져온 다음 callback 함수를 호출을 해준다. */
    pcap_loop(adhandle, 0, packet_handler, NULL);

    pcap_close(adhandle);
    return 0;
}


/* Callback function invoked by libpcap for every incoming packet */
/**
 * packet에 대해서 감지를 하는 callback 함수이다.
 * -> pkt_data는 실제로 전송이 되는 데이터가 저장이 되어 있는 메모리 주소이다.
 * -> pcap_pkthdr* header에 설명 정보, 시간 정보 등이 담겨서 넘어온다.
 */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;

    /*
     * unused parameters
     */
    (VOID)(param);
    (VOID)(pkt_data);

    /* convert the timestamp to readable format */
    /**
     * 송수신된 시간에 대한 정보를 담고 있다.
     * pcap_pkthdr의 ts.tv_sec는 시간에 대한 정보를 가지는 멤버 변수이다.
     * pcap_pkthdr의 len은 packet 데이터에 대한 길이 정보를 가지고 있다.
     */
    local_tv_sec = header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

    printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);

}
