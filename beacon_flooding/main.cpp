#include <pcap.h>
#include <stdio.h>
#include <libnet.h>

#define DOT11TYPE_BEACON 0x80  /* Dot11 beaconframe */
#define SSID_TAG 0

struct Param {
    char* dev_{nullptr};

    bool parse(int argc, char* argv[]) {
        if (argc != 2) {
            usage();
            return false;
        }
        dev_ = argv[1];
        return true;
    }

    static void usage() {
        printf("syntax: pcap-test <interface>\n");
        printf("sample: pcap-test wlan0\n");
    }
};

struct RadioHeader{
    u_int8_t he_rv;
    u_int8_t pad;
    u_int16_t h_len;
};

struct Dot11beacon{
    u_int8_t frame_ctr[2];
};

struct Tag{
    u_int8_t Tag_num;
    u_int8_t Tag_len;
};

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}


int main(int argc, char* argv[]) {
    Param param;
    if (!param.parse(argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        struct RadioHeader* Rdheader;
        struct Dot11beacon* Bcheader;
        struct Tag* Tag_ssid;

        const u_char* packet;
        const u_char* test_ssid;

        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        //hdr
        Rdheader = (RadioHeader*)packet;
        Bcheader = (Dot11beacon*)(packet+Rdheader->h_len);

        if (Bcheader->frame_ctr[0] == DOT11TYPE_BEACON){
            printf("=============== beacon frame ===============\n type : %x\n", Bcheader->frame_ctr[0]);
            dump((unsigned char*)Bcheader, header->caplen-Rdheader->h_len);

            printf("=============== ssid ===============\n type : %x\n", Bcheader->frame_ctr[0]);
            test_ssid = ((u_char*)(Bcheader))+36;
            dump((unsigned char*)test_ssid, header->caplen-Rdheader->h_len-36);


            Tag_ssid = (Tag*)test_ssid;
            printf("Tag NUM : %x \n", Tag_ssid->Tag_num);
            if(Tag_ssid->Tag_num == SSID_TAG){
                printf("%s", test_ssid+sizeof(Tag));
            }
            //new ssid insert -> sendpacket
        }
    }
    pcap_close(pcap);
}
