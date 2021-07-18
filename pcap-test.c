#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
        struct libnet_ethernet_hdr* ethernet_header = (struct libnet_ethernet_hdr*)packet;
        struct libnet_ipv4_hdr* ip_header = (struct libnet_ipv4_hdr*) &packet[14];      //Ethernet header size(14)
        struct libnet_tcp_hdr* tcp_header = (struct libnet_tcp_hdr* ) &packet[14+(ip_header->ip_hl)*4];   //IP header len

        if(ntohs(ethernet_header -> ether_type) == 0x800 && ip_header -> ip_p == 0x6){  // IP(0x0800), tcp(0x6)
            // Ethernet
            printf("Src MAC Address \t");
            for(int i=0;i<ETHER_ADDR_LEN-1;i++)
                printf("%02x:", ethernet_header -> ether_shost[i]);
            printf("%02x\n", ethernet_header -> ether_shost[ETHER_ADDR_LEN-1]);
            printf("Dst MAC Address \t");
            for(int i=0;i<ETHER_ADDR_LEN-1;i++)
                printf("%02x:", ethernet_header -> ether_dhost[i]);
            printf("%02x\n", ethernet_header -> ether_dhost[ETHER_ADDR_LEN-1]);
            // IP
            printf("Scr IP Address \t");
            for(int i=1;i<4;i++){
                printf("%d.", ntohl(ip_header -> ip_src.s_addr) >> (8*(4-i)) & 0xFF);
            }
            printf("%d\n", ntohl(ip_header -> ip_src.s_addr) & 0xFF);
            printf("Dst IP Address \t");
            for(int i=1;i<4;i++){
                printf("%d.", ntohl(ip_header -> ip_dst.s_addr) >> (8*(4-i)) & 0xFF);
            }
            printf("%d\n", ntohl(ip_header -> ip_dst.s_addr) & 0xFF);
            // TCP
            printf("Src Port Address \t%d\n",ntohs(tcp_header -> th_sport));
            printf("Dst Port Address \t%d\n",ntohs(tcp_header -> th_dport));
            // Data
            uint16_t total_header_len = 14+(ip_header->ip_hl)*4+(tcp_header -> th_off)*4;
            printf("Data \t");
            if (total_header_len == header->caplen){    //data len 0
                for(int i=0;i<8;i++)
                    printf("00 ");
            }
            else{
                for(int i=0;i<8;i++){
                    printf("%02x ", packet[total_header_len+i]);
                }
            }
            printf("\n\n");
        }
    }

	pcap_close(pcap);
}
