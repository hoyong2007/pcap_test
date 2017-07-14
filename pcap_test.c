#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
typedef struct ethernet{
	u_char src[6];
	u_char dst[6];
	u_char type[2]; 	// 08 00 -> IP
} ETHER;

typedef struct ipp{
	u_char version;
	u_char dsp;
	u_short len;
	u_short id;
	u_short fragment;
	u_char ttl;
	u_char protocol;
	u_short checksum;
	struct in_addr src;
	struct in_addr dst;
	/*
	char version;
	char dsp;
	char tot_len[2];
	char id[2];
	char flag;
	char fragment;
	char ttl;
	char protocol;	// 06 -> TCP
	char checksum[2];
	char src[4];
	char dst[4];
	*/
} IP;

typedef struct tcp{
	char sport[2];
	char dport[2];
	char seq_num[4];
	char ack_num[4];
	char len;
	char flag;
	char win_size[2];
	char checksum[2];
	char urg[2];
} TCP;

int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr *header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	int res;
	FILE *f;
	struct ethhdr *ether;
	struct ip *ip;
	struct tcphdr *tcp;
	//ETHER *ether;
	//IP *ip;
	//TCP *tcp;

	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, 65536, 0, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	/* Grab a packet */
	while(1) {
		res = pcap_next_ex(handle, &header, &packet);
		if (res==0)
		{
			printf("timeout");
			continue;
		}
		else if (res==-1)
			printf("error");
		/* Print its length */
		
		ether = (struct ethhdr*)packet;
		ip = (struct ip*)(packet + 14); 
		
		if (ntohs(ether->h_proto) == ETHERTYPE_IP)
		{
			f = fopen("./sample.pcap", "wb");
			fwrite(ether, 1, 500, f);
			fclose(f);
			printf("packet : %p\n", packet);
			printf("ip : %p\n", ip);
			printf("src ip - %s\n", inet_ntoa(ip->ip_src));
			printf("dst ip - %s\n", inet_ntoa(ip->ip_dst));
			break;
			if (ip->ip_p == IPPROTO_TCP)
			{
				printf("\nsrc mac - %02x:%02x:%02x:%02x:%02x:%02x\n", (unsigned char)ether->h_source[0], (unsigned char)ether->h_source[1], (unsigned char)ether->h_source[2], (unsigned char)ether->h_source[3], (unsigned char)ether->h_source[4], (unsigned char)ether->h_source[5]);
				printf("dst mac - %02x:%02x:%02x:%02x:%02x:%02x\n", (unsigned char)ether->h_dest[0], (unsigned char)ether->h_dest[1], (unsigned char)ether->h_dest[2], (unsigned char)ether->h_dest[3], (unsigned char)ether->h_dest[4], (unsigned char)ether->h_dest[5]);
				printf("src ip - %s\n", inet_ntoa(ip->ip_src));
				printf("dst ip - %s\n", inet_ntoa(ip->ip_dst));
				tcp = (struct tcphdr*)(packet + ip->ip_hl*4);
			}
		}
	}
	/* And close the session */
	pcap_close(handle);
	return(0);
}

/*
* fopen	- pcap_open
* fread	- pcap_next_ex
* fwrite- pcap_sendpacket
* fclose- pcap_close
* gcc -o pcap_test pcap_test.c -lpcap
* in the while
* header -> packet's len, time
* packet -> packet buffer pointer (start with ethernet header)
* packet[12]==0x08 && packet[13]==0x00
* ntohs
*/