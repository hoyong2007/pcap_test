#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>


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
	uint32_t res;
	uint32_t i;
	struct ethhdr *ether;
	struct ip *ip;
	struct tcphdr *tcp;
	unsigned char *data;
	u_char src_addr[20];
	u_char dst_addr[20];


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
	
	if (argc < 2) {
		printf("Usage : ./pcap_test [interface]\n");
		return 2;
	}

	/* Open the session in promiscuous mode */
	handle = pcap_open_live(argv[1], 65536, 0, 1000, errbuf);
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
			continue;
		else if (res==-1)
		{
			printf("error");
			return -1;
		}
		/* Print its length */
		
		ether = (struct ethhdr*)packet;
		ip = (struct ip*)(packet + 14); 
		
		if (ntohs(ether->h_proto) == ETHERTYPE_IP)
		{
			if (ip->ip_p == IPPROTO_TCP)
			{
				tcp = (struct tcphdr*)(packet + 14 + ip->ip_hl*4);
				printf("\n\nsrc mac - %02x:%02x:%02x:%02x:%02x:%02x\n", (unsigned char)ether->h_source[0], (unsigned char)ether->h_source[1], (unsigned char)ether->h_source[2], (unsigned char)ether->h_source[3], (unsigned char)ether->h_source[4], (unsigned char)ether->h_source[5]);
				printf("dst mac - %02x:%02x:%02x:%02x:%02x:%02x\n", (unsigned char)ether->h_dest[0], (unsigned char)ether->h_dest[1], (unsigned char)ether->h_dest[2], (unsigned char)ether->h_dest[3], (unsigned char)ether->h_dest[4], (unsigned char)ether->h_dest[5]);
				inet_ntop(AF_INET, &(ip->ip_src), src_addr, sizeof(src_addr));
				inet_ntop(AF_INET, &(ip->ip_dst), dst_addr, sizeof(dst_addr));
				printf("src ip - %s\n", src_addr);
				printf("dst ip - %s\n", dst_addr);
				printf("src port - %d\n", ntohs(tcp->th_sport));
				printf("dst port - %d\n", ntohs(tcp->th_dport));
				//printf("data offset - %x\n", tcp->th_off * 4);
				//printf("packet len - %x\n", ntohs(ip->ip_len));
				data = (unsigned char*)(packet + 14 + ip->ip_hl*4 + tcp->th_off*4);
				for (i=0 ; i<ntohs(ip->ip_len)-(tcp->th_off*4)-(ip->ip_hl*4) ; i+=2)
				{	if (i == 0)
						printf("-----------data start----------");
					if (i % 0x10 == 0 )
						printf("\n");
					printf(" %02x%02x", data[i], data[i+1]);
				}
				if (i>0)
					printf("\n------------data end-----------\n\n");
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
* header -> packet's len, time
* packet -> packet buffer pointer (start with ethernet header)
* ntohs - network byte to host short
* inet_ntoa - in_addr to address string
*/