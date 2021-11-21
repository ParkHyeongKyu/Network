#include <pcap/pcap.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <time.h>

#define ETHER_ADDR_LEN 6
#define IP_HEADER 0x0800
#define ARP_HEADER 0x0806
#define REVERSE_ARP_HEADER 0x0835
#define SYN 0x02
#define PUSH 0x08
#define ACK 0x10
#define SYN_ACK 0x12
#define PUSH_ACK 0x18
#define FIN_ACK 0x11

typedef struct mac_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
}mac;

struct ether_header
{
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
}eth;

typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

typedef struct ip_header
{
	u_char ver_ihl;         // Version (4 bits) + Internet header length(4bits)
	u_char tos; // Type of service 
	u_short tlen; // Total length 
	u_short identification; // Identification
	u_short flags_fo; // Flags (3 bits) + Fragment offset (13 bits)
	u_char ttl; // Time to live
	u_char proto; // Protocol
	u_short crc; // Header checksum
	ip_address saddr; // Source address
	ip_address daddr; // Destination address
	u_int op_pad; // Option + Padding
}ip_header;

typedef struct tcp_header
{
	u_short sport;   // Source port
	u_short dport;   // Destination port
	u_int seqnum;   // Sequence Number
	u_int acknum;   // Acknowledgement number
	u_char th_off;  // Header length
	u_char flags;   // packet flags
	u_short win;    // Window Size
	u_short crc;    // Header Checksum
	u_short urgptr; // Urgent pointer
}tcp_header;

typedef struct udp_header
{
	u_short sport; // Source port
	u_short dport; // Destination port
	u_short len;   // Datagram length
	u_short crc;   // Checksum
}udp_header;

typedef struct icmp_header
{
	u_char type; // message type
	u_char code; // message type add information
	u_short crc; //Checksum
}icmp_header;

clock_t init;

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

int main()
{
	init = clock();

	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "";
	struct bpf_program fcode;

	// get all interfaces
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	//print interfaces
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
		printf("\nNo interfaces found! Make sure LiPcap is installed.\n");
		return -1;
	}
	
	//select one interface
	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nAdapter number out of range.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
	//open device
	if ((adhandle = pcap_open_live(d->name, 65536, 1, -1, errbuf)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	//packet filtering
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nselected device %s is available\n", d->name);
	//free interfaces
	pcap_freealldevs(alldevs);
	//packet capture
	pcap_loop(adhandle, 0, packet_handler, NULL);

	return 0;
}

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	//time when this packet captured
	clock_t fin = clock();

	struct tm* ltime;
	char timestr[16];
	time_t local_tv_sec;

	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);

	unsigned int ptype;
	
	mac* destmac;
	mac* srcmac;
	destmac = (mac*)pkt_data;
	srcmac = (mac*)(pkt_data + 6);

	struct ether_header* eth;
	eth = (struct ether_header*)pkt_data;

	ptype = ntohs(eth->ether_type);

	ip_header * ih;
	u_int ip_len;
	ih = (ip_header*)(pkt_data + 14);
	ip_len = (ih->ver_ihl & 0xf) * 4;

	if (ntohs(eth->ether_type) == IP_HEADER)
	{
		if (ih->proto == 0x06) //back ground color of TCP is RED
		{
			tcp_header* th;
			th = (tcp_header*)((u_char*)ih + ip_len);
			printf("\e[0;41;30mThis is TCP\e[0m");
			printf("\n");
			printf("\e[0;41;30mpacket arrival time : %s, Time taken from start program : %lfsec\e[0m", timestr, (double)(fin-init)/CLOCKS_PER_SEC);
			printf("\n");
			printf("\e[0;41;30mSrc Mac Add -> Dest Mac Add : [%02x.%02x.%02x.%02x.%02x.%02x] -> [%02x.%02x.%02x.%02x.%02x.%02x]\e[0m", srcmac->byte1, srcmac->byte2, srcmac->byte3, srcmac->byte4, srcmac->byte5, srcmac->byte6, destmac->byte1, destmac->byte2, destmac->byte3, destmac->byte4, destmac->byte5, destmac->byte6);
			printf("\n");
			printf("\e[0;41;30mSrc IP Address -> Dest IP Address : (%d.%d.%d.%d) -> (%d.%d.%d.%d)\e[0m", ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4, ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
			printf("\n");
			printf("\e[0;41;30mDest port num : %d, Src port num : %d, Seq num : %d, Ack num : %d\e[0m", ntohs(th->dport), ntohs(th->sport), th->seqnum, th->acknum);
			printf("\n\n\n");		
		}
		else if (ih->proto == 0x11) //back ground color of UDP is YELLOW
		{
			udp_header* uh;
			uh = (udp_header*)((u_char*)ih + ip_len);
			printf("\e[0;43;30mThis is UDP\e[0m");
			printf("\n");
			printf("\e[0;43;30mpacket arrival time : %s, Time taken from start program : %lfsec\e[0m", timestr, (double)(fin - init) / CLOCKS_PER_SEC);
			printf("\n");
			printf("\e[0;43;30mSrc Mac Add -> Dest Mac Add : [%02x.%02x.%02x.%02x.%02x.%02x] -> [%02x.%02x.%02x.%02x.%02x.%02x]\e[0m", srcmac->byte1, srcmac->byte2, srcmac->byte3, srcmac->byte4, srcmac->byte5, srcmac->byte6, destmac->byte1, destmac->byte2, destmac->byte3, destmac->byte4, destmac->byte5, destmac->byte6);
			printf("\n");
			printf("\e[0;43;30mSrc IP Address -> Dest IP Address : (%d.%d.%d.%d) -> (%d.%d.%d.%d)\e[0m", ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4, ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
			printf("\n");
			printf("\e[0;43;30mDest port num : %d, Src port num : %d\e[0m", ntohs(uh->dport), ntohs(uh->sport));
			printf("\n\n\n");
		}
		else if (ih->proto == 0x01) //back ground color of ICMP is PINK
		{
			icmp_header* icmp;
			icmp = (icmp_header*)((u_char*)ih + ip_len);
			printf("\e[0;45;30mThis is ICMP\e[0m");
			printf("\n");
			printf("\e[0;45;30mpacket arrival time : %s, Time taken from start program : %lfsec\e[0m", timestr, (double)(fin - init) / CLOCKS_PER_SEC);
			printf("\n");
			printf("\e[0;45;30mSrc Mac Add -> Dest Mac Add : [%02x.%02x.%02x.%02x.%02x.%02x] -> [%02x.%02x.%02x.%02x.%02x.%02x]\e[0m", srcmac->byte1, srcmac->byte2, srcmac->byte3, srcmac->byte4, srcmac->byte5, srcmac->byte6, destmac->byte1, destmac->byte2, destmac->byte3, destmac->byte4, destmac->byte5, destmac->byte6);
			printf("\n");
			printf("\e[0;45;30mSrc IP Address -> Dest IP Address : (%d.%d.%d.%d) -> (%d.%d.%d.%d)\e[0m", ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4, ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
			printf("\n");
			printf("\e[0;45;30mType : %d, Code : %d\e[0m", icmp->type, icmp->code);
			printf("\n\n\n");
		}
		else //IP header but not TCP/UDP/ICMP -> back ground color is GREEN
		{
			printf("\e[0;42;37mThis is IP header but not TCP/UDP/ICMP\e[0m");
			printf("\n");
			printf("\e[0;42;37mpacket arrival time : %s, Time taken from start program : %lfsec\e[0m", timestr, (double)(fin - init) / CLOCKS_PER_SEC);
			printf("\n");
			printf("\e[0;42;37mSrc Mac Add -> Dest Mac Add : [%02x.%02x.%02x.%02x.%02x.%02x] -> [%02x.%02x.%02x.%02x.%02x.%02x]\e[0m", srcmac->byte1, srcmac->byte2, srcmac->byte3, srcmac->byte4, srcmac->byte5, srcmac->byte6, destmac->byte1, destmac->byte2, destmac->byte3, destmac->byte4, destmac->byte5, destmac->byte6);
			printf("\n\n\n");
		}
	}
	else //not IP header -> back ground color is BLUE
	{
		printf("\e[0;46;37mThis is not IP header\e[0m");
		printf("\n");
		printf("\e[0;46;37mpacket arrival time : %s, Time taken from start program : %lfsec\e[0m", timestr, (double)(fin - init) / CLOCKS_PER_SEC);
		printf("\n");
		printf("\e[0;46;37mSrc Mac Add -> Dest Mac Add : [%02x.%02x.%02x.%02x.%02x.%02x] -> [%02x.%02x.%02x.%02x.%02x.%02x]\e[0m", srcmac->byte1, srcmac->byte2, srcmac->byte3, srcmac->byte4, srcmac->byte5, srcmac->byte6, destmac->byte1, destmac->byte2, destmac->byte3, destmac->byte4, destmac->byte5, destmac->byte6);
		printf("\n\n\n");
	}

	return;
}