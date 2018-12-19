/*
 * Author: Sudhindra Gopal Krishna
 * Email: sudhi@ou.edu
 * Data Network
 * Project 2
 * Parser Side
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <netinet/if_ether.h> 
#include <netinet/ip.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ctype.h>
#include <arpa/inet.h>


int size, capturedLen;
struct sockaddr_in source,dest;
int getLen(const char *fname);

/*
 * Part of the code was referred from sniffer 
 * https://www.tcpdump.org/sniffex.c
 */

#define Size_Ethernet 14
#define Ether_Addr_Len 6
#define	ether_IP 0x0800


//IP structure

struct sniffIp
{
	u_char ip_vhl; /* version << 4 */
	u_char ip_tos;  /*tos --> type of service*/
	u_short ip_len;	//Total length
	u_short ip_id;	//Identification
	#define ip_rf 0x8000	//reserved fragment flag
	#define ip_df 0x4000	//dont fragment flag
	#define ip_mf 0x2000	//more fragment flag
	#define ip_offmask 0x1fff //mask for fragment flag
	u_short ip_reserved_zero;
	u_char ip_ttl;	//time to live
	u_char ip_p;	//protocol
	u_short ip_sum;	//checksum
	struct in_addr ip_src, ip_dst; //source and destination address
};

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

struct sniffIp *ip;

/*
 * Part of the code was referred from sniffer 
 * https://www.tcpdump.org/sniffex.c
 */

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const u_char *payload, int len, int offset){


	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05x   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
		}
		/* print space to handle line less than 8 bytes */
		if (len < 8)
			printf(" ");

		/* fill hex gap with spaces if not full line */
		if (len < 16) {
			gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 1; i < len; i++) {
		
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return;
}

/*
 * Part of the code was referred from sniffer 
 * https://www.tcpdump.org/sniffex.c
 */

/*
 * print packet payload data (avoid printing binary data)
 */
void printData(const u_char *payload)
{

	// struct sniffIp *ip;
	ip = (struct sniffIP*)(payload + 16);
	size = ntohs(ip->ip_len)+16;
	
	int len_rem = size;
	int line_width = 16;   /* number of bytes per line */
	int line_len;
	int offset = 0;     /* zero-based offset counter */

	const u_char *ch = payload;

	if (size <= 0)
		return;

/* data fits on one line */
	if (size <= line_width) {
		print_hex_ascii_line(ch, size, offset);
		return;
	}

/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
		/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}


/*
 * Part of the code was referred from sniffer 
 * https://www.tcpdump.org/sniffex.c
 */

void printIP(const u_char *data){
	

	ip = (struct sniffIP*)(data + 16);
	int size_ip = IP_HL(ip)*4;
	printf("\nIP:\t-----IP Header-----\n");
	printf("IP:\n");
	printf("IP:\tVersion = %d\n",IP_V(ip));
	printf("IP:\theader length = %d bytes\n", size_ip);
	printf("IP:\tType of service = %hhx\n", (ip->ip_tos));
	printf("IP:\tTotal length = %hu octets\n",ntohs(ip->ip_len));
	printf("IP:\tIdentification = %hx\n", ntohs(ip->ip_id));
	// printf("RF %hhu\n",ip->ip_reserved_zero);
	if((ip->ip_reserved_zero) == 0x40){
		printf("IP:\tFlags = 0x4000\n");
		printf("IP:\t\t0... .... .... .... = Reserved bit: Not set\nIP:\t\t.1.. .... .... .... = Don't fragment: Set\nIp:\t\t..0. .... .... .... = More fragments: Not set\nIP:\t\t...0 0000 0000 0000 = Fragment offset: 0\n");

	}else if((ip->ip_reserved_zero) == 0x80){
		printf("IP:\tFlags = 0x8000\n");
		printf("IP:\t\t1... .... .... .... = Reserved bit: Set\nIP:\t\t.0.. .... .... .... = Don't fragment: Not set\nIp:\t\t..0. .... .... .... = More fragments: Not set\nIP:\t\t...0 0000 0000 0000 = Fragment offset: 0\n");
	
	}else if((ip->ip_reserved_zero) == 0x20){
		printf("IP:\tFlags = 0x2000\n");
		printf("IP:\t\t0... .... .... .... = Reserved bit: Not set\nIP:\t\t.0.. .... .... .... = Don't fragment: Not set\nIp:\t\t..1. .... .... .... = More fragments: Set\nIP:\t\t...0 0000 0000 0000 = Fragment offset: 0\n");
	
	}else if((ip->ip_reserved_zero) == 0x10){
		printf("IP:\tFlags = 0x1000\n");
		printf("IP:\t\t0... .... .... .... = Reserved bit: Not set\nIP:\t\t.0.. .... .... .... = Don't fragment: Not set\nIp:\t\t..0. .... .... .... = More fragments: Not set\nIP:\t\t...1 0000 0000 0000 = Fragment offset: 1\n");
	
	}else if((ip->ip_reserved_zero) == 0x0){
		printf("IP:\tFlags = 0x0000\n");
		printf("IP:\t\t0... .... .... .... = Reserved bit: Not set\nIP:\t\t.0.. .... .... .... = Don't fragment: Not set\nIp:\t\t..0. .... .... .... = More fragments: Not set\nIP:\t\t...0 0000 0000 0000 = Fragment offset: 0\n");
	}

	
	printf("IP:\tTime to live = %d seconds/hops\n",ip->ip_ttl);
	printf("IP:\tProtocol = %hhu\n", ip->ip_p);
	printf("IP:\tHeader checksum = %x\n",ntohs(ip->ip_sum));
	printf("IP:\tSource Address = %s\n", inet_ntoa(ip->ip_src));
	printf("IP:\tDestination Address = %s\n",inet_ntoa(ip->ip_dst));
	printf("IP:\n");
	printf("\n");
	

}


