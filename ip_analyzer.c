/*------------------------------
* ip_analyzer.c
* Description: PCAP file tcp analyzer
* CSC 361
* Instructor: Kui Wu
* By Teague Lander
-------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include "ip_analyzer.h"

#define MAX_NUM_HOPS 80

struct in_addr ip_src;
struct in_addr ip_ult_dst;
struct in_addr ip_intr_dst[MAX_NUM_HOPS];
int ip_intr_dst_count = 0;
int src_dst_found = 0;  //The number of valid packets

u_char protocols_found[MAX_NUM_PROTOCOLS];
int protocols_found_count = 0;

int fragments_found_count = 0;
int last_fragment_offset = 0;

/* --------- main() routine ------------
 * three main task will be excuted:
 * accept the input URI and parse it into fragments for further operation
 * open socket connection with specified sockid ID
 * use the socket id to connect sopecified server
 * don't forget to handle errors
 */
int main(int argc, char **argv) {
	char filename[MAX_STR_LEN];
	pcap_t* pcap; //This will point to our offline pcap file
	const unsigned char *packet; //Current packet
	struct pcap_pkthdr header; //Gives us some basic info on our packet	
	
	//Read in FILE_NAME from command line
	if (argc == 2) {
		strcpy(filename, argv[1]);
	}else {
		printf("Error: Wrong number of arguments\nShould take the form 'ip_analyzer FILE_NAME'\n");
		exit(1);
	}
	
	//Open Pcap files and parse each packet
	pcap = OpenTraceFile(filename);
	
	while ((packet = pcap_next(pcap, &header)) != NULL){
		ParsePacket(packet, header.ts, header.caplen);
	}
	
	//Print stuff
	printf("\n");
	if (src_dst_found > 0) {
		char str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &ip_src,str,INET_ADDRSTRLEN);	
		printf("IP address of the source node: %s\n",str);
		inet_ntop(AF_INET, &ip_ult_dst,str,INET_ADDRSTRLEN);	
		printf("IP address of ultimate destination node: %s\n",str);
		printf("IP addresses of the intermediate destination nodes:\n");
		for (int i = 0; i < ip_intr_dst_count; i++) {
			inet_ntop(AF_INET, &ip_intr_dst[i],str,INET_ADDRSTRLEN);	
			printf("\t router %d: %s\n",i+1,str);
		}
		printf("\n");
		printf("The values in the procotol field of IP headers:\n");
		for (int i = 0; i < protocols_found_count; i++) {
			printf("\t%s\n",protocol_types[protocols_found[i]]);
		}
		printf("\n");
		printf("The number of fragments created from the original datagram is: %d\n",fragments_found_count);
		printf("The offset of the last fragment is: %d\n", last_fragment_offset);
	}else {
		printf("No valid traceroute\n");
	}
	printf("\n");
	
	
	
	pcap_close(pcap);
	return 0;
}


/* --------- ParsePacket() routine ------------
 * Skips over the ethernet header of '*packet'
 * Extracts the source and destination IP addresses, skips over IP header
 * Casts the rest of the packet on a TCP header
 * Calls store_connection to properly store the packet with its respective connection
 */
int ParsePacket(const unsigned char *packet, struct timeval ts, unsigned int capture_len) {
	struct ip *ip;
	struct TCP_hdr *tcp;
	unsigned int IP_header_length;
	char src_ip[15]; bzero(&src_ip, sizeof(src_ip));
	char dst_ip[15]; bzero(&dst_ip, sizeof(dst_ip));
	
	if (capture_len < sizeof(struct ether_header)) { //Check if we have enough bytes to form an ethernet header
		too_short(ts, "Ethernet Header");
		return;
	}
	
	//Now skip over ethernet header and check if we might have an ip header
	packet += sizeof(struct ether_header);
	capture_len -= sizeof(struct ether_header);
	if (capture_len < sizeof(struct ip)) {
		too_short(ts, "IP Header");
		return;
	}
	
	ip = (struct ip*) packet;
	IP_header_length = ip->ip_hl * 4;	/* ip_hl is in 4-byte words */
	
	if (capture_len < IP_header_length) { /* didn't capture the full IP header including options */
		too_short(ts, "IP header with options");
		return;
	}
	
	ParseIP(ip);
	
}


pcap_t* OpenTraceFile(char *filename) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle;

	if ((handle = pcap_open_offline(filename,errbuf)) == NULL) {
		printf("Error: Unable to open the file\n");
		exit(1);
	}
	return handle;
}

/* Note, this routine returns a pointer into a static buffer, and
 * so each call overwrites the value returned by the previous call.
 */
const char *timestamp_string(struct timeval ts) {
	static char timestamp_string_buf[256];

	sprintf(timestamp_string_buf, "%d.%06d",
		(int) ts.tv_sec, (int) ts.tv_usec);

	return timestamp_string_buf;
}

/* --------- timevaldiff() routine ------------
 * Returns the difference in seconds between starttime and finishtime
 *
 * Adapted from https://www.mpp.mpg.de/~huber/util/timevaldiff.c
 */
float timevaldiff(struct timeval *starttime, struct timeval *finishtime) {
	float msec;
	msec=(finishtime->tv_sec-starttime->tv_sec)*1000;
	msec+=(finishtime->tv_usec-starttime->tv_usec)/1000;
	return msec;
}

/* --------- too_short() routine ------------
 * Prints an error to say our packet is too short to contain a TCP header
 */
void too_short(struct timeval ts, const char *truncated_hdr) {
	fprintf(stderr, "packet with timestamp %s is truncated and lacks a full %s\n", timestamp_string(ts), truncated_hdr);
}


/* --------- ParseIP() routine ------------
 * 
 *
 */
void ParseIP(struct ip *ip) {

	//Check if the protocol is already listed
	if (ip->ip_p == ICMP_P || ip->ip_p == UDP_P) {
		int found = 0;
		for (int i = 0; i < protocols_found_count; i++)	{
			if (ip->ip_p == protocols_found[i]) {
				found = 1;
				break;
			}
		}
		if (found == 0) { //Not listed, add to list
			protocols_found[protocols_found_count] = ip->ip_p;
			protocols_found_count += 1;
		}
	}
	
	if (src_dst_found == 0) {
		if (ip->ip_p == ICMP_P || ip->ip_p == UDP_P) {
			ip_src = ip->ip_src;
			ip_ult_dst = ip->ip_dst;	
			
			src_dst_found = 1;	
		}
	}else {
		
	}
}




/* --------- compute_rtt() routine ------------
 * Matches packet flags, sequence numbers and acknowledgment numbers
 * to get the RTT values
 */
void compute_rtt() {

}

/* --------- print_connections() routine ------------
 * Prints connection info
 */
void print_connections() {

}

/* --------- print_general() routine ------------
 * Prints general info
 */
void print_general() {
}

/* --------- print_tcp_stats() routine ------------
 * Calculates and prints tcp complete connection stats
 */
void print_tcp_stats() {
	
}

