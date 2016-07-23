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
#include <netinet/udp.h>
#include <sys/time.h>
#include <math.h>
#include "ip_analyzer.h"

#define MAX_NUM_HOPS 80
#define MAX_NUM_PROTOCOLS 20
#define MAX_NUM_PROBES 5
#define MAX_NUM_DATAGRAMS MAX_NUM_HOPS*MAX_NUM_PROBES

struct in_addr ip_src;
struct in_addr ip_ult_dst;
struct in_addr ip_intr_dst[MAX_NUM_HOPS];
int ip_intr_dst_count = 0;
int src_dst_found = 0;  //The number of valid packets

struct timeval outgoing_time[MAX_NUM_HOPS][MAX_NUM_PROBES];
u_short outgoing_seq_num[MAX_NUM_HOPS][MAX_NUM_PROBES]; //SEQ NUM can technically be a port
int outgoing_time_count_per_hop[MAX_NUM_HOPS];

struct timeval rtt_time[MAX_NUM_HOPS][MAX_NUM_PROBES];
int rtt_count[MAX_NUM_HOPS];

struct timeval rtt_avg_time[MAX_NUM_HOPS];
struct timeval rtt_std_time[MAX_NUM_HOPS];

u_short first_id = -1;
u_short udp_port = 0;

u_char protocols_found[MAX_NUM_PROTOCOLS];
int protocols_found_count = 0;

u_short fragment_first_id[MAX_NUM_DATAGRAMS];
u_short fragment_udp_port[MAX_NUM_DATAGRAMS]; //REMOVE
int fragments_found_count[MAX_NUM_DATAGRAMS];
int last_fragment_offset[MAX_NUM_DATAGRAMS];
int fragmented_datagram_count = 0;



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
	
	//Set these to -1 so we know they haven't been set yet
	for (int i = 0; i < MAX_NUM_DATAGRAMS; i++) {
		fragment_first_id[i] = -1;
		fragment_udp_port[i] = -1;
	}
	
	//Open Pcap files and parse each packet
	pcap = OpenTraceFile(filename);
	
	while ((packet = pcap_next(pcap, &header)) != NULL){
		if (ParsePacket(packet, header.ts, header.caplen) == 1) {
			break;
		}
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
		//PRINT DATAGRAM FRAGMENT STATS
		for (int i = 0; i < fragmented_datagram_count; i++) {
			//if (fragments_found_count[i] > 0) {
			printf("The number of fragments created from the original datagram D%d is: %d\n",i+1,fragments_found_count[i]);
			printf("The offset of the last fragment is: %d\n", last_fragment_offset[i]);
			printf("\n");
			//}
		}
		if (fragmented_datagram_count == 0) {
			printf("No fragmented packets\n\n");
		}
		
		avg_rtt();
		
		//PRINT RTT STATS
		char src_port_str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &ip_src,src_port_str,INET_ADDRSTRLEN);
		int i = 0;
		for (i = 0; i < ip_intr_dst_count; i++) {
			inet_ntop(AF_INET, &ip_intr_dst[i],str,INET_ADDRSTRLEN);
			char* time = timestamp_string(rtt_avg_time[i]);
			printf( "The avg RTT between %s and %s is: %s s, ",src_port_str,str,time);
			time = timestamp_string(rtt_std_time[i]);
			printf( "the s.d. is: %s s\n",time);
		}
		inet_ntop(AF_INET, &ip_ult_dst,str,INET_ADDRSTRLEN);
		char* time = timestamp_string(rtt_avg_time[i]);
		printf("The avg RTT between %s and %s is: %s s, ",src_port_str,str,time);
		time = timestamp_string(rtt_std_time[i]);
		printf( "the s.d. is: %s s\n",time);
		printf("\n");	
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
		return 0;
	}
	
	//Now skip over ethernet header and check if we might have an ip header
	packet += sizeof(struct ether_header);
	capture_len -= sizeof(struct ether_header);
	if (capture_len < sizeof(struct ip)) {
		too_short(ts, "IP Header");
		return 0;
	}
	
	ip = (struct ip*) packet;
	IP_header_length = ip->ip_hl * 4;	/* ip_hl is in 4-byte words */
	
	if (capture_len < IP_header_length) { /* didn't capture the full IP header including options */
		too_short(ts, "IP header with options");
		return 0;
	}
	
	return ParseIP(packet, ip, ts);
	
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
double timevaldiff(struct timeval *starttime, struct timeval *finishtime) {
	double msec;
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
int ParseIP(const unsigned char *packet, struct ip *ip, struct timeval ts) {

	u_short id = ntohs(ip->ip_id); //& 0x0F;	
	unsigned int IP_header_len = ip->ip_hl * 4;
	int mf = (ip->ip_off & 0x0020) >> 5;
	int cur_frag_num = (int)(ip->ip_ttl)-1;
	u_short src_port;
	u_short icmp_seq_num;
	int udp_res = 0; //Is this a response to a udp packet
	//u_char msg_ttl;
	
	packet += IP_header_len;
	
	//Packet is ICMP
	if (ip->ip_p == ICMP_P) {
		struct icmphdr* icmp = (struct icmphdr*) packet;	
		add_protocol(ip->ip_p);
		
		//Skip over everything in the icmp message until we get the udp source port or icmp seq
		packet += sizeof(struct icmphdr); //This will be the packet return from the icmp data
		struct ip* msg_ip = (struct ip*) packet;
		unsigned int msg_header_len = (msg_ip->ip_hl) * 4;
		//msg_ttl = msg_ip->ip_ttl;
		packet += msg_header_len;
		if (msg_ip->ip_p == UDP_P) {
			udp_res = 1;
			struct udphdr* msg_udp = (struct udphdr*) packet;
			//what we want is u_short src_port = udp->uh_sport; (FOR MATCHING THINGS)
			src_port = msg_udp->uh_sport;	
			//printf("udp port %hu\n",src_port);
			
		}else if (msg_ip->ip_p == ICMP_P && (icmp->type == 11 || icmp->type == 0) ) {
			struct icmphdr* msg_icmp = (struct icmphdr*) packet;
			icmp_seq_num = msg_icmp->un.echo.sequence;
			packet += sizeof(struct icmphdr);
			msg_ip = (struct ip*) packet;
			//printf("icmp seq num found %hu ttl %d\n",icmp_seq_num, (int)msg_ttl);
		}
		
		//Packet timed out
		if (icmp->type == 11) {
			 //MORE THAN MAX HOPE ERROR HERE
			 add_intr_dst(ip->ip_src);
			 if (udp_res == 0) {
				add_incoming_time(icmp_seq_num,ts);
			 } else {
			 	add_incoming_time_by_port(src_port,ts);
			 }
			 
		}else if (icmp->type == 8 && ip->ip_ttl == (char)1 && first_id == (u_short)(-1)) { //NEW ID
			//Set source and ult ip addresses
			ip_src = ip->ip_src;
			ip_ult_dst = ip->ip_dst;
			//Record time packet was sent
			add_outgoing_time(icmp,ts,ip->ip_ttl);
			//Set ID of first packet
			first_id = ntohs(ip->ip_id);	
			fragment_first_id[cur_frag_num] = id;		
			if (mf == 1) { //FRAGMENTS HERE
				fragments_found_count[fragmented_datagram_count]++;
				fragmented_datagram_count++;
			}
			
		}else if (first_id == id) { //PACKET IS A FRAGMENT // || udp_port == src_port  
			fragments_found_count[0]++;
			//Get offset value
			u_short offset = ntohs(ip->ip_off) & 0x1FFF;
			if (mf == 0) {
				last_fragment_offset[0] = (int)offset * 8;
			}
			//Record time packet was sent
			
		}else if (icmp->type == 8) {
			//Record time packet was sent
			if (fragment_first_id[cur_frag_num] == (u_short)(-1)) {
				
				fragment_first_id[cur_frag_num] = id;
				
				//fragment_udp_port[cur_frag_num] = (ip->ip_src.s_addr);
				fragmented_datagram_count++;

				add_outgoing_time(icmp,ts,ip->ip_ttl);
			}else {
				add_outgoing_time(icmp,ts,ip->ip_ttl);
			}
			
		}else if (icmp->type == 0 || icmp->type == 3) {
			if (udp_res == 0) {
				add_incoming_time(icmp_seq_num,ts);
			 } else {
			 	add_incoming_time_by_port(src_port,ts);
			 }
			return 1;
			
		}
		
	}else if (ip->ip_p == UDP_P) {
	
		struct udphdr* udp = (struct udphdr*) packet;
		add_protocol(ip->ip_p);

		//printf("cur_frag_num %hu fragment_first_id[cfn] %hu\n",cur_frag_num,fragment_first_id[cur_frag_num]);

		if (ip->ip_ttl == (char)1 && first_id == (u_short)(-1)) {  //First Packet
			
			//Set source and ult ip addresses
			ip_src = ip->ip_src;
			ip_ult_dst = ip->ip_dst;
			//Set id
			first_id = ntohs(ip->ip_id); //REMOVE
			fragment_first_id[0] = ntohs(ip->ip_id);
			//fragment_udp_port[0] = udp->uh_sport;
			//outgoing_seq_num[ip->ip_ttl][outgoing_time_count_per_hop[ip->ip_ttl]] = (udp->uh_sport);
			//outgoing_time_count_per_hop[ip->ip_ttl]++;
			add_outgoing_time_by_port(udp->uh_sport,ts,ip->ip_ttl); //add_outgoing_time(icmp_seq_num,ts,ip->ip_ttl);
			//Set port
			udp_port = udp->uh_sport;
			fragmented_datagram_count++;
			if (mf == 1) { //FRAGMENTS HERE
				fragments_found_count[fragmented_datagram_count]++;				
			}
		}else if (fragment_first_id[cur_frag_num] == (u_short)(-1)) { //First of new fragment
			fragment_first_id[cur_frag_num] = id;
			//fragment_udp_port[cur_frag_num] = udp->uh_sport;
			//outgoing_seq_num[ip->ip_ttl][outgoing_time_count_per_hop[ip->ip_ttl]] = (udp->uh_sport);
			//outgoing_time_count_per_hop[ip->ip_ttl]++;
			add_outgoing_time_by_port(udp->uh_sport,ts,ip->ip_ttl);
			fragmented_datagram_count++;
			
			if (mf == 1) { //FRAGMENTS HERE
				fragments_found_count[fragmented_datagram_count]++;				
			}
			
		}else if ( id == (fragment_first_id[cur_frag_num]) ){
			fragments_found_count[cur_frag_num]++;
			
			if (mf == 0) {
				//Get offset value
				u_short offset = ntohs(ip->ip_off) & 0x1FFF;
				last_fragment_offset[cur_frag_num] = (int)offset * 8;
			}
			
		} else {
			add_outgoing_time_by_port(udp->uh_sport,ts,ip->ip_ttl);
		}
	}
	
	src_dst_found = 1; //CHANGE THIS
	return 0;
}

void add_outgoing_time(struct icmphdr* icmp, struct timeval ts,  u_char ttl) {
	int ind = ttl-1;
	outgoing_seq_num[ind][outgoing_time_count_per_hop[ind]] = icmp->un.echo.sequence;
	outgoing_time[ind][outgoing_time_count_per_hop[ind]] = ts;
//	printf("hello ttl %hu seq %hu ts %s\n",ttl,outgoing_seq_num[ind][outgoing_time_count_per_hop[ind]],timestamp_string(outgoing_time[ind][outgoing_time_count_per_hop[ind]]) );

	outgoing_time_count_per_hop[ind]++;
	
}

void add_outgoing_time_by_port(u_short src_port, struct timeval ts,  u_char ttl) {
	int ind = ttl-1;
	outgoing_seq_num[ind][outgoing_time_count_per_hop[ind]] = src_port;
	outgoing_time[ind][outgoing_time_count_per_hop[ind]] = ts;
	//printf("hello ttl %hu seq %hu ts %s\n",ttl,outgoing_seq_num[ind][outgoing_time_count_per_hop[ind]],timestamp_string(outgoing_time[ind][outgoing_time_count_per_hop[ind]]) );
	//printf("outgoing port %d\n",src_port);
	outgoing_time_count_per_hop[ind]++;
	
}

void add_incoming_time(u_short seq_num, struct timeval ts) {
	//printf("add incoming time seq_num %hu\n", seq_num);
	int indX = -1;
	int indY = -1;
	for (int i = 0; i < ip_intr_dst_count+1; i++) {
		for (int j = 0; j < outgoing_time_count_per_hop[i]; j++) {
			//printf("saw seq %hu\n",
			if (seq_num == outgoing_seq_num[i][j]) {
				indX = i;
				indY = j;
				break;
			}
		}
		if (indX > -1) {
			break;
		}
	}
	if (indY > -1 && indX > -1) {
		timersub(&ts,&outgoing_time[indX][indY],&rtt_time[indX][indY]);
	}	
}

void add_incoming_time_by_port(u_short port, struct timeval ts) {
	//printf("add incoming time port %hu\n", port);
	int indX = -1;
	int indY = -1;
	for (int i = 0; i < ip_intr_dst_count+1; i++) {
		for (int j = 0; j < outgoing_time_count_per_hop[i]; j++) {
			//printf("saw seq %hu\n",
			if (port == outgoing_seq_num[i][j]) {
				indX = i;
				indY = j;
				break;
			}
		}
		if (indX > -1) {
			break;
		}
	}
	if (indY > -1 && indX > -1) {
		//printf("saved time by port\n");
		timersub(&ts,&outgoing_time[indX][indY],&rtt_time[indX][indY]);
		//printf("rtt_time %s\n", timestamp_string(rtt_time[0][1]));
	}	
}

void avg_rtt() {
	struct timeval temp_time;
	for (int i = 0; i < ip_intr_dst_count+1; i++) {
		timerclear(&temp_time);
		timerclear(&rtt_std_time[i]);
		for (int j = 0; j < outgoing_time_count_per_hop[i]; j++) {
			timeradd(&rtt_avg_time[i], &rtt_time[i][j], &rtt_avg_time[i]);
			if (j+1 == outgoing_time_count_per_hop[i]  && j != 0) {
				rtt_avg_time[i].tv_sec /= (float)j;
				rtt_avg_time[i].tv_usec /= (float)j;
				for (int k = 0; k < j; k++) {
					rtt_std_time[i].tv_usec += pow(rtt_time[i][k].tv_usec-rtt_avg_time[i].tv_usec,2);
				}
				rtt_std_time[i].tv_sec = 0;
				rtt_std_time[i].tv_usec = sqrt(rtt_std_time[i].tv_usec/j);
			}
		}
	}
}

int find_fragment_num_by_id(u_short id) {
	for (int i = 0; i < fragmented_datagram_count; i++) {
		if (fragment_first_id[i] == id) {
			return i;
		}
	}
	return -1;
}

int find_fragment_num_by_port(u_short port) {
	for (int i = 0; i < fragmented_datagram_count; i++) {
		if (fragment_udp_port[i] == port) {
			return i;
		}
	}
	return -1;
}

void add_intr_dst(struct in_addr ip) {
	int found = 0;
	for (int i = 0; i < ip_intr_dst_count; i++) {
		if (ip_intr_dst[i].s_addr == ip.s_addr) {
			found = 1;
			break;
		}
	}
	if (found == 0) {
		ip_intr_dst[ip_intr_dst_count] = ip;
		ip_intr_dst_count += 1;	
	}
}

void add_protocol(u_char protocol) {
	int found = 0;
	for (int i = 0; i < protocols_found_count; i++)	{
		if (protocol == protocols_found[i]) {
			found = 1;
			break;
		}
	}
	if (found == 0) { //Not listed, add to list
		protocols_found[protocols_found_count] = protocol;
		protocols_found_count += 1;
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

