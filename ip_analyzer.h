//HEADER FILE FOR ip_analyzer.c

//HEADER DEFINITIONS
#define MAX_STR_LEN 80


//IP PROTOCOLS
#define MAX_NUM_PROTOCOLS 20
#define ICMP_P 0x01
#define TCP_P 0x06
#define UDP_P 0x11

const char *protocol_types[] = {"HOPOPT","ICMP","IGMP","GGP","IP-in-IP","ST", "TCP", "CBT", "EGP", "IGP", "BBN-RCC-MON", "NVP-II", "PUP", "ARGUS", "EMCON", "XNET", "CHAOS", "UDP", "MUX", "DCN-MEAS", "HMP"};

struct round_trip {
	double dur;
};


//Functions
int main(int argc, char **argv);
pcap_t* OpenTraceFile(char *filename);
int ParsePacket(const unsigned char *packet, struct timeval ts, unsigned int capture_len);

