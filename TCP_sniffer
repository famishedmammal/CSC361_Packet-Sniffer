#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <stdbool.h>
#include <limits.h>
#include <float.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>

#define SIZE_ETHERNET 14

	/* Ethernet header */
	struct sniff_ethernet {
		u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
		u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
		u_short ether_type; /* IP? ARP? RARP? etc */
	};

	/* IP header */
	struct sniff_ip {
		u_char ip_vhl;		/* version << 4 | header length >> 2 */
		u_char ip_tos;		/* type of service */
		u_short ip_len;		/* total length */
		u_short ip_id;		/* identification */
		u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
		u_char ip_ttl;		/* time to live */
		u_char ip_p;		/* protocol */
		u_short ip_sum;		/* checksum */
		struct in_addr ip_src,ip_dst; /* source and dest address */
	};
	#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
	#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

	/* TCP header */
	typedef u_int tcp_seq;

	struct sniff_tcp {
		u_short th_sport;	/* source port */
		u_short th_dport;	/* destination port */
		tcp_seq th_seq;		/* sequence number */
		tcp_seq th_ack;		/* acknowledgement number */
		u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
		u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		u_short th_win;		/* window */
		u_short th_sum;		/* checksum */
		u_short th_urp;		/* urgent pointer */
};

// My struct for previously discovered connections
struct stored_connection 
{
	char *s_sourceIP;
	char *s_destIP;
	int n_toDest;
	int n_toSource;
	u_short sourceP;
	u_short destP;
	int windowSize;
	int numsyn;
	int numfin;
	bool reset;

	int starttime_pre;
	int starttime_post;
	int endtime_pre;
	int endtime_post;
	int duration_pre;
	int duration_post;
	int dbytes_toDest;
	int dbytes_toSource;

	double min_rtt;
	double max_rtt;
	double all_rtt;
	double rtt_time;
	int SEQ_OFF;	

	struct stored_connection *next;

};
typedef struct stored_connection NODE;

// Function for creating my stored_connection types
NODE* createNode(const struct sniff_ip *ip, const struct sniff_tcp *tcp, struct pcap_pkthdr header) {
	NODE* n = malloc( sizeof(NODE) );

	n->s_sourceIP = malloc(strlen(inet_ntoa(ip->ip_src))+1);
	strcpy(n->s_sourceIP, inet_ntoa(ip->ip_src));
	n->s_destIP = malloc(strlen(inet_ntoa(ip->ip_dst))+1);
	strcpy(n->s_destIP, inet_ntoa(ip->ip_dst));
	n->sourceP =  tcp->th_sport;
	n->destP =  tcp->th_dport;
	n->windowSize = ntohs(tcp->th_win);
	n->n_toDest = 1;
	n->n_toSource = 0;
	n->next = NULL;
	n->numsyn = 0;
	n->numfin = 0;
	n->reset = false;

	n->starttime_pre = header.ts.tv_sec;
	n->starttime_post = header.ts.tv_usec;
	n->endtime_pre = 0;
	n->endtime_post = 0;
	n->duration_pre = 0;
	n->duration_post = 0;
	n->dbytes_toDest = 0;
	n->dbytes_toSource = 0;

	n->min_rtt = DBL_MAX;
	n->max_rtt = DBL_MIN;
	n->all_rtt = 0.0;
	n->rtt_time = 0.0;

	return n;
}

int main(int argc, char **argv)
{
	// Initialize pCap
	struct pcap_pkthdr header;
	const u_char *packet;
	if (argc < 2) {
		fprintf(stderr, "Invalid file: %s <pcap>\n", argv[0]);
		exit(1);
	}
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_offline(argv[1], errbuf);
	if (handle == NULL) {
		fprintf(stderr,"Couldn't open pcap file %s: %s\n", argv[1], errbuf);
		return(2);
	}

	// Iterate through all packets in the dump file.
	NODE *root = NULL;
	NODE *getinfo = NULL;
	int numReset = 0;
	while (packet = pcap_next(handle,&header)) {
		
		// Define pointers
		const struct sniff_ethernet *ethernet;  
		const struct sniff_ip *ip;              
		const struct sniff_tcp *tcp;            
		const char *payload;                   
		int size_ip;
		int size_tcp;
		int size_payload;
		bool toDest = true;
		
		// Break packet into components
		ethernet = (struct sniff_ethernet*)(packet);
		ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
		size_ip = IP_HL(ip)*4;
		tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
		size_tcp = TH_OFF(tcp)*4;
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
		size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

		//Determine if connection is unique
		if (root == NULL) 
		{
			root = getinfo = createNode(ip, tcp, header);
		}
		else 
		{
			NODE *prev_index = NULL;
			NODE *curr_index = NULL;
			curr_index = root;

			while(curr_index != NULL) {

				// Case : source->dest. Check 4-tuple.
				if ((strcmp(inet_ntoa(ip->ip_src), curr_index->s_sourceIP) == 0) && (strcmp(inet_ntoa(ip->ip_dst), curr_index->s_destIP) == 0)
					&& (ntohs(curr_index->sourceP) == ntohs(tcp->th_sport)) && (ntohs(curr_index->destP) == ntohs(tcp->th_dport))					
					)
				{
					curr_index->n_toDest++;
					break;
				}
				// Case : dest->source. Check 4-tuple, reversed.
				else if ((strcmp(inet_ntoa(ip->ip_src), curr_index->s_destIP) == 0) && (strcmp(inet_ntoa(ip->ip_dst), curr_index->s_sourceIP) == 0)
					&& (ntohs(curr_index->sourceP) == ntohs(tcp->th_dport)) && (ntohs(curr_index->destP) == ntohs(tcp->th_sport))
					)
				{
					curr_index->n_toSource++;
					toDest = false;
					break;
				}
				
				prev_index = curr_index;
				curr_index = curr_index->next;
			}
			
			// Case : Discovered new connection. Create new stored_connection
			if (curr_index == NULL) 
				getinfo = (prev_index->next) = createNode(ip, tcp, header);
			else
				getinfo = curr_index;
		}

		// Take discovered information and add it to corresponding stored_connection
		if (tcp->th_flags & TH_SYN) 
			getinfo->numsyn++;	
		if (tcp->th_flags & TH_FIN) 
			getinfo->numfin++;
		if (tcp->th_flags & TH_RST) {
			getinfo->reset = true;
			numReset++;
		}
		getinfo->endtime_pre = header.ts.tv_sec;
		getinfo->endtime_post = header.ts.tv_usec;	
		getinfo->duration_pre = (getinfo->endtime_pre)-(getinfo->starttime_pre);
		getinfo->duration_post = (getinfo->endtime_post)-(getinfo->starttime_post);
		if (getinfo->duration_post < 0) {
			getinfo->duration_pre--;
			getinfo->duration_post = (1-getinfo->duration_post);
		}
		if (toDest)
			getinfo->dbytes_toDest += size_payload;
		else
			getinfo->dbytes_toSource += size_payload;
		
		// Round trip time
		if ( toDest )
		{
			getinfo->rtt_time = header.ts.tv_sec + (header.ts.tv_usec/ 1000000.0);
			getinfo->SEQ_OFF = ntohl(tcp->th_seq) + size_payload; 
		}
		else if ( (getinfo->SEQ_OFF == ntohl(tcp->th_ack)) )
		{
			double rtt = (header.ts.tv_sec + (header.ts.tv_usec/ 1000000.0)) - getinfo->rtt_time;
			if (rtt < getinfo->min_rtt)
				getinfo->min_rtt = rtt;
			if (rtt > getinfo->max_rtt)
				getinfo->max_rtt = rtt;
			getinfo->all_rtt += rtt;
		}

			
	}

	// Display : Count the number of connections
	int numConnections = 0;
	NODE *curr_index_ = root;
	while(curr_index_ != NULL) {
		numConnections++;
		curr_index_ = curr_index_->next;
	}
	printf("\n\nA) Total number of connections: %d\n\n---------------------------\n\nB) Connection details:\n", numConnections);

	// Display : Unique connection information
	numConnections = 0;
	int numOpen = 0;
	int numComplete = 0;
	int minTime_pre = INT_MAX;
	int minTime_post = INT_MAX;
	int maxTime_pre = INT_MIN;
	int maxTime_post = INT_MIN;
	int minPackets = INT_MAX;
	int maxPackets = INT_MIN;
	int minWindow = INT_MAX;
	int maxWindow = INT_MIN;
	double meanTime = 0.0;
	double meanPackets = 0.0;
	double meanWindow = 0.0;
	double minRTT = DBL_MAX;
	double maxRTT = DBL_MIN;
	double meanRTT = 0.0;
	curr_index_ = root;
	while(curr_index_ != NULL) {
		printf("\n++++++++++\n");
		printf("\nConnection %d:", numConnections++);
		printf("\nSource Address: %s", curr_index_->s_sourceIP);
		printf("\nDestination Address: %s", curr_index_->s_destIP);
		printf("\nSource Port: %d", ntohs(curr_index_->sourceP));
		printf("\nDestination Port: %d", ntohs(curr_index_->destP));
		if (curr_index_->reset == true) {
			printf("\nStatus: R");
			printf("\nEND\n");
			curr_index_ = curr_index_->next;
			continue;
		}
		printf("\nStatus: S%dF%d", curr_index_->numsyn, curr_index_->numfin);
		printf("\nStart Time: %d.%06d", curr_index_->starttime_pre, curr_index_->starttime_post); 
		printf("\nEnd Time: %d.%06d", curr_index_->endtime_pre, curr_index_->endtime_post); 
		printf("\nDuration: %d.%06d", curr_index_->duration_pre, curr_index_->duration_post);
		printf("\nNumber of packets sent from Source to Destination: %d", curr_index_->n_toDest);
		printf("\nNumber of packets sent from Destination to Source: %d", curr_index_->n_toSource);
		printf("\nTotal number of packets: %d", curr_index_->n_toDest + curr_index_->n_toSource);
		printf("\nNumber of data bytes sent from Source to Destination: %d", curr_index_->dbytes_toDest);
		printf("\nNumber of data bytes sent from Destination to Source: %d", curr_index_->dbytes_toSource);
		printf("\nTotal number of data bytes: %d", curr_index_->dbytes_toDest + curr_index_->dbytes_toSource);
		printf("\nEND\n");

		// Calculate averages, etc.
		if ((curr_index_->numsyn > 0) && (curr_index_->numfin > 0)) {
			if (curr_index_->duration_pre <= minTime_pre) 
			{
				if (curr_index_->duration_post <= minTime_post) 
				{
					minTime_pre = curr_index_->duration_pre;
					minTime_post = curr_index_->duration_post;
				}
			}
	 		if (curr_index_->duration_pre >= maxTime_pre) 
			{
				if (curr_index_->duration_post >= maxTime_post) 
				{
					maxTime_pre = curr_index_->duration_pre;
					maxTime_post = curr_index_->duration_post;
				}
			}
			if ((curr_index_->n_toDest) + (curr_index_->n_toSource) < minPackets) 
			{
				minPackets = (curr_index_->n_toDest) + (curr_index_->n_toSource);
			}
			if ((curr_index_->n_toDest) + (curr_index_->n_toSource) > maxPackets) 
			{
				maxPackets = (curr_index_->n_toDest) + (curr_index_->n_toSource);
			}
			if (curr_index_->windowSize > maxWindow) {
				maxWindow = curr_index_->windowSize;		
			}
			if (curr_index_->windowSize < minWindow) {
				minWindow = curr_index_->windowSize;		
			}
			if (curr_index_->max_rtt > maxRTT)
			{
				maxRTT = curr_index_->max_rtt;
			}
			if (curr_index_->min_rtt < minRTT)
			{
				minRTT = curr_index_->min_rtt;
			}
			meanRTT += curr_index_->all_rtt / (curr_index_->n_toDest + curr_index_->n_toSource);
			meanWindow += curr_index_->windowSize;	
			meanTime += (curr_index_->duration_pre)+(curr_index_->duration_post / 1000000.0);
			meanPackets += (curr_index_->n_toDest) + (curr_index_->n_toSource);
			numComplete++;
		}			
		if ((!curr_index_->reset) && (curr_index_->numfin==0))
			numOpen++;
		curr_index_ = curr_index_->next;
	};
	meanTime /= numComplete;
	meanPackets /= numComplete;
	meanWindow /= numComplete;
	meanRTT /= numComplete;

	printf("\n-------------------------------------------------\n");

	printf("\nC) General");
	printf("\nTotal number of complete TCP connections: %d", numComplete);
	printf("\nNumber of reset TCP connections: %d", numReset);
	printf("\nNumber of TCP connections that were still open when the trace capture ended: %d", numOpen);

	printf("\n\n-------------------------------------------------\n");

	printf("\nC) Complete TCP Connections:\n");
	printf("\nMinimum time durations: %d.%06d", minTime_pre, minTime_post);
	printf("\nMean time durations: %f", meanTime);
	printf("\nMaximum time durations: %d.%06d\n", maxTime_pre, maxTime_post);

	printf("\nMinimum RTT values including both send/received: %f", minRTT);
	printf("\nMean RTT values including both send/received: %f", meanRTT);
	printf("\nMaximum RTT values including both send/received: %f\n", maxRTT);

	printf("\nMinimum number of packets including both send/received: %d", minPackets);
	printf("\nMean number of packets including both send/received: %f", meanPackets);
	printf("\nMaximum number of packets including both send/received: %d\n", maxPackets);

	printf("\nMinimum receive window sizes including both send/received: %d", minWindow);
	printf("\nMean receive window sizes including both send/received: %f", meanWindow);
	printf("\nMaximum receive window sizes including both send/received: %d\n\n", maxWindow);

	pcap_close(handle);
	return 0;
}
