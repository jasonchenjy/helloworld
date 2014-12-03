#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include "sniffer_ioctl.h"
#include <sys/types.h>

#define PACKET_SIZE 65535
/*
typedef	u_int32_t	tcp_seq;

#define TH_ECNECHO	0x40
#define SIZE_ETHERNET	14
struct ethernet_hdr_t{
	uint8_t dst_mac[6];
	uint8_t src_mac[6];
	uint16_t ethertype;
};
*/

/*ip packet header*/

//struct ip_packet_header {
//        unsigned char  version_ihl;             /* ip version & internet header length */
//        unsigned char  ip_tos;                 	/* type of service */
//        unsigned short int ip_len;              /* total length */
//        unsigned short int ip_id;               /* identification */
//        unsigned short int ip_off;              /* 3 lsbs flags, reset is frageement offset */
//        #define IP_RF 0x8000            /* reserved fragment flag */
//        #define IP_DF 0x4000            /* dont fragment flag */
//        #define IP_MF 0x2000            /* more fragments flag */
//        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
//       unsigned char  ip_ttl;                  /* time to live */
//        unsigned char  ip_protocol;             /* protocol */
//        unsigned short int ip_check_sum;        /* checksum */
//       	uint32_t ip_src ;         /* source and dest address */
//	uint32_t ip_dst;

//};
//#define IP_HL(ip)	(((ip)->version_ihl) & 0x0f)
//#define IP_V(ip)	(((ip)->version_ihl) >>4)

/* tcp header structure*/
//struct tcp_packet_header {
//       u_short th_sport;               /* source port */
//        u_short th_dport;               /* destination port */
//        tcp_seq th_seq;                 /* sequence number */
//        tcp_seq th_ack;                 /* acknowledgement number */
//        u_char  th_offx2;               /* data offset, rsvd */
//        #define TH_OFF(th)              (((th)->th_offx2 & 0xf0) >> 4)
//        u_char  th_flags;
//        #define TH_FIN  0x01
//        #define TH_SYN  0x02
//        #define TH_RST  0x04
//        #define TH_PUSH 0x08
//        #define TH_ACK  0x10
//        #define TH_URG  0x20
//        #define TH_ECE  0x40
//        #define TH_CWR  0x80
//        #define TH_FLAGS                (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
//        u_short th_win;                 /* window */
//        u_short th_sum;                 /* checksum */
//        u_short th_urp;                 /* urgent pointer */
//};


static char * program_name;
static char * dev_file = "sniffer.dev";
int flag=0;

void usage() 
{
    fprintf(stderr, "Usage: %s [-i input_file] [-o output_file]\n", program_name);
    exit(EXIT_FAILURE);
}

int print_packet(char * pkt, int len, FILE* file)
{
    /* print format is :
     * src_ip:src_port -> dst_ip:dst_port
     * pkt[0] pkt[1] ...    pkt[64] \n
     * ...
     * where pkt[i] is a hex byte */
    	//printf("process!\n");
        struct ip_packet_header *ip_header;
        struct tcp_packet_header *tcp_header;
	//ip_header = (struct ip_packet_header*)(pkt+SIZE_ETHERNET);
        ip_header = (struct ip_packet_header*)(pkt);
        int size_ip=IP_HL(ip_header)*4;
        tcp_header=(struct tcp_packet_header*)(pkt+size_ip);
        uint32_t ip_src = (ip_header->ip_src);
        uint32_t ip_dst = (ip_header->ip_dst);
        int sport = ntohs(tcp_header->th_sport);
        int dport = ntohs(tcp_header->th_dport);
        //printf("=====%x===\n", ip_header->ip_src);
	if(flag){
		fprintf(file, " %d.%d.%d.%d:%d -> ", (ip_src & 0x000000ff), (ip_src& 0x0000ff00) >> 8,(ip_src& 0x00ff0000) >> 16, (ip_src& 0xff000000)>>24, sport);
		fprintf(file, "%d.%d.%d.%d port:%d\n", (ip_dst & 0x000000ff), (ip_dst& 0x0000ff00) >> 8,(ip_dst& 0x00ff0000) >> 16, (ip_dst& 0xff000000 )>>24, dport);
    	}
	else{
		fprintf(stdout, " %d.%d.%d.%d:%d -> ", (ip_src & 0x000000ff), (ip_src& 0x0000ff00) >> 8,(ip_src& 0x00ff0000) >> 16, (ip_src& 0xff000000)>>24, sport);
		fprintf(stdout, "%d.%d.%d.%d port:%d\n", (ip_dst & 0x000000ff), (ip_dst& 0x0000ff00) >> 8,(ip_dst& 0x00ff0000) >> 16, (ip_dst& 0xff000000 )>>24, dport);
	
	}
	return 0;
}
/*
void process_packet(unsigned char* buf){
	printf("process!\n");
	struct ip_packet_header *ip_header;
	struct tcp_packet_header *tcp_header;
	ip_header = (struct ip_packet_header*)(buf+SIZE_ETHERNET);
       	int size_ip=IP_HL(ip_header)*4;
       	tcp_header=(struct tcp_packet_header*)(buf+SIZE_ETHERNET+size_ip);
	uint32_t final_ip_src = ip_header->ip_src;
	uint32_t final_ip_dst = ip_header->ip_dst;
	int final_th_sport = ntohs(tcp_header->th_sport);  
        int final_th_dport = ntohs(tcp_header->th_dport); 
	printf("=====%02x===\n", ip_header->ip_src);
}
*/
int main(int argc, char **argv)
{
    //printf("begin\n");
    int c;
    char *input_file, *output_file = NULL;
    program_name = argv[0];

    input_file= dev_file;

    while((c = getopt(argc, argv, "i:o:")) != -1) {
        switch (c) {
        case 'i':
	    input_file=strdup(optarg);
	    //printf("i:%s\n", optarg);
	    //input_file=optarg;
            break;
        case 'o':
	    output_file=strdup(optarg);
            //printf("o:%s\n", optarg);
           
            break;
        default:
            usage();
        }
    }
    int file=open(input_file, 0);
    if(file<0){
	printf("can't open device file: %s\n", input_file);
		return 0;
    }
    
    FILE* out_file=NULL;
    if(output_file!=NULL){
    	out_file=fopen(output_file, "w");
	flag=1;
    }
      	
    char buf[65535];
    int size=0;
    while(size = read(file, buf, 65535)) {
	int i=0;
	print_packet(buf, size, out_file);
	for(;i<size;i++){
		if(flag){
			fprintf(out_file,"%x ", (unsigned char)buf[i]);
		}
		else{
			
			fprintf(stdout,"%x ", (unsigned char)buf[i]);
		}
		//process_packet((unsigned char)buf);
	//while(size>0)
	//{
	//	printf("%x ", (unsigned char)buf[size++]);
	}
	printf("\n");
    }
    close(file);
    if(flag){
    	fclose(out_file);
    }
    return 0;
}
