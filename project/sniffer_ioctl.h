#ifndef __SNIFFER_IOCTL_
#define __SNIFFER_IOCTL__

typedef u_int32_t       tcp_seq;

#define TH_ECNECHO      0x40
#define SIZE_ETHERNET   14
#define HASH_MAP_SIZE 400000

struct ethernet_hdr_t{
        uint8_t dst_mac[6];
        uint8_t src_mac[6];
        uint16_t ethertype;
};


/*ip packet header*/
struct ip_packet_header {
        unsigned char  version_ihl;             /* ip version & internet header length */
        unsigned char  ip_tos;                  /* type of service */
        unsigned short int ip_len;              /* total length */
        unsigned short int ip_id;               /* identification */
        unsigned short int ip_off;              /* 3 lsbs flags, reset is frageement offset */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        unsigned char  ip_ttl;                  /* time to live */
        unsigned char  ip_protocol;             /* protocol */
        unsigned short int ip_check_sum;        /* checksum */
        uint32_t ip_src ;         /* source and dest address */
        uint32_t ip_dst;
//	uint8_t options_and_data[0];
};
#define IP_HL(ip)       (((ip)->version_ihl) & 0x0f)
#define IP_V(ip)        (((ip)->version_ihl) >>4)

/* tcp header structure*/
struct tcp_packet_header {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
        #define TH_OFF(th)              (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS                (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
//	uint8_t options_and_data[0];
};



struct sniffer_flow_entry {
	uint32_t dst_ip;
	uint32_t src_ip;
	uint16_t src_port;
	uint16_t dst_port;
	int action;
	char* interface;
	int protocol;  //0: udp 1:icmp 2:tcp
	int direction; //-1:any 0: in 1: out
	char* dev_file;
};

typedef enum {SYN, SYNACK, ACK, FIN, RST, EMPTY, FINACK, UNKNOWN} FLAG;


struct chain{
	void* list;
};

struct state_HashMap{
	struct chain* array;
};



#define SNIFFER_IOC_MAGIC       'p'

#define SNIFFER_FLOW_ENABLE     _IOW(SNIFFER_IOC_MAGIC, 0x1, struct sniffer_flow_entry)
#define SNIFFER_FLOW_DISABLE    _IOW(SNIFFER_IOC_MAGIC, 0x2, struct sniffer_flow_entry)

#define SNIFFER_IOC_MAXNR   0x3


#define SNIFFER_ACTION_NULL     0x0
#define SNIFFER_ACTION_CAPTURE  0x1
#define SNIFFER_ACTION_DPI      0x2

#endif /* __SNIFFER_IOCTL__ */
