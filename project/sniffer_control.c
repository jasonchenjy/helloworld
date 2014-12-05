#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <netdb.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <errno.h>
#include "sniffer_ioctl.h"

static char * program_name;
static char * dev_file = "sniffer.dev";
static unsigned int cmd=0;

void usage() 
{
    fprintf(stderr, "Usage: %s [parameters]\n"
                "parameters: \n"
                "    --mode [enable|disable]\n"
                "    --src_ip [url|any] : default is any \n"
                "    --src_port [XXX|any] : default is any \n"
                "    --dst_ip [url|any] : default is any \n" 
                "    --dst_port [XXX|any] : default is any \n"
		"    --protocol [tcp|udp|icmp] : default is any \n"
		"    --direction [in|out] : default is any \n"
		"    --interface [name] : default is NULL \n"
                "    --action [capture|dpi] : default is null\n", program_name);
    exit(EXIT_FAILURE);
}

int sniffer_send_command(struct sniffer_flow_entry *flow)
{
	int file=open(flow->dev_file, 0);
	if(file<0){
		printf("can't open device file: %s\n", flow->dev_file);
		return 0;
	}
	int ret_val=ioctl(file, cmd, flow);
	if(ret_val<0){
		printf("ioctl failed\n");
	}
    	return 0;
}

void initial(struct sniffer_flow_entry *entry){
	entry->dst_ip=0;
	entry->src_ip=0;
	entry->src_port=0;
	entry->dst_port=0;
	entry->action=0;
	entry->direction=-1;
	entry->protocol=2;
	entry->interface=NULL;
	entry->dev_file=(char*)malloc(40);
	memset(entry->dev_file, '\0', 40);
	strcpy(entry->dev_file, dev_file);

}
/*
uint32_t get_local_ip(){
	int fd;
	struct ifreq ifr;
	char iface[] = "eth0";
	fd=socket(AF_INET, SOCK_DGRAM, 0);
	if(fd<0){
		printf("fd==%d=\n", fd);
		return 0;
	}
	ifr.ifr_addr.sa_family=AF_INET;
	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
	int ret_val=ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);
	if(ret_val<0){
		printf("ioctl========%d= fd: %s\n", ret_val, strerror(errno));
		return 0;
	}
	printf("%s - %s \n", iface, inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));
	
	return 0;
	
}
*/

int main(int argc, char **argv)
{
    int c;
    program_name = argv[0];
    struct hostent* hp;
    char* end;
    char capture[]="capture";
    char dpi[]="dpi";
    char localhost[]="localhost";
    long val=0;

    struct sniffer_flow_entry *entry=(struct sniffer_flow_entry*)malloc(sizeof(struct sniffer_flow_entry));
    initial(entry);
    //get_local_ip();
    while(1) {
	
        static struct option long_options[] = 
        {
            {"mode", required_argument, 0, 0},
            {"src_ip", required_argument, 0, 0},
            {"src_port", required_argument, 0, 0},
            {"dst_ip", required_argument, 0, 0},
            {"dst_port", required_argument, 0, 0},
            {"action", required_argument, 0, 0},
            {"dev", required_argument, 0, 0},
	    {"interface", required_argument, 0, 0},
	    {"direction", required_argument, 0, 0},
	    {"protocol", required_argument, 0, 0},
            {0, 0, 0, 0}
        };
        int option_index = 0;
        c = getopt_long (argc, argv, "", long_options, &option_index);

        if (c == -1)
            break;

        switch (c) {
        case 0:
	    
            printf("option %d %s", option_index, long_options[option_index].name);
            if (optarg)
                printf(" with arg %s", optarg);
            printf("\n");

            switch(option_index) {
            case 0:     // mode
		
		if(strcmp(optarg, "enable")==0){
			cmd=SNIFFER_FLOW_ENABLE;
			printf("enable!!\n");
		}else{
			cmd=SNIFFER_FLOW_DISABLE;
			printf("disable!!\n");
		}
		
                break;
            case 1:     // src_ip
		if(strcmp(optarg, localhost)==0 && 0){
			//entry->dst_ip=get_local_ip();
		}else{
			hp=gethostbyname(optarg);
			if(hp==NULL){
				break;
			}
			else{
				entry->src_ip=ntohl(*((unsigned int*)(hp->h_addr_list[0])));
			}
		}
		printf("========src ip:%d======\n", entry->src_ip);
		printf("From IP address: %d.%d.%d.%d\n", (entry->src_ip& 0xff000000)>>24, (entry->src_ip& 0x00ff0000) >> 16,(entry->src_ip& 0x0000ff00) >> 8, (entry->src_ip& 0x000000ff));
                break;
            case 2:     // src_port
		if(strcmp(optarg, "any")==0){
			entry->src_port=0;
			break;		
		}
		val=strtol(optarg, &end, 10);
		if(*end!='\0' ||val<0 ||val>=0x10000){
			break;
		}
		entry->src_port=(uint16_t)val;
		printf("======src port:%d======\n", entry->src_port);
                break;
            case 3:     // dst_ip
		if(strcmp(optarg, localhost)==0 && 0){
			//entry->dst_ip=get_local_ip();
		}else{
			hp=gethostbyname(optarg);
			if(hp==NULL){
				break;
			}
			else{
				entry->dst_ip=ntohl(*((unsigned int*)(hp->h_addr_list[0])));
			}
		}
		printf("=====dst ip:%d====\n", entry->dst_ip);
		printf("From IP address: %d.%d.%d.%d\n", (entry->dst_ip& 0xff000000)>>24, (entry->dst_ip& 0x00ff0000) >> 16,(entry->dst_ip& 0x0000ff00) >> 8, (entry->dst_ip& 0x000000ff));
                break;
            case 4:     // dst_port
		if(strcmp(optarg, "any")){
			entry->dst_port=0;
			break;
		}
		val=strtol(optarg, &end, 10);
		if(*end!='\0' ||val<0 ||val>=0x10000){
			break;
		}
		entry->dst_port=(uint16_t)val;
		printf("======dst port:%d=====\n", entry->dst_port);
                break;
            case 5:     // action
		
		if(strcmp(optarg, capture)==0){
			entry->action=SNIFFER_ACTION_CAPTURE;
		}else if(strcmp(optarg, dpi)==0){
			entry->action=SNIFFER_ACTION_DPI;
		}else{
			entry->action=SNIFFER_ACTION_NULL;
		}
                break;
            case 6:     // dev
		memset(entry->dev_file, '\0', 40);
		strcpy(entry->dev_file, optarg);
                break;
	    case 7:    //interface
		printf("======7:=====\n");
		break;
            case 8:    //direction
		if(strcmp(optarg, "IN")==0 || strcmp(optarg, "in")==0){
			entry->direction=0;
		}
		else if(strcmp(optarg, "OUT")==0 || strcmp(optarg, "out")==0){
			entry->direction=1;
			
		}
		printf("======8:=====\n");
		break;
	    case 9:
		if(strcmp(optarg, "udp")==0){
			entry->protocol=0;
		}
		else if(strcmp(optarg, "icmp")==0){
			entry->protocol=1;
			
		}
		else if(strcmp(optarg, "tcp")==0){
			entry->protocol=2;
			
		}
		printf("======dst protocol:%d=====\n", entry->protocol);
            	break;
	    }
	    break;
        default:
	    
            usage();
        }
	
    }
    sniffer_send_command(entry);
    free(entry->dev_file);
    free(entry);
    return 0;
}
