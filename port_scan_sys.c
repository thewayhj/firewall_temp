//syn_port_scan.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>

#define START_PORT 20
#define END_PORT 90	

#define LOCAL_IP "192.168.80.129"
#define LOCAL_PORT 9000

unsigned short cksum_in(unsigned short *, int);
void scan_syn_port(unsigned long target, int port);

struct pseudohdr {
	unsigned long s_addr;
	unsigned long d_addr;
	char zero;
	unsigned char protocol;
	unsigned short length;
};

int main(int argc, char *argv[])
{
	unsigned long target;
	int portNum;
	struct hostent *h;

	if(argc < 2) {
		printf("usage : portscan domain_name\n");
		exit(-1);
	}

	if((target = inet_addr(argv[1])) == -1) {
		h = gethostbyname(argv[1]);
		if(!h) {
			printf("gethostbyname error\n");
			return 4;
		}
		target = ((struct in_addr*)h->h_addr)->s_addr;
	}
	
	for(portNum = START_PORT; portNum <= END_PORT; portNum++) {
		printf("port %d scanning..", portNum);
		scan_syn_port(target, portNum);
	}
}

void scan_syn_port(unsigned long target, int port)
{
	int sd;

	int on = 1;
	int len;

	int tx_packet_size = sizeof(struct ip) + sizeof(struct tcphdr) + sizeof(struct pseudohdr);
	int rx_packet_size = sizeof(struct ip) + sizeof(struct tcphdr);
	char *rx_packet = (char *)malloc(rx_packet_size);
	char *tx_packet = (char *)malloc(tx_packet_size);

	struct tcphdr *tcph, *rx_tcph;
	struct ip *iph, *rx_iph;
	struct pseudohdr *pseudoh;

	struct in_addr s_addr, d_addr;
	struct sockaddr_in local, remote;
	
	struct servent *serv;

	iph = (struct ip *)(tx_packet);
	tcph = (struct tcphdr *)(tx_packet + sizeof(struct ip));
	pseudoh = (struct pseudohdr *)(tx_packet + sizeof(struct ip) + sizeof(struct tcphdr));

	if((sd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
		printf("socket open error\n");
		exit(-1);
	}

	if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on)) < 0) {
		printf("set socket option error\n");
		exit(-2);
	}

	memset(tx_packet, 0, tx_packet_size);

	d_addr.s_addr = target;
	s_addr.s_addr = inet_addr(LOCAL_IP);
	
	pseudoh->s_addr = s_addr.s_addr;
	pseudoh->d_addr = d_addr.s_addr;
	pseudoh->protocol = IPPROTO_TCP;
	pseudoh->zero = 0;
	pseudoh->length = htons(sizeof(struct tcphdr));

	tcph->th_sport = htons(LOCAL_PORT);
	tcph->th_dport = htons(port);
	tcph->th_seq = htons(random()%time(NULL));
	tcph->th_ack = 0;
	tcph->th_off = 5;
	//tcph->res1 = 0;
    tcph->th_flags = !TH_FIN | !TH_FIN | !TH_SYN | !TH_RST|!TH_PUSH|!TH_ACK|!TH_URG|!TH_ECE|!TH_CWR;
	tcph->th_win = htons(1024);
	tcph->th_sum = (unsigned short)cksum_in((unsigned short *)tcph, (sizeof(struct tcphdr) + sizeof(struct pseudohdr)));

	iph->ip_hl = 5;
	iph->ip_v = 4;
	iph->ip_tos = 0;
	iph->ip_len = htons(tx_packet_size) - sizeof(struct pseudohdr);
	iph->ip_id = 0;
	iph->ip_off =0;
    iph->ip_ttl = IPDEFTTL;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_src = s_addr;
    iph->ip_dst = d_addr;
    iph->ip_sum = (unsigned short)cksum_in((unsigned short *)iph,sizeof(struct ip));

    	remote.sin_family = PF_INET;
    	remote.sin_addr = d_addr;
    	remote.sin_port =htons(port);
    	remote.sin_port =0;   



   	if(sendto(sd,tx_packet,(tx_packet_size - sizeof(struct pseudohdr)),0x0,(struct sockaddr*)&remote,sizeof(remote))<0)
    	{
        	printf("send error\n");
        	exit(-3);
    	}



    	printf("[tx] %u->%u  ",ntohs(tcph->th_sport),ntohs(tcph->th_dport));
    (tcph->th_flags == TH_FIN)?printf("U"):printf("-");
    (tcph->th_flags == 1)?printf("A"):printf("-");
    (tcph->th_flags == 1)?printf("P"):printf("-");
    (tcph->th_flags == 1)?printf("R"):printf("-");
    (tcph->th_flags == 1)?printf("S"):printf("-");
    (tcph->th_flags == 1)?printf("F"):printf("-");

    	while(recvfrom(sd,rx_packet,rx_packet_size,0x0,(struct sockaddr*)&local,&len)>0)
    	{


        	rx_iph  = (struct ip *)(rx_packet);
        	rx_tcph = (struct tcphdr*)(rx_packet + rx_iph->ip_hl *4);
       
        	if(rx_iph->ip_src.s_addr != iph->ip_dst.s_addr) continue;


        	if((ntohs(tcph->th_sport) == ntohs(rx_tcph->th_dport))&&(ntohs(tcph->th_dport) == ntohs(rx_tcph->th_sport)))
        	{
            		printf("[rx] %u->%u  ",ntohs(rx_tcph->th_sport),ntohs(rx_tcph->th_dport));


            		(rx_tcph->th_flags ==1)?printf("U"):printf("-");
            		(rx_tcph->th_flags ==1)?printf("A"):printf("-");
            		(rx_tcph->th_flags ==1)?printf("P"):printf("-");
            		(rx_tcph->th_flags ==1)?printf("R"):printf("-");
            		(rx_tcph->th_flags ==1)?printf("S"):printf("-");
            		(rx_tcph->th_flags ==1)?printf("F"):printf("-");


            		if(rx_tcph->th_flags == TH_SYN && rx_tcph->th_flags==TH_ACK){
                		serv = getservbyport(htons(port),"tcp");
                		printf("port[%d] open/%s \n",ntohs(rx_tcph->th_sport),serv->s_name);
            		}           
            		else if(rx_tcph->th_flags == TH_RST){
                		printf(" *\n");
            		}
            		else{
                		printf("protocol error\n");
                		exit(-1);
            		}
            		break;
        	}
    	}
    	close(sd);
}
unsigned short cksum_in(unsigned short *addr, int len)
{

    	unsigned long sum =0;
    	unsigned short answer =0;
    	unsigned short *w = addr;
    	int nleft = len;

    	while(nleft>1){
        	sum+=*w++;
    		if(sum & 0x80000000)
        		sum=(sum&0xffff)+(sum>>16);
        	nleft -=2;
    		
	}
    	if(nleft ==1){
        	*(unsigned char*)(&answer)=*(unsigned char *)w;
        	sum+= answer;
    	}
    	while(sum>>16)
        	sum = (sum & 0xffff)+(sum>>16);
    	return (sum==0xffff)?sum:~sum;  
}
