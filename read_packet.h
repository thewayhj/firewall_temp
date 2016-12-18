#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <netinet/in.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>

void print_ip(struct ip *); //ip header
void print_tcp(struct tcphdr *); // tcp header

int read_packet(){
	int sd;
	int len;

	int rx_packet_size = sizeof(struct ip) + sizeof(struct tcphdr);
	char *rx_packet = malloc(rx_packet_size);

	struct tcphdr *rx_tcph;
	struct ip *rx_iph;

	struct in_addr s_addr, d_addr;
	struct sockaddr_in local, remote;

	struct servent *serv;

	if((sd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) <0){
		printf("socket open error\n");
		exit(-1);
	}
	while(1){
		bzero(rx_packet, rx_packet_size);
		
		len = sizeof(local);
		if(recvfrom(sd,rx_packet,rx_packet_size,0x0,(struct sockaddr *)&local, &len)<0){
			printf("recvfrom error\n");
			exit(-2);
		}

		rx_iph = (struct ip *)(rx_packet);
		rx_tcph = (struct tcphdr *)(rx_packet + rx_iph->ip_hl * 4);
        
		print_ip(rx_iph);
		print_tcp(rx_tcph);
	}
	close(sd);
}

void print_ip(struct ip *iph){
    puts("[IP HEADER]");
    printf("VER : %d HL : %u TOS : %d TOL: %d \n",iph->ip_v, iph->ip_hl,iph->ip_tos, iph->ip_len);
    printf("ID : %d TTL: %d Protocol : %u CheckSum = %d\n",iph->ip_id, iph->ip_ttl,iph->ip_sum,iph->ip_p);
	printf("SRC IP: %s ", inet_ntoa(iph->ip_src));
	printf("DST IP: %s \n", inet_ntoa(iph->ip_dst));    
}

void print_tcp(struct tcphdr *tcph){
    puts("[TCP HEADER]");
	printf("SRC PORT: %d DST PORT : %d\n",tcph->th_sport, tcph->th_dport);
	printf("Flags : ");
	(tcph->th_flags&TH_URG)?printf("U"):printf("-");
	(tcph->th_flags&TH_ACK)?printf("A"):printf("-");
	(tcph->th_flags&TH_PUSH)?printf("P"):printf("-");
	(tcph->th_flags&TH_RST)?printf("R"):printf("-");
	(tcph->th_flags&TH_SYN)?printf("S"):printf("-");
	(tcph->th_flags&TH_FIN)?printf("F"):printf("-");
	printf("\n");
	printf("Data : ");
}
