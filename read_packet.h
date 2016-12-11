#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <netinet/in.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>

void print_ip(struct ip *);
void print_tcp(struct tcphdr *);

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
	printf("[IP HEADER] VER : %d HL : %2u Protocol : %3u",iph->ip_v, iph->ip_hl, iph->ip_p);
	printf("SRC IP: %15s ", inet_ntoa(*(struct in_addr *)&iph->ip_src));
	printf("DEST IP: %15s \n", inet_ntoa(*(struct in_addr *)&iph->ip_dst));
}

void print_tcp(struct tcphdr *tcph){
	printf("[TCP HEADER] src port: %5u dest port : %5u ",ntohs(tcph->th_sport), ntohs(tcph->th_dport));

	(tcph->th_flags == TH_FIN)?printf("U"):printf("-");
	(tcph->th_flags == 1)?printf("A"):printf("-");
	(tcph->th_flags == 1)?printf("P"):printf("-");
	(tcph->th_flags == 1)?printf("R"):printf("-");
	(tcph->th_flags == 1)?printf("S"):printf("-");
	(tcph->th_flags == 1)?printf("F"):printf("-");
	printf("\n\n");
}
