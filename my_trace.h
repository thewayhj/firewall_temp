#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <pthread.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <time.h>
#include <netdb.h>

void sig_alrm(int);
void send_msg(void);
void handlePing(void);
time_t current_time;
unsigned short cksum_in(unsigned short *, int);
void tv_sub(struct timeval *, struct timeval *);

struct in_addr addr;
struct timeval *tvsend, tvrecv;
char rbuf[1500];
char error_1[] =" usage : ping domain_name";
char error_2[] =" Wrong Addrress";


int sd;
int i=0;
pid_t pid;

int isWait = 0;
int nsent = 0;
int ttl = 1;
int miss = 0;
int hops = 30;
FILE *LOG;
struct sockaddr_in sasend;
struct sockaddr_in sarecv;
struct hostent *host;
int salen;
int end = 0;
void my_trace(char *argv) { // traceroute
	ttl=1;
	miss=0;
	time(&current_time);
	
	
	bzero((char *)&sasend, sizeof(sasend));
	sasend.sin_family = AF_INET;
    if(INADDR_NONE == inet_addr(argv)){
        if((host = gethostbyname(argv)) == NULL){
            printf("%s\n",error_2);
            exit(-1);
        }
        else{
            memcpy(&addr.s_addr,host->h_addr_list[0],4);
            sasend.sin_addr.s_addr = inet_addr(inet_ntoa(addr));
        }
    }
    else
         sasend.sin_addr.s_addr = inet_addr(argv);
	
	gettimeofday((struct timeval *)tvsend, NULL);
	
	salen = sizeof(sasend);
	pid = getpid() & 0xffff;      //ICMP ID (16 bits)
	
	printf("Dest : %s\n",inet_ntoa(sasend.sin_addr));
	printf(" Hops\t   Address\t   rtt\n");
	handlePing();
	
}

void handlePing(void) {
	int len, hlen, icmplen;
	struct timeval tval;

	fd_set readfd;
	struct ip *iph;
	struct icmp *icmp;

	double rtt;

	signal(SIGALRM, sig_alrm);
	if((sd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
		printf("socket open error\n");
		exit(-1);
    	}
	
	while(1){
		printf("%3d:",ttl); // Hops number
		send_msg(); // ip
		alarm(3); // alarm 3
		isWait = 1;
		if((len = recvfrom(sd, rbuf, sizeof(rbuf), 0, NULL, NULL)) < 0) {
			printf("read error\n");
			exit(-1);
		}
		isWait = 0;
		iph = (struct ip *)rbuf;
		hlen = iph->ip_hl *4;
		icmp = (struct icmp *)(rbuf + hlen);
		icmplen = len - hlen;		
		if(iph->ip_p != IPPROTO_ICMP)
			return;
		gettimeofday(&tvrecv, NULL);
		//tvsend = (struct timeval *)icmp->icmp_data;
		tv_sub(&tvrecv, tvsend);
		rtt = tvrecv.tv_sec * 1000.0 + tvrecv.tv_usec / 1000.0; // rtt
		printf("\t%s\t%.3f ms\n",inet_ntoa(*(struct in_addr *)&iph->ip_src), rtt);
		//printf("%d\n",ttl);
		if(iph->ip_src.s_addr == sasend.sin_addr.s_addr||ttl>hops){
			if(ttl>hops){
				printf("   Too many hops\n");
				sprintf(rbuf," Resume : hops %d back %d\n",ttl-1,ttl-miss-1);
				printf("%s",rbuf);
			}	
			//sprintf(rbuf," Resume : hops %d back %d\n",ttl-1,ttl-miss-1);
			//printf("%s",rbuf);
            		end = 1;
           		break;
		}
	}
	signal(SIGALRM,SIG_IGN); // disregard signal
}
void sig_alrm(int signo) {
	printf("\tNo reply\n");
	if(ttl>hops){
		printf("   Too many hops\n");
		sprintf(rbuf," Resume : hops %d back %d\n",ttl-1,ttl-miss-2);
		printf("%s",rbuf);
		puts("Too many hops Exit Program");
		exit(0);
	}
	printf("%3d:",ttl);
	miss ++;
    send_msg();
    if(end == 0)
        alarm(5);
	return;
}
void send_msg(void) {
	int len;
	struct icmp *icmp;
	char sendbuf[1500];
	int datalen = 56;
	icmp = (struct icmp *)sendbuf;
	icmp->icmp_type = 8;
	icmp->icmp_code = 0;
	icmp->icmp_id = pid;
	icmp->icmp_seq = nsent++;
	memset(icmp->icmp_data, 0xa5, datalen);
	gettimeofday((struct timeval *)icmp->icmp_data, NULL);
    tvsend = (struct timeval *)icmp->icmp_data;
	len = 8 + datalen;
	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = cksum_in((unsigned short *)icmp, len);
	setsockopt(sd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
	ttl++;
	sendto(sd, sendbuf, len, 0, (struct sockaddr *)&sasend, salen);
}
void tv_sub(struct timeval *out, struct timeval *in) {
   if((out->tv_usec -= in->tv_usec) < 0) {
      --out->tv_sec;
      out->tv_usec += 1000000;
   }
   out->tv_sec -= in->tv_sec;
}
unsigned short cksum_in(unsigned short *addr, int len) {
   unsigned long sum = 0;
   unsigned short answer = 0;
   unsigned short *w = addr;
   int nleft = len;

   while(nleft > 1) {
      sum += *w++;
      if(sum & 0x80000000)
         sum = (sum & 0xffff) + (sum >> 16);
      nleft -= 2;
   }
   if(nleft == 1) {
      *(unsigned char *)(&answer) = *(unsigned char *)w;
      sum += answer;
   }
   while(sum >> 16)
      sum = (sum & 0xffff) + (sum >> 16);
   return (sum==0xffff)?sum:~sum;
}
