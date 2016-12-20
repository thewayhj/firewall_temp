#ifndef read_packet_file_h
#define read_packet_file_h

#ifdef HEE
#define PATH "/home/hello/lsp/network/term/firewall_temp/"
#endif
#define FILE_NAME PATH"sample.txt"
#define PACKET_LOG_FILE_NAME PATH"packet_log"
#include <netinet/ip.h>
#include <time.h>
struct packet_st{
    struct ip rx_iph;
    struct tcphdr rx_tcph;
};



#include <netinet/ip.h>
#include <stdlib.h>

void packet_log_write(struct packet_st *pt){
    struct tm *t;
    time_t timer;
    timer = time(NULL);
    t = localtime(&timer);
    
    FILE *fp;
    fp = fopen(PACKET_LOG_FILE_NAME,"a");
    
    
    fprintf(fp,"%d.%d.%d %d:%d:%d %s %d\n",t->tm_year+1900,t->tm_mon+1,t->tm_mday,t->tm_hour,t->tm_min,t->tm_sec,inet_ntoa(pt->rx_iph.ip_src),pt->rx_tcph.th_dport);
    
    fclose(fp);
}

void read_packet_file(int *shmid){
    FILE *fp;
    char packet[BUFSIZ];
    char *temp;
    char temp2[BUFSIZ];
    fp = fopen(FILE_NAME,"r");
    int k=0;
    while(fgets(packet,BUFSIZ,fp)!=NULL){
        
        int i=0;
        int j=20;
        struct ip rx_iph;
        struct tcphdr rx_tcph;
        
        struct packet_st *pt_st;
        
        pt_st = (struct packet_st *)malloc(sizeof(struct packet_st)*10);
        
        int headerlength;
        atoi(strtok(packet,"|"));
        while(i<4){
            switch (i) {
                case 0: // ethernet
                    strtok(NULL,"|");
                    strtok(NULL,"|");
                    strtok(NULL,"|");
                    strtok(NULL,"|");
                    strtok(NULL,"|");
                    
                    strtok(NULL,"|");
                    strtok(NULL,"|");
                    strtok(NULL,"|");
                    strtok(NULL,"|");
                    strtok(NULL,"|");
                    strtok(NULL,"|");
                    
                    strtok(NULL,"|");
                    strtok(NULL,"|");
                    break;
                case 1: // ip header
                    
                    temp = strtok(NULL,"|");
                    
                    rx_iph.ip_v = (int)strtol(temp,NULL,16)>>4;
                    rx_iph.ip_hl = (int)strtol(temp,NULL,16)&15;
                    
                    temp = strtok(NULL,"|");
                    rx_iph.ip_tos = (int)strtol(temp,NULL,16);
                    
                    temp = strtok(NULL,"|");
                    strcpy(temp2,temp);
                    temp = strtok(NULL,"|");
                    strcat(temp2,temp);
                    rx_iph.ip_len = (int)strtol(temp2,NULL,16);
                    
                    temp = strtok(NULL,"|");
                    strcpy(temp2,temp);
                    temp = strtok(NULL,"|");
                    strcat(temp2,temp);
                    rx_iph.ip_id = (int)strtol(temp2,NULL,16);
                    
                    temp = strtok(NULL,"|");
                    temp = strtok(NULL,"|");
                    rx_iph.ip_off = 1;
                    
                    temp = strtok(NULL,"|");
                    rx_iph.ip_ttl = (int)strtol(temp,NULL,16);
                    temp = strtok(NULL,"|");
                    rx_iph.ip_p = (int)strtol(temp,NULL,16);
                    
                    temp = strtok(NULL,"|");
                    strcpy(temp2,temp);
                    temp = strtok(NULL,"|");
                    strcat(temp2,temp);
                    rx_iph.ip_sum = (int)strtol(temp2,NULL,16);
                    
                    temp = strtok(NULL,"|");
                    strcpy(temp2,temp);
                    temp = strtok(NULL,"|");
                    strcat(temp2,temp);
                    temp = strtok(NULL,"|");
                    strcat(temp2,temp);
                    temp = strtok(NULL,"|");
                    strcat(temp2,temp);
                    rx_iph.ip_src.s_addr = htonl((int)strtol(temp2,NULL,16));
                    
                    temp = strtok(NULL,"|");
                    strcpy(temp2,temp);
                    temp = strtok(NULL,"|");
                    strcat(temp2,temp);
                    temp = strtok(NULL,"|");
                    strcat(temp2,temp);
                    temp = strtok(NULL,"|");
                    strcat(temp2,temp);

                    rx_iph.ip_dst.s_addr = htonl((int)strtol(temp2,NULL,16));
                    
                    while(j < rx_iph.ip_hl*4){
                        strtok(NULL,"|");
                        j++;
                    }
                    print_ip(&rx_iph);
                    break;
                case 2: // tcp header
                    temp = strtok(NULL,"|");
                    strcpy(temp2,temp);
                    temp = strtok(NULL,"|");
                    strcat(temp2,temp);
                    rx_tcph.th_sport = (int)strtol(temp2,NULL,16);
                    temp = strtok(NULL,"|");
                    strcpy(temp2,temp);
                    temp = strtok(NULL,"|");
                    strcat(temp2,temp);
                    rx_tcph.th_dport = (int)strtol(temp2,NULL,16);
                    
                    temp = strtok(NULL,"|");
                    strcpy(temp2,temp);
                    temp = strtok(NULL,"|");
                    strcat(temp2,temp);
                    temp = strtok(NULL,"|");
                    strcat(temp2,temp);
                    temp = strtok(NULL,"|");
                    strcat(temp2,temp);
                    rx_tcph.th_seq = (int)strtol(temp2,NULL,16);
                    
                    temp = strtok(NULL,"|");
                    strcpy(temp2,temp);
                    temp = strtok(NULL,"|");
                    strcat(temp2,temp);
                    temp = strtok(NULL,"|");
                    strcat(temp2,temp);
                    temp = strtok(NULL,"|");
                    strcat(temp2,temp);
                    rx_tcph.th_ack = (int)strtol(temp2,NULL,16);
                    
                    temp = strtok(NULL,"|");
                    strcpy(temp2,temp);
                    temp = strtok(NULL,"|");
                    strcat(temp2,temp);
                    
                    headerlength = ((int)strtol(temp2,NULL,16)>>12)&15;
                    
                    rx_tcph.th_flags = TH_URG&(int)strtol(temp2,NULL,16);
                    rx_tcph.th_flags+= TH_ACK&(int)strtol(temp2,NULL,16);
                    rx_tcph.th_flags+= TH_PUSH&(int)strtol(temp2,NULL,16);
                    rx_tcph.th_flags+= TH_RST&(int)strtol(temp2,NULL,16);
                    rx_tcph.th_flags+= TH_SYN&(int)strtol(temp2,NULL,16);
                    rx_tcph.th_flags+= TH_FIN&(int)strtol(temp2,NULL,16);
                    
                    temp = strtok(NULL,"|");
                    strcpy(temp2,temp);
                    temp = strtok(NULL,"|");
                    strcat(temp2,temp);
                    rx_tcph.th_win = (int)strtol(temp2,NULL,16);
                    
                    temp = strtok(NULL,"|");
                    strcpy(temp2,temp);
                    temp = strtok(NULL,"|");
                    strcat(temp2,temp);
                    rx_tcph.th_sum = (int)strtol(temp2,NULL,16);
                    
                    temp = strtok(NULL,"|");
                    strcpy(temp2,temp);
                    temp = strtok(NULL,"|");
                    strcat(temp2,temp);
                    rx_tcph.th_urp = (int)strtol(temp2,NULL,16);
                    
                    j=20;
                    strcpy(temp2,"");
                    while(j < headerlength*4){
                        strcat(temp2,strtok(NULL,"|"));
                        j++;
                    }
                    print_tcp(&rx_tcph);
                    break;
                case 3: // data
                    strcpy(temp2,"");
                    while((temp = strtok(NULL,"|"))!=NULL){
                        strcat(temp2,temp);
                    }
                    puts(temp2);
                    break;
                }
            i++;
        }
        
        (pt_st+k)->rx_iph = rx_iph;
        (pt_st+k)->rx_tcph = rx_tcph;
        packet_log_write(pt_st+k);
        int t = firewall(pt_st+k, shmid);
        
        if(t&1){            
            printf("IP block\n\n");
        }
        if(t&2) {            
            printf("PORT block\n");
        }
        if(t&4) {            
            printf("FLAGS block\n");
        }
	printf("\n");
        k++;       
    }
}
#endif /* read_packet_file_h */
