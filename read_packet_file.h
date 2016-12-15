//
//  read_packet_file.h
//  firewall_temp
//
//  Created by ParkMinwoo on 2016. 12. 15..
//  Copyright © 2016년 ParkMinwoo. All rights reserved.
//

#ifndef read_packet_file_h
#define read_packet_file_h
#define PATH "/Users/Minwoo/Documents/workspace/git/firewall_temp/"
#define FILE_NAME PATH"sample.txt"

#include <netinet/ip.h>

void read_packet_file(){
    FILE *fp;
    char packet[BUFSIZ];
    char *temp;
    char temp2[BUFSIZ];
    fp = fopen(FILE_NAME,"r");
    while(fgets(packet,BUFSIZ,fp)){
        
        int i=0;
        int j=20;
        struct ip rx_iph;
        struct tcphdr rx_tcph;
        int headerlength;
        atoi(strtok(packet,"|"));
        while(i<4){
            switch (i) {
                case 0:
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
                case 1:
                    
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
                    rx_iph.ip_src.s_addr = inet_addr(<#const char *#>)(int)strtol(temp2,NULL,16);
                    
                    temp = strtok(NULL,"|");
                    strcpy(temp2,temp);
                    temp = strtok(NULL,"|");
                    strcat(temp2,temp);
                    temp = strtok(NULL,"|");
                    strcat(temp2,temp);
                    temp = strtok(NULL,"|");
                    strcat(temp2,temp);
                    rx_iph.ip_dst.s_addr = (int)strtol(temp2,NULL,16);
                    
                    while(j < rx_iph.ip_hl*4){
                        strtok(NULL,"|");
                        j++;
                    }
                    print_ip(&rx_iph);
                    break;
                case 2:
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
                case 3:
                    strcpy(temp2,"");
                    while((temp = strtok(NULL,"|"))!=NULL){
                        strcat(temp2,temp);
                    }
                    puts(temp2);
                    break;
                }
            i++;
        }
    }
}
#endif /* read_packet_file_h */
