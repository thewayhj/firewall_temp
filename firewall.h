//
//  firewall.h
//  firewall_temp
//
//  Created by ParkMinwoo on 2016. 12. 11..
//  Copyright © 2016년 ParkMinwoo. All rights reserved.
//

#include <sys/ipc.h>
#include <sys/shm.h>

#define SHMID_FAIL "shmid failed"
#define SHMAT_FAIL "shmat failed"
#define SHMDT_FAIL "shmdt failed"

#ifdef HEE
#define PATH "/home/hello/lsp/network/term/firewall_temp/"
#else
#define PATH "/Users/Minwoo/Documents/workspace/git/firewall_temp/"
#endif
#define IP_POLICY_FILE_NAME PATH"firewall_policy_ip_list"
#define PORT_POLICY_FILE_NAME PATH"firewall_policy_port_list"
#define FLAGS_POLICY_FILE_NAME PATH"firewall_policy_flag_list"
#define BLOCK_LOG_FILE_NAME PATH"block_packet"
#ifndef firewall_h
#define firewall_h


#endif /* firewall_h */

struct fire_ip{
    struct in_addr addr;
    int domain;
};

struct fire_port{
    unsigned int s_port;
    unsigned int e_port;
};
int firewall_ip_policy_load(int);
int firewall_port_policy_load(int);
void firewall_ip_policy_write(int);
void firewall_port_policy_write(int);

void firewall_load(int* shmid){
    
    shmid[0] = firewall_ip_policy_load(7);
    shmid[1] = firewall_port_policy_load(8);
    shmid[2] = firewall_ip_policy_load(9);

}
int firewall_ip_policy_load(int key_num){
    FILE *fp;
    char temp[BUFSIZ];
    int domain;
    int i=0;
    int shm_id;
    struct fire_ip *shmaddr;
    
    if((fp = fopen(IP_POLICY_FILE_NAME,"r"))==NULL){
        perror("error");
        exit(1);
    }
    if ( -1 == ( shm_id = shmget( (key_t)key_num, sizeof(struct fire_ip) * 10, IPC_CREAT|0666)))
    {
        printf( "공유 메모리 생성 실패\n");
        return -1;
    }
    if((shmaddr=shmat(shm_id, (void *)0, 0)) == (void *)-1) {
        perror(SHMAT_FAIL);
        exit(1);
    }
    while(fscanf(fp, "%s %d",temp, &domain) != EOF){
        
        struct fire_ip fip;
        
        fip.domain = domain;
        fip.addr.s_addr = inet_addr(temp);
        
        *(shmaddr+i++) = fip;
        
    }
    struct fire_ip fip;
    
    fip.domain = -1;
    fip.addr.s_addr = -1;
    
    *(shmaddr+i++) = fip;
    if(shmdt(shmaddr) == -1) {
        perror(SHMDT_FAIL);
        exit(1);
    }
    fclose(fp);
    return shm_id;
}
void firewall_ip_policy_print(int shm_id){
    struct fire_ip *shmaddr;
    int i=0;
    if((shmaddr=shmat(shm_id, (void *)0, 0)) == (void *)-1) {
        perror(SHMAT_FAIL);
        exit(1);
    }
    while((shmaddr+i)->addr.s_addr != -1) {
        printf("%d.%u %d\n",i+1,(shmaddr+i)->addr.s_addr,(shmaddr+i)->domain);
        i++;
    }
    if(shmdt(shmaddr) == -1) {
        perror(SHMDT_FAIL);
        exit(1);
    }
}
void firewall_ip_policy_add(int shm_id){
    struct fire_ip *shmaddr;
    int i=0;
    char input[BUFSIZ];
    int temp;
    
    if((shmaddr=shmat(shm_id, (void *)0, 0)) == (void *)-1) {
        perror(SHMAT_FAIL);
        exit(1);
    }
    while((shmaddr+i)->addr.s_addr != -1) {
        i++;
    }
    
    puts("input ip");
    scanf("%s",input);
    puts("input domain");
    scanf("%d",&temp);
    
    (shmaddr+i)->addr.s_addr = inet_addr(input);
    (shmaddr+i)->domain = temp;
    i++;
    (shmaddr+i)->addr.s_addr = -1;
    (shmaddr+i)->domain = -1;
    
    if(shmdt(shmaddr) == -1) {
        perror(SHMDT_FAIL);
        exit(1);
    }
}
void firewall_ip_policy_del(int shm_id){
    struct fire_ip *shmaddr;
    int num;
    if((shmaddr=shmat(shm_id, (void *)0, 0)) == (void *)-1) {
        perror(SHMAT_FAIL);
        exit(1);
    }
    scanf("%d",&num);
    do {
        *(shmaddr+num-1) = *(shmaddr+num);
    }
    while((shmaddr+num++)->addr.s_addr != -1);
    
    if(shmdt(shmaddr) == -1) {
        perror(SHMDT_FAIL);
        exit(1);
    }
}
int firewall_port_policy_load(int key_num){
    FILE *fp;
    int temp[2];
    int i=0;
    int shm_id;
    struct fire_port *shmaddr;
    
    if((fp = fopen(PORT_POLICY_FILE_NAME,"r"))==NULL){
        perror("error");
        exit(1);
    }
    if ( -1 == ( shm_id = shmget( (key_t)key_num, sizeof(struct fire_ip) * 10, IPC_CREAT|0666)))
    {
        printf( "공유 메모리 생성 실패\n");
        return -1;
    }
    if((shmaddr=shmat(shm_id, (void *)0, 0)) == (void *)-1) {
        perror(SHMAT_FAIL);
        exit(1);
    }
    while(fscanf(fp, "%d %d",&temp[0], &temp[1]) != EOF){
        
        struct fire_port fip;
        
        fip.s_port = temp[0];
        fip.e_port = temp[1];
        
        *(shmaddr+i++) = fip;
        
    }
    struct fire_port fip;
    fip.s_port = -1;
    fip.e_port = -1;
    *(shmaddr+i) = fip;
    if(shmdt(shmaddr) == -1) {
        perror(SHMDT_FAIL);
        exit(1);
    }
    fclose(fp);
    return shm_id;
}
void firewall_policy_write(int *shmid){
    firewall_ip_policy_write(shmid[0]);
    firewall_port_policy_write(shmid[1]);
    
}
void firewall_ip_policy_write(int shm_id){
    FILE *fp;
    fp = fopen(IP_POLICY_FILE_NAME,"w");
    struct fire_ip *shmaddr;
    if((shmaddr=shmat(shm_id, (void *)0, 0)) == (void *)-1) {
        perror(SHMAT_FAIL);
        exit(1);
    }
    while((shmaddr+i)->addr.s_addr != -1) {
        fprintf(fp,"%lu %d\n",(shmaddr+i)->addr,(shmaddr+i)->domain);
        i++;
    }
    if(shmdt(shmaddr) == -1) {
        perror(SHMDT_FAIL);
        exit(1);
    }
}
void firewall_port_policy_write(int shm_id){
    FILE *fp;
    fp = fopen(PORT_POLICY_FILE_NAME,"w");
    struct fire_port *shmaddr;
    if((shmaddr=shmat(shm_id, (void *)0, 0)) == (void *)-1) {
        perror(SHMAT_FAIL);
        exit(1);
    }
    while((shmaddr+i)->s_port != -1) {
        fprintf(fp,"%d %d\n",(shmaddr+i)->s_port,(shmaddr+i)->e_port);
        i++;
    }
    if(shmdt(shmaddr) == -1) {
        perror(SHMDT_FAIL);
        exit(1);
    }
}
void fiewall_port_policy_get(int shmid){
    struct fire_port *shmaddr;
    if((shmaddr=shmat(shmid, (void *)0, 0)) == (void *)-1) {
        perror(SHMAT_FAIL);
        exit(1);
    }
    if(shmdt(shmaddr) == -1) {
        perror(SHMDT_FAIL);
        exit(1);
    }
}

void firewall_port_policy_add(int shm_id){
    struct fire_port *shmaddr;
    int i=0;
    char input[BUFSIZ];
    int temp[2];
    
    if((shmaddr=shmat(shm_id, (void *)0, 0)) == (void *)-1) {
        perror(SHMAT_FAIL);
        exit(1);
    }
    while((shmaddr+i)->s_port != -1) {
        i++;
    }
    
    puts("input port 1");
    scanf("%d",&temp[0]);
    puts("input port 2");
    scanf("%d",&temp[1]);
    
    (shmaddr+i)->s_port = temp[0];
    (shmaddr+i)->e_port = temp[1];
    i++;
    (shmaddr+i)->s_port = -1;
    (shmaddr+i)->e_port = -1;
    
    if(shmdt(shmaddr) == -1) {
        perror(SHMDT_FAIL);
        exit(1);
    }
}
void firewall_port_policy_del(int shm_id){
    struct fire_port *shmaddr;
    int num;
    if((shmaddr=shmat(shm_id, (void *)0, 0)) == (void *)-1) {
        perror(SHMAT_FAIL);
        exit(1);
    }
    scanf("%d",&num);
    do {
        *(shmaddr+num-1) = *(shmaddr+num);
    }
    while((shmaddr+num++)->s_port != -1);
    
    if(shmdt(shmaddr) == -1) {
        perror(SHMDT_FAIL);
        exit(1);
    }
}
void firewall_port_policy_print(int shm_id){
    struct fire_port *shmaddr;
    int i=0;
    if((shmaddr=shmat(shm_id, (void *)0, 0)) == (void *)-1) {
        perror(SHMAT_FAIL);
        exit(1);
    }
    while((shmaddr+i)->s_port != -1){
        printf("%d %d\n",(shmaddr+i)->s_port,(shmaddr+i)->e_port);
        i++;
    }
    if(shmdt(shmaddr) == -1) {
        perror(SHMDT_FAIL);
        exit(1);
    }
}

int firewall_ip(struct ip *header,int shmid){
    
    int i=0;
    struct fire_ip *shmaddr;
    if((shmaddr=shmat(shmid, (void *)0, 0)) == (void *)-1) {
        perror(SHMAT_FAIL);
        exit(1);
    }
    while((shmaddr+i)->domain != -1) {
        puts(inet_ntoa((shmaddr+i)->addr));
        puts(inet_ntoa(header->ip_src));
        if(header->ip_src.s_addr>>(32-(shmaddr+i)->domain) == (shmaddr+i)->addr.s_addr>>(32-(shmaddr+i)->domain)){
            
            return 1;
        }
        i++;
    }
    if(shmdt(shmaddr) == -1) {
        perror(SHMDT_FAIL);
        exit(1);
    }
    return 0;

    return 0;
}
int firewall_tcp(struct tcphdr *header,int shmid){
    int i=0;
    
    struct fire_port *shmaddr;
    if((shmaddr=shmat(shmid, (void *)0, 0)) == (void *)-1) {
        perror(SHMAT_FAIL);
        exit(1);
    }
    while((shmaddr+i)->s_port != -1) {
        if((shmaddr+i)->s_port<=header->th_dport && header->th_dport <= (shmaddr+i)->e_port){
            
            return 2;
        }
        i++;
    }
    if(shmdt(shmaddr) == -1) {
        perror(SHMDT_FAIL);
        exit(1);
    }
    return 0;
}
int firewall_flags(struct tcphdr *tcph,int shmid){
	switch(tcph->th_flags){
		case TH_SYN:
		case TH_SYN + TH_ACK:
		case TH_ACK:
		case TH_FIN:
		case TH_FIN + TH_ACK:
		case TH_RST:
			return 0;
		default:
			return 4;
			
	}
}
int firewall(struct packet_st *pt,int *shmid){
    time_t timer;
    struct tm *t;
    
    timer = time(NULL);
    
    t = localtime(&timer);
    
    FILE *fp;
    fp = fopen(BLOCK_LOG_FILE_NAME,"a");
    int block=0;
    
    block+=firewall_ip(&pt->rx_iph,shmid[0]);
    block+=firewall_tcp(&pt->rx_tcph,shmid[1]);
    block+=firewall_flags(&pt->rx_tcph,shmid[2]);
    
    if(block != 0) {
        fprintf(fp,"%d.%d.%d %d:%d:%d\t%s %d\n",t->tm_year+1900,t->tm_mon,t->tm_mday,t->tm_hour,t->tm_min,t->tm_sec,inet_ntoa(pt->rx_iph.ip_src),pt->rx_tcph.th_dport);
        
    }
    fclose(fp);
    return block;
}
int firewall_block_list(struct packet_st *pt){
    FILE *fp;
    fp = fopen(BLOCK_LOG_FILE_NAME,"r");
    char temp[BUFSIZ];
    char temp2[BUFSIZ];
    char temp3[BUFSIZ];
    int t;
    int i=0;
    while(fscanf(fp,"%s %s %s %hd\n",temp3,temp2,temp,&(pt+i)->rx_tcph.th_dport)!=EOF){
        (pt+i)->rx_iph.ip_src.s_addr = inet_addr(temp);
        i++;
    }
    fclose(fp);
    return i;
}
void firewall_block_list_print() {
    FILE *fp;
    char temp[BUFSIZ];
    fp = fopen(BLOCK_LOG_FILE_NAME,"r");
    while(fgets(temp,BUFSIZ,fp)!=NULL){
        temp[strlen(temp)-1] = '\0';
        puts(temp);
    }
    fclose(fp);
    
    
}

