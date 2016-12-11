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


#ifndef firewall_h
#define firewall_h


#endif /* firewall_h */

struct fire_ip{
    u_long addr;
    int domain;
};

struct fire_port{
    unsigned int s_port;
    unsigned int e_port;
};
int firewall_ip_policy_load(int shmid);
int firewall_port_policy_load(int shmid);

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
    
    if((fp = fopen("/Users/Minwoo/Documents/workspace/git/firewall_temp/firewall_policy_ip_list","r"))==NULL){
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
        fip.addr = inet_addr(temp);
        
        *(shmaddr+i++) = fip;
        
    }
    struct fire_ip fip;
    
    fip.domain = -1;
    fip.addr = -1;
    
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
    while((shmaddr+i)->addr != -1) {
        printf("%lu %d\n",(shmaddr+i)->addr,(shmaddr+i)->domain);
        i++;
    }
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
    
    if((fp = fopen("/Users/Minwoo/Documents/workspace/git/firewall_temp/firewall_policy_port_list","r"))==NULL){
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
