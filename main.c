//
//  main.c
//  firewall_temp
//
//  Created by ParkMinwoo on 2016. 12. 11..
//  Copyright © 2016년 ParkMinwoo. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <string.h>
#include "read_packet.h"
#include "read_packet_file.h"
#include "my_trace.h"
#include "firewall.h"



int print_menu(){
    
    char choice=0;
    puts("\n====== MENU =====");
    puts("| 1. Firewall   |");
    puts("| 2. Traceroute |");
    puts("| 3.            |");
    puts("| 4.            |");
    puts("| 0. exit       |");
    puts("=================");
    printf("Choice Number : ");
    scanf(" %c",&choice);
    switch (choice) {
        case '0':
            exit(0);
            break;
        case '1':
            puts("\n====== Firewall =======");
            puts("| 1. Read Packet File |");
            puts("| 2. Block list       |");
            puts("| 3. Firewall Policy  |");
            puts("| 4.                  |");
            puts("| 0. back             |");
            puts("=======================");
            printf("Choice Number : ");
            scanf(" %c",&choice);
            switch (choice) {
                case '0':
                    return print_menu();
                case '1':
                    return 11;
                    break;
                case '2':
                    return 12;
                    break;
                case '3':
                    puts("\n=== Firewall Policy ===");
                    puts("| 1. IP               |");
                    puts("| 2. PORT             |");
                    puts("| 3. FLAGS            |");
                    puts("| 0. Back             |");
                    puts("=======================");
                    printf("Choice Number : ");
                    scanf(" %c",&choice);
                    switch (choice) {
                        case '1':
                            puts("\n==== IP =====");
                            puts("| 1. ADD    |");
                            puts("| 2. DELETE |");
                            puts("| 3. DISPLAY|");
                            puts("| 0. MENU   |");
                            puts("=============");
                            printf("Choice Number : ");
                            scanf(" %c",&choice);
                            switch (choice) {
                                case '1':
                                    return 1311;
                                    break;
                                case '2':
                                    return 1312;
                                    break;
                                case '3':
                                    return 1313;
                                    break;
                                default:
                                    break;
                            }
                            break;
                        case '2':
                            puts("\n==== PORT =====");
                            puts("| 1. ADD      |");
                            puts("| 2. DELETE   |");
                            puts("| 3. DISPLAY  |");
                            puts("| 0. MENU     |");
                            puts("===============");
                            printf("Choice Number : ");
                            scanf(" %c",&choice);
                            switch (choice) {
                                case '1':
                                    return 1321;
                                    break;
                                case '2':
                                    return 1322;
                                    break;
                                case '3':
                                    return 1233;
                                    break;
                                default:
                                    break;
                            }
                            
                            break;
                        case '3':
                            puts("\n===== FLAGS ======");
                            puts("| 1. ADD         |");
                            puts("| 2. DELETE      |");
                            puts("| 3. LOOK        |");
                            puts("| 0. MENU        |");
                            puts("==================");
                            printf("Choice Number : ");
                            scanf(" %c",&choice);
                            switch (choice) {
                                case '1':
                                    return 1331;
                                    break;
                                case '2':
                                    return 1332;
                                    break;
                                case '3':
                                    return 1333;
                                    break;
                                default:
                                    break;
                            }
                            break;
                        default:
                            break;
                    }
                    break;
            }
            break;
        case '2':
            puts("\n====== Traceroute =======");
            puts("| 1. Input            |");
            puts("| 2. Packet IP list   |");
            puts("| 3. Block IP list    |");
            puts("| 4. History          |");
            puts("| 0. back             |");
            puts("=======================");
            scanf(" %c",&choice);
            switch (choice) {
                case '1':
                    return 21;
                    break;
                case '2':
                    return 22;
                    break;
                case '3':
                    return 23;
                    break;
                default:
                    break;
            }// block list
            break;
            
            
        case '3':
            
            break;
        default:
            break;
    }
    return 0;
}
int main(){
    
    int count=0;
    char input[BUFSIZ];
    int choice;
    pid_t pid;
    pid = fork();
    int shmid[3];
    struct packet_st *pt;
    pt = (struct packet_st *)malloc(sizeof(struct packet_st)*10);
    
    firewall_load(shmid);
    // parent proccess
    if (pid > 0) {
        
        while(1){
            switch (print_menu()) {
                case 11:
                    read_packet_file(shmid);
                    break;
                case 12:
                    firewall_block_list_print();
                    break;
                case 21:
                    scanf("%s",input);
                    my_trace(input);
                    break;
                case 22:
                    
                    break;
                    
                case 23:
                    count=firewall_block_list(pt);
                    while(i<count) {
                     
                        printf("%d)%s\n",i+1,inet_ntoa((pt+i)->rx_iph.ip_dst));
                        i++;
                    }
                    scanf("%d",&choice);
                    
                    my_trace(inet_ntoa((pt+i-1)->rx_iph.ip_dst));
                    break;
                case 1311:
                    firewall_ip_policy_add(shmid[0]);
                    firewall_ip_policy_write(shmid[0]);
                    break;
                case 1312:
                    firewall_ip_policy_print(shmid[0]);
                    firewall_ip_policy_del(shmid[0]);
                    firewall_ip_policy_write(shmid[0]);
                    break;
                case 1313:
                    firewall_ip_policy_print(shmid[0]);
                    break;
                case 1321:
                    firewall_port_policy_add(shmid[1]);
                    firewall_port_policy_write(shmid[1]);
                case 1322:
                    firewall_port_policy_print(shmid[1]);
                case 1323:
                    firewall_port_policy_print(shmid[1]);
                    firewall_port_policy_del(shmid[1]);
                    firewall_port_policy_write(shmid[1]);
                    break;
                default:
                    break;
            }
            
        }
    }
    // child proccess
    else if(pid == 0) {
        
        // read_packet();
        
    }
    else {
        
        
        
    }
    
    
}

