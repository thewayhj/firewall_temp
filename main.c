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


#include "read_packet.h"
#include "my_trace.h"
#include "firewall.h"


int print_menu(){
    
    char choice=0;
    
    puts("1. Firewall");
    puts("2. Traceroute");
    puts("3. ");
    puts("4. ");
    puts("0.exit");
    scanf(" %c",&choice);
    switch (choice) {
        case '0':
            exit(0);
            break;
        case '1':
            puts("1. Monitoring");
            puts("2. Block list");
            puts("3. Firewall Policy");
            puts("4.");
            puts("0. back");
            scanf(" %c",&choice);
            switch (choice) {
                case '0':
                case '1':
                    
                    return 121;
                    break;
                case '3':
                    puts("1. IP");
                    puts("2. PORT");
                    puts("3. ");
                    puts("0. Back");
                    scanf(" %c",&choice);
                    switch (choice) {
                        case '1':
                            return 131;
                            break;
                        case '2':
                            return 132;
                            break;
                        case '3':
                            return 133;
                            break;
                        default:
                            break;
                    }
                    
                    
                default:
                    break;
            }
            break;
        case '2':
            return 211;
            break;
            
        default:
            puts("wrong input");
            break;
    }
    
    return 0;
}

#define KEY 1234

int main(){
    
    pid_t pid;
    pid = fork();
    int shmid[3];
    
    
    firewall_load(shmid);
    // parent proccess
    if (pid > 0) {
        
        while(1){
            switch (print_menu()) {
                case 211:
                    my_trace("www.google.com");
                    break;
                case 131:
                    firewall_ip_policy_print(shmid[0]);
                    break;
                case 132:
                    firewall_port_policy_print(shmid[1]);
                    break;
                default:
                    break;
            }
            
        }
    }
    // child proccess
    else if(pid == 0) {
        
        read_packet();
        
    }
    else {
        
        
        
    }
    
    
}

