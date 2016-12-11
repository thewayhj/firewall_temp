//
//  main.c
//  firewall_temp
//
//  Created by ParkMinwoo on 2016. 12. 11..
//  Copyright © 2016년 ParkMinwoo. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>

#include "read_packet.h"
#include "my_trace.h"


void print_menu(){
    
    puts("1. Monitoring");
    puts("2. Traceroute");
    puts("3. ");
    puts("4. ");
    puts("0.exit");
    
}

int main(){
    
    char choice=0;
    pid_t pid;
    pid = fork();
    // parent proccess
    if(pid > 0) {
        
        while(1){
            print_menu();
            scanf(" %c",&choice);
            switch (choice) {
                case '0':
                    exit(0);
                    break;
                case '1':
                    
                    break;
                case '2':
                    my_trace("www.google.com");
                    break;
                    
                default:
                    puts("wrong input");
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

