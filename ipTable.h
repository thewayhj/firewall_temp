#include <unistd.h>
#include <stdio.h>
#include <errno.h>   /* errno */
#include <string.h>  /* strerror */

FILE        *fp = NULL;
size_t      readSize = 0;
char        pszBuff[1024];

char  ad[100] = "sudo iptables -A INPUT ";
char  del[100] = "sudo iptables -D INPUT ";
char  fnl[100]=" -j DROP";
char ip[100] = "-s ";
char port_1[100] = "-p tcp --sport ";
char port_2[100] = " --dport ";
char result[100];

int addport(int buf1,int buf2){
	char pbuf_1[10];
	char pbuf_2[10];
	
	
	sprintf(pbuf_1,"%d",buf1);
	sprintf(pbuf_2,"%d",buf2);

	sprintf(result, "%s%s%s%s%s%s",ad,port_1,pbuf_1,port_2,pbuf_2,fnl);
	comp();
}

int addip(char buf[]){
	sprintf(result, "%s%s%s%s",ad,ip,buf,fnl);
	comp();
}

int delport(int buf1,int buf2){

	char pbuf_1[10];
	char pbuf_2[10];
	
	sprintf(pbuf_1,"%d",buf1);
	sprintf(pbuf_2,"%d",buf2);
	
	sprintf(result, "%s%s%s%s%s%s",del,port_1,pbuf_1,port_2,pbuf_2,fnl);
	comp();
}

int delip(char buf[]){
	
	sprintf(result, "%s%s%s%s",del,ip,buf,fnl);
	comp();

}

int comp(){

    fp = popen(result, "r");
    if( !fp)
    {
        printf("[%d:%s]\n", errno, strerror(errno));
        return -1;
    }

    // read the result
    readSize = fread( (void*)pszBuff, sizeof(char), 1024-1, fp );

    if( readSize == 0 )
    {
        pclose(fp);
        printf("[%d:%s]\n", errno, strerror(errno));
        return -1;
    }

    pclose(fp);
    pszBuff[readSize]=0;
	printf("%s\n", pszBuff);
}
