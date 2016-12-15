#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void Remove( char* string, char ch);
int main(int argc, char *argv[])
{
  char string[100];
  FILE *f;
  f = fopen("sample.txt","w");
  strcpy( string, f);
  Remove( string, '|');
  puts( string);
  system("PAUSE"); 
  fclose(f);
  return 0;
}

void Remove( char* string, char ch )
{
     char* pstr = string;
     char* pstrOld = strdup( string );
     char* pstrNew;
     char* pstrOldFree = pstrOld;
     
     pstrNew = strchr( pstrOld, ch );
     
     while( pstrNew )
     {
            strncpy( pstr, pstrOld, pstrNew-pstrOld);
            *(pstr+(pstrNew-pstrOld)) = 0;
            
            pstr += (pstrNew-pstrOld);
            
            pstrOld = pstrNew + 1;
            pstrNew = strchr( pstrOld, ch );
            
            if( pstrNew == NULL )
            strcat(pstr, pstrOld );
            
     }
     free(pstrOldFree);
 }
