#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "common.h"
#define PORT 3490
#define MAXSIZE 1024
unsigned char* Khatstorage;
unsigned char** Kstorage;
unsigned char** Fstorage;
pairing_t pairing;

int main(int argc, char *argv[])
{
    struct sockaddr_in server_info;
    struct hostent *he;
    int socket_fd,num;
    char buffer[10240];
    char buff[10240];

    if (argc != 2) {
        fprintf(stderr, "Usage: client hostname\n");
        exit(1);
    }

    if ((he = gethostbyname(argv[1]))==NULL) {
        fprintf(stderr, "Cannot get host name\n");
        exit(1);
    }

    if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0))== -1) {
        fprintf(stderr, "Socket Failure!!\n");
        exit(1);
    }

    memset(&server_info, 0, sizeof(server_info));
    server_info.sin_family = AF_INET;
    server_info.sin_port = htons(PORT);
    server_info.sin_addr = *((struct in_addr *)he->h_addr);
    if (connect(socket_fd, (struct sockaddr *)&server_info, sizeof(struct sockaddr))<0) {
        perror("connect");        exit(1);
    }
	memset(buffer,0,10240);
	char file[30];
        printf("Client: Enter file name for Server:\n");
//	fgets(file,30,stdin);
        scanf("%s",file);
	FILE *fp=fopen(file,"r");
        fgets(buffer,100,fp);

	printf("content read from file %s\n",buffer);
        if ((send(socket_fd,buffer, ATT_NUM,0))== -1) {
	        fprintf(stderr, "Failure Sending Message\n");
                close(socket_fd);
                exit(1);
        }
        else {
	  char *sze;
	  int size;
	  sze=malloc(sizeof(int));
	  memset(sze,0,sizeof(int));
          printf("Client:Message being sent: %s\n",buffer);
	  printf("receiving size of pkey\n");
	  
	  num=recv(socket_fd,(char*)&size,sizeof(size),0);
	  printf("\nnum= %d\n",size);

	  //receiving pkey

	  FILE * fp_bin;
          fp_bin = fopen("PrivK.bin", "wb");
 	  if(fp_bin ==NULL)
	     exit(1);

	  Khatstorage=malloc(size);

	  memset(Khatstorage,0,size);
 	  Kstorage = malloc(ATT_NUM*sizeof(unsigned char*));
	  memset(Kstorage,0,ATT_NUM*sizeof(unsigned char*));
	  Fstorage = malloc(ATT_NUM*sizeof(unsigned char*));
	  memset(Fstorage,0,ATT_NUM*sizeof(unsigned char*));
         
	  int i;      
	  printf("receiving pkey\n");   
	  num=recv(socket_fd,Khatstorage,size,0);
	  fwrite(Khatstorage, 1, size, fp_bin);

//	  fprintf(fp_bin,"%s",Khatstorage);
 	  char s[16384];
	  FILE *fp1 = fopen("./a.param", "r");
	  size_t count = fread(s, 1, 16384, fp1);
	  if (!count) pbc_die("input error");
	  fclose(fp1);
	  if (pairing_init_set_buf(pairing, s, count))
		 pbc_die("pairing init failed");

 	  element_t khattest;
  	  element_init_G1(khattest, pairing);
	  element_from_bytes_compressed(khattest, Khatstorage);
	  element_printf("PrivK.khat received is %B\n", khattest);

  
	  for( i = 0; i < ATT_NUM; i++){
	    Kstorage[i] = malloc(size);
	    memset(Kstorage[i],0,size);
	  }
	  printf("memory allocated for Kstorage\n");
	  for(i=0;i<ATT_NUM;i++){
            num=recv(socket_fd,Kstorage[i],size,0);
            fwrite(Kstorage[i], 1, size, fp_bin);
            element_t Ktest;
       	    element_init_G1(Ktest, pairing);
	    element_from_bytes_compressed(Ktest, Kstorage[i]);
	    element_printf("PrivK.K[i] received is %B\n", Ktest);
	    free(Kstorage[i]);
	  }
	  printf("received kstorage \n");  
 	  free(Kstorage);
	  for( i = 0; i < ATT_NUM; i++){
	    Fstorage[i] = malloc(size);
	    memset(Fstorage[i],0,size);
	  }

	  printf("memory allocated for Fstorage\n");
	  for(i=0;i<ATT_NUM;i++){
             num=recv(socket_fd,Fstorage[i],size,0);
             fwrite(Fstorage[i], 1, size, fp_bin);
  	     if ( num <= 0 )
             {
        	printf("Either Connection Closed or Error\n");
		return 0;
             }
             element_t Ftest;
       	     element_init_G1(Ftest, pairing);
	     element_from_bytes_compressed(Ftest, Fstorage[i]);
	     element_printf("PrivK.F[i] received is %B\n", Ftest);
	     free(Fstorage[i]);
	  }

	  free(Fstorage);
	  printf("received entire key\n");   
	  fclose(fp_bin);
          close(socket_fd); 
	} 
	return 0;
}

