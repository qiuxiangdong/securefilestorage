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


#define flag flase

struct Index ind;
pairing_t pairing;
struct PrivateKey PrivK;
struct Trapdoor trapdoor;
struct sockaddr_in server;
struct sockaddr_in dest;
int status,socket_fd, client_fd,num;
socklen_t size;
char *file_name;

char buffer[10241];
char *buff;
int Keywords_Num,Policy[ATT_NUM];
unsigned char *Dhatstorage,*Dprimestorage,**Dstorage,*C0hatstorage,*C0primestorage,**C0storage, *C1hatstorage,*C1primestorage,**C1storage;


#include <mysql/my_global.h>
#include <mysql/mysql.h>
#include <string.h>


void finish_with_error(MYSQL *con)
{
	fprintf(stderr, "SQLERROR:%s\n", mysql_error(con));
	mysql_close(con);
	exit(1);
}

void store_in_database(){
	MYSQL *con = mysql_init(NULL);
	MYSQL *con1 = mysql_init(NULL);

	if (con == NULL || con1 == NULL) 
	{
		fprintf(stderr, "%s\n", mysql_error(con));
		exit(1);
	}

	mysql_real_connect(con1, "localhost", "root", "supriya", NULL, 0, NULL, 0);

	mysql_query(con1, "CREATE DATABASE filekey");

	if (mysql_real_connect(con, "localhost", "root", "supriya","filekey", 0, NULL, 0) == NULL) 
	{
		finish_with_error(con);
	}

	/*if (mysql_query(con, "DROP TABLE IF EXISTS Keystb")) {
	  finish_with_error(con);
	  }*/

	int len = (6*1050)+(1050*ATT_NUM*3);
	char d_storage[15*ATT_NUM],c_storage[15*ATT_NUM],c1_storage[15*ATT_NUM],str2[15],d_storage_val[65*ATT_NUM],query[len];

	unsigned char DhatSt[1050],DprimeSt[1050],C0hatst[1050],C0primest[1050],C1hatst[1050],C1primest[1050],DSt[1050*ATT_NUM],C0St[1050*ATT_NUM],C1St[1050*ATT_NUM],pol[20];

	memset(DhatSt,0,sizeof(DhatSt));
	memset(DprimeSt,0,sizeof(DprimeSt));
	memset(C0hatst,0,sizeof(C0hatst));
	memset(C0primest,0,sizeof(C0primest));
	memset(C1hatst,0,sizeof(C1hatst));
	memset(C1primest,0,sizeof(C1primest));
	memset(DSt,0,sizeof(DSt));
	memset(C0St,0,sizeof(C0St));
	memset(C1St,0,sizeof(C1St));


	memset(d_storage,0,sizeof(d_storage));
	memset(c_storage,0,sizeof(c_storage));
	memset(c1_storage,0,sizeof(c1_storage));

	memset(str2,0,sizeof(str2));
	memset(d_storage_val,0,sizeof(d_storage_val));


	//Creating a query for creating table

	//concatenating the string for Dstorage
	for(int i=1;i<=ATT_NUM;i++){
		memset(str2,0,sizeof(str2));
		if(i==ATT_NUM)
			sprintf(str2,"Dst%d TEXT",i);
		else
			sprintf(str2,"Dst%d TEXT,",i);
		strcat(d_storage,str2);
	}

	//concatenating the string for Cstorage
	for(int i=1;i<=ATT_NUM;i++){
		memset(str2,0,sizeof(str2));
		if(i==ATT_NUM)
			sprintf(str2,"Cst%d TEXT",i);
		else
			sprintf(str2,"Cst%d TEXT,",i);
		strcat(c_storage,str2);

	}

	//concatenating the string for C1storage
	for(int i=1;i<=ATT_NUM;i++){
		memset(str2,0,sizeof(str2));
		if(i==ATT_NUM)
			sprintf(str2,"C1st%d TEXT",i);
		else
			sprintf(str2,"C1st%d TEXT,",i);
		strcat(c1_storage,str2);     
	}  

	//Query for creating the table
	memset(query,0,sizeof(query));
	sprintf(query,"CREATE TABLE IF NOT EXISTS Keystb (Keywords_Num INT,Policy TEXT,filename TEXT,Dhatstorage TEXT,DprimeStorage TEXT,C0hatstorage TEXT,C0primestorage TEXT,C1hatStorage TEXT,C1primestorage TEXT,%s,%s,%s)",d_storage,c_storage,c1_storage);

	if (mysql_query(con, query)) {      
		finish_with_error(con);
	}

	//Creating query for inserting values in table


	char str[500]; 

	memset(str,0,sizeof(str));
	memset(pol,0,sizeof(pol));
	for(int i=0;i<ATT_NUM;i++){
		sprintf(str,"%d",Policy[i]);
		strcat(pol,str);
		strcat(pol," ");
	}

	//concatenating the values for Dstorage
	for(int i=0;i<ATT_NUM;i++){
		memset(str,0,sizeof(str));
		element_t Dstor;
		element_init_G1(Dstor, pairing);
		element_from_bytes_compressed(Dstor, Dstorage[i]);
		element_snprintf(str,500, "%B",Dstor);
		strcat(DSt,str);
		if(i!= (ATT_NUM-1))
			strcat(DSt,"','");
	}

	//printf("\nDSt = %s\n\n\n",DSt);

	//concatenating the values for Cstorage
	for(int i=0;i<ATT_NUM;i++){
		memset(str,0,sizeof(str));
		element_t Cstor;
		element_init_G1(Cstor, pairing);
		element_from_bytes_compressed(Cstor, C0storage[i]);
		element_snprintf(str,500, "%B",Cstor);
		strcat(C0St,str);
		if(i!= (ATT_NUM-1))
			strcat(C0St,"','");
	}
	//printf("\nC0St = %s\n",C0St);

	//concatenating the values for C1storage
	for(int i=0;i<ATT_NUM;i++){
		memset(str,0,sizeof(str));
		element_t C1stor;
		element_init_G1(C1stor, pairing);
		element_from_bytes_compressed(C1stor, C1storage[i]);
		element_snprintf(str,500, "%B",C1stor);
		strcat(C1St,str);
		if(i!= (ATT_NUM-1))
			strcat(C1St,"','");
	}
	//printf("\nC1St = %s\n",C1St);


	//Query for inserting values


	//DhatStorage
	element_t Dhatstor;
	element_init_G1(Dhatstor, pairing);
	element_from_bytes_compressed(Dhatstor, Dhatstorage);
	element_snprintf(DhatSt,500, "%B",Dhatstor);
	//printf("\nDhatSt = %s",DhatSt);

	//Dprimestorage
	element_t Dpst;
	element_init_GT(Dpst, pairing);
	element_from_bytes(Dpst, Dprimestorage);
	element_snprintf(DprimeSt,500, "%B",Dpst);
	//printf("\nDprimest = %s\n\n",DprimeSt);

	//C0hatstorage
	element_t C0hst;
	element_init_GT(C0hst, pairing);
	element_from_bytes(C0hst, C0hatstorage);
	element_snprintf(C0hatst,500, "%B",C0hst);
	//printf("\n\n\nC0hatst = %s\n\n\n",C0hatst);


	//C0primestorage
	element_t C0pst;
	element_init_G1(C0pst, pairing);
	element_from_bytes_compressed(C0pst, C0primestorage);
	element_snprintf(C0primest,500, "%B",C0pst);
	//printf("\nC0primest = %s\n\n\n",C0primest);


	//C1hatstorage
	element_t C1hst;
	element_init_GT(C1hst, pairing);
	element_from_bytes(C1hst, C1hatstorage);
	element_snprintf(C1hatst,500, "%B",C1hst);
	//printf("\nC1hatst = %s\n\n\n",C1hatst);


	//C1primestorage
	element_t C1pst;
	element_init_G1(C1pst, pairing);
	element_from_bytes_compressed(C1pst, C1primestorage);
	element_snprintf(C1primest,500, "%B",C1pst);
	//printf("\nC1primest = %s\n\n",C1primest);

	memset(query,0,sizeof(query)); 

	sprintf(query,"INSERT INTO Keystb VALUES(%d,\'%s\',\'%s\',\'%s\',\'%s\',\'%s\',\'%s\',\'%s\',\'%s\',\'%s\',\'%s\',\'%s\')",Keywords_Num,pol,file_name,DhatSt,DprimeSt,C0hatst,C0primest,C1hatst,C1primest,DSt,C0St,C1St); 
	//printf("\nInsert query = %s\n\n\n",query);

	if (mysql_query(con, query)) {
		finish_with_error(con);
	}
}

void rec_from_client(){
	char s[16384];
	int i;
	FILE *fp = fopen("./a.param", "r");
	size_t count = fread(s, 1, 16384, fp);
	if (!count) pbc_die("input error");
	fclose(fp);
	if (pairing_init_set_buf(pairing, s, count)) 
		pbc_die("pairing init failed");
	if ((num = recv(client_fd,(char*)&Keywords_Num, sizeof(int),0))== -1) {
		perror("recv");
		exit(1);
	}
	//printf("Keywords_Num:%d\n",Keywords_Num);
	if ((num = recv(client_fd,Policy,sizeof(Policy),0))== -1) {
		perror("recv");
		exit(1);
	}
	//printf("Policy[0] : %d\n",Policy[0]);

	//Dhatstorage
	Dhatstorage=malloc(66);
	memset(Dhatstorage, 0, 66);
	if ((num = recv(client_fd,Dhatstorage, 65,0))== -1) {
		perror("recv");
		exit(1);
	}
	element_t dhat;
	element_init_G1(dhat, pairing);
	element_from_bytes_compressed(dhat, Dhatstorage);
	//element_printf("Dhatstorage %B\n", dhat);

	//Dprimestorage
	Dprimestorage=malloc(129);
	memset(Dprimestorage, 0, 129);
	if ((num = recv(client_fd,Dprimestorage,128,0))== -1) {
		perror("recv");
		exit(1);
	}
	element_t dprime;
	element_init_GT(dprime, pairing);
	element_from_bytes(dprime, Dprimestorage);
	//element_printf("Dprimestorage %B\n", dprime);

	//Dstorage
	Dstorage=malloc(sizeof(unsigned char*)*ATT_NUM);
	for(i=0;i<ATT_NUM;i++){
		Dstorage[i]=malloc(66);
		memset(Dstorage[i],0,66);
		if ((num = recv(client_fd,Dstorage[i], 65,0))== -1) {
			perror("recv");
			exit(1);
		}
		element_t dstor;
		element_init_G1(dstor, pairing);
		element_from_bytes_compressed(dstor, Dstorage[i]);
	//	element_printf("Dstorage[%d] %B\n",i,dstor);
	}

	//C0hatstorage
	C0hatstorage=malloc(128);
	memset(C0hatstorage, 0, 128);
	if ((num = recv(client_fd,C0hatstorage, 128,0))== -1) {
		perror("recv");
		exit(1);
	}
	element_t c0hatstor;
	element_init_GT(c0hatstor, pairing);
	element_from_bytes(c0hatstor, C0hatstorage);
	//element_printf("C0hatstorage %B\n", c0hatstor); 

	//C0primestorage
	C0primestorage=malloc(66);
	memset(C0primestorage, 0, 66);
	if ((num = recv(client_fd,C0primestorage,65,0))== -1) {
		perror("recv");
		exit(1);
	}
	element_t c0primestor;
	element_init_G1(c0primestor, pairing);
	element_from_bytes_compressed(c0primestor, C0primestorage);
	//element_printf("C0primestorage %B\n", c0primestor); 

	//C0storage
	C0storage=malloc(sizeof(unsigned char*)*ATT_NUM);
	for(i=0;i<ATT_NUM;i++){
		C0storage[i]=malloc(66);
		memset(C0storage[i], 0, 66);
		if ((num = recv(client_fd,C0storage[i], 65,0))== -1) {
			perror("recv");
			exit(1);
		}
		element_t C0stor;
		element_init_G1(C0stor, pairing);
		element_from_bytes_compressed(C0stor, C0storage[i]);
	//	element_printf("C0storage[%d] %B\n",i, C0stor);
	}


	//C1hatstorage
	C1hatstorage=malloc(129);
	memset(C1hatstorage, 0, 129);
	if ((num = recv(client_fd,C1hatstorage,128,0))== -1) {
		perror("recv");
		exit(1);
	}
	element_t C1hatstor;
	element_init_GT(C1hatstor, pairing);
	element_from_bytes(C1hatstor, C1hatstorage);
	//element_printf("C1hatstorage %B\n",C1hatstor);

	//C1primestorage
	C1primestorage=malloc(66);
	memset(C1primestorage, 0, 66);
	if ((num = recv(client_fd,C1primestorage,65,0))== -1) {
		perror("recv");
		exit(1);
	}
	element_t C1primestor;
	element_init_G1(C1primestor, pairing);
	element_from_bytes_compressed(C1primestor, C1primestorage);
	//element_printf("C1primestorage %B\n",C1primestor);

	//C1storage
	C1storage=malloc(sizeof(unsigned char*)*ATT_NUM);
	for(i=0;i<ATT_NUM;i++){
		C1storage[i]=malloc(66);
		memset(C1storage[i], 0, 66);
		if ((num = recv(client_fd,C1storage[i], 65,0))== -1) {
			perror("recv");
			exit(1);
		}
		element_t C1stor;
		element_init_G1(C1stor, pairing);
		element_from_bytes_compressed(C1stor, C1storage[i]);
	//	element_printf("C1storage[%d] %B\n",i, C1stor);
	}	

}

void main()
{

	int yes =1;

	if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0))== -1) {
		fprintf(stderr, "Socket failure!!\n");
		exit(1);
	}
	if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
		perror("setsockopt");
		exit(1);
	}
	memset(&server, 0, sizeof(server));
	memset(&dest,0,sizeof(dest));
	server.sin_family = AF_INET;
	server.sin_port = htons(PORT);
	server.sin_addr.s_addr = INADDR_ANY; 
	if ((bind(socket_fd, (struct sockaddr *)&server, sizeof(struct sockaddr )))== -1)    { //sizeof(struct sockaddr) 
		fprintf(stderr, "Binding Failure\n");
		exit(1);
	}

	if ((listen(socket_fd, BACKLOG))== -1){
		fprintf(stderr, "Listening Failure\n");
		exit(1);
	}
	printf("Server: Waiting for a Request..\n");
	while(1) {
		size = sizeof(struct sockaddr_in);
		if ((client_fd = accept(socket_fd, (struct sockaddr *)&dest, &size)) ==-1 )
		{
			perror("accept");
			exit(1);
		}
		printf("Server: connection from client %s\n", inet_ntoa(dest.sin_addr));

		while(1) 
		{
			memset(&buffer, 0, sizeof(buffer));
			rec_from_client();
			char* buffer=malloc(3000);
			memset(buffer,0,3000);
			file_name=malloc(30);
			memset(file_name,0,30);
			int len=0;
			if ((num = recv(client_fd,(char*)&len, sizeof(int),0))== -1) {
				perror("recv");
				exit(1);
			}
			printf("len:%d\n",len);
			if ((num = recv(client_fd, file_name, len,0))== -1) {
				perror("recv");
				exit(1);
			}
			
			else if (num == 0) {
				printf("Server:Error in receiving file name\nConnection closed\n");
				break;
			}
			printf("%s\n",file_name);
			if ((num = recv(client_fd, buffer, 3000,0))== -1) {
				perror("recv");
				exit(1);
			}
			else if (num == 0) {
				printf("Server:Error in receiving file content\nConnection closed\n");
				break;
			}
			char buf_write[9]="Received";                    
			if ((send(client_fd,buf_write, 9,0))== -1) 
			{
				fprintf(stderr, "Failure Sending Message\n");
				close(client_fd);
				break;
			}
			close(client_fd);
			store_in_database();
			printf("Server: File %s and its index uploaded in the database on the cloud\n\n",file_name);
			fflush(stdout);
			FILE *filep=fopen(file_name,"w");
			fputs(buffer,filep);
			fclose(filep);

			break;
		}
	}	  
}

