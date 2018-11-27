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

#include <mysql/my_global.h>
#include <mysql/mysql.h>
#include <string.h>

#define PORT 3490
#define flag flase

struct Index ind;
struct Index ind1;
pairing_t pairing;

struct PublicKey PK;
struct PrivateKey PrivK;
struct Trapdoor trapdoor;
struct Trapdoor trapdoor1;
struct sockaddr_in server;
struct sockaddr_in dest;
int status,socket_fd, client_fd,num;
socklen_t size;


char buffer[10241],fileresult[50];

int Keywords_Num;
int AttributeList[ATT_NUM];
unsigned char *Qhatstorage,*Qprimestorage,**Qstorage,**Qfstorage;

int Search(struct Index ind, struct Trapdoor trapdoor)
{
	for(int i = 0; i < ATT_NUM; i++)
	{
		if((ind.Policy[i] == 1 && trapdoor.AttributeList[i] == 0) || (ind.Policy[i] == 2 && trapdoor.AttributeList[i] == 1))      
			return 2;
	}
	element_t temp;
	element_init_GT(temp, pairing);
	pairing_apply(temp, ind.D_hat, trapdoor.Q_hat, pairing);

	element_t temp1;
	element_init_GT(temp1, pairing);
	element_set1(temp1);

	element_t temp2;
	element_init_GT(temp2, pairing);

	for(int i = 0; i < ATT_NUM; i++)
	{
		if(ind.Policy[i] != 0)
		{
			pairing_apply(temp2, ind.D[i], trapdoor.Q[i], pairing);
			element_mul(temp1, temp1, temp2);
		}

		if(ind.Policy[i] == 0)
		{
			pairing_apply(temp2, ind.D[i], trapdoor.Qf[i], pairing);
			element_mul(temp1, temp1, temp2);
		}
	}

	element_mul(temp, temp, temp1);
	element_pow_zn(temp1, ind.D_prime, trapdoor.Q_prime);

	int search = 0;

	if(element_cmp(temp, temp1) == 0)
		search = 1;

	element_clear(temp1);
	element_clear(temp);
	element_clear(temp2);

	return search;

}

int recv_trapdoor()
{
	char s[16384];
	FILE *fp = fopen("./a.param", "r");
	size_t count = fread(s, 1, 16384, fp);
	if (!count) pbc_die("input error");
	fclose(fp);
	if (pairing_init_set_buf(pairing, s, count)) 
		pbc_die("pairing init failed");
	int i;
	unsigned char* Qhatstorage = malloc(65);
	unsigned char* Qprimestorage = malloc(20);
	unsigned char** Qstorage = malloc(sizeof(unsigned char*)*ATT_NUM);
	for(i = 0; i < ATT_NUM; i++)
		Qstorage[i] = malloc(65);
	unsigned char** Qfstorage = malloc(sizeof(unsigned char*)*ATT_NUM);
	for(i = 0; i < ATT_NUM; i++)
		Qfstorage[i] = malloc(65);
	printf("Server: Ready to receive\n");
	if ((num = recv(client_fd,AttributeList,sizeof(AttributeList),0))== -1) {
		perror("recv");
		exit(1);
	}

	memset(Qhatstorage, 0, 65);
	if ((num = recv(client_fd,Qhatstorage,65,0))== -1) {
		perror("recv");
		exit(1);
	}
	//printf("attributelist received: %d\n",(int)AttributeList[0]);
	for(i=0;i<ATT_NUM;i++)
	{
		trapdoor.AttributeList[i]=AttributeList[i];
	}
	element_t Qhatstor;
	element_init_G1(trapdoor.Q_hat, pairing);
	element_from_bytes_compressed(trapdoor.Q_hat, Qhatstorage);
	// element_printf("Qhatstorage received is %B\n", Qhatstor);
	//element_printf("Qhatstorage received is %B\n", trapdoor.Q_hat);
	memset(Qprimestorage, 0, 20);
	if ((num = recv(client_fd,Qprimestorage,20,0))== -1) {
		perror("recv");
		exit(1);
	}
	element_init_Zr(trapdoor.Q_prime, pairing);
	element_from_bytes(trapdoor.Q_prime, Qprimestorage);
	// element_printf("Qprimestorage received is %B\n", trapdoor.Q_prime);
	for(i = 0; i < ATT_NUM; i++)
	{
		if ((num = recv(client_fd,Qstorage[i],65,0))== -1) {
			perror("recv");
			exit(1);
		}
		element_t Qstor;
		element_init_G1(trapdoor.Q[i], pairing);
		element_from_bytes_compressed(trapdoor.Q[i], Qstorage[i]);
		//    element_printf("Q[%d] received is %B\n", i,trapdoor.Q[i]);
	}
	for(i = 0; i < ATT_NUM; i++)
	{
		if ((num = recv(client_fd,Qfstorage[i],65,0))== -1) {
			perror("recv");
			exit(1);
		}
		element_t Qfstor;
		element_init_G1(trapdoor.Qf[i], pairing);
		element_from_bytes_compressed(trapdoor.Qf[i], Qfstorage[i]);
		//trapdoor.Qf[i][0]=Qfstor[0];
		//trapdoor.Qf[i][1]=Qfstor[1];
		// element_printf("Qf[%d] received is %B\n",i, trapdoor.Qf[i]); 
	}

	return 1;
}

void finish_with_error(MYSQL *con)
{
	fprintf(stderr, "\n\nSQLERROR:%s\n", mysql_error(con));
	mysql_close(con);
	exit(1);
}
/**
 * This is run by data owner to generate AES encryption key
 */
void SecretKeyGen(char* filename)
{
	char* a = "openssl rand -base64 128 -out ";
	char *result = malloc(strlen(a)+strlen(filename)+1);//+1 for the zero-terminator
	//in real code you would check for errors in malloc here
	if (result == NULL) exit (1);

	strcpy(result, a);
	strcat(result, filename);
	system(result);
}

/**
 * This is run by data owner to encrypt an uploaded file
 */
void FileEncryption(char* PlaintextFile, char* KeyFile, char* CiphertextFile)
{
	char* a = "openssl enc -aes-256-cbc -salt -in ";
	char* b = malloc(strlen(a)+strlen(PlaintextFile)+1);
	if (b == NULL) exit (1);

	strcpy(b, a);
	strcat(b, PlaintextFile);

	char* a1 = " -out ";
	char* b1 = malloc(strlen(a)+strlen(CiphertextFile)+1);

	if (b1 == NULL) exit (1);

	strcpy(b1, a1);
	strcat(b1, CiphertextFile);

	char* b2 = malloc(strlen(b)+strlen(b1)+1);

	if (b2 == NULL) exit (1);

	strcpy(b2, b);
	strcat(b2, b1);

	char* a3 = " -pass file:./";
	char* b3 = malloc(strlen(a3)+strlen(KeyFile)+1);

	if (b3 == NULL) exit (1);

	strcpy(b3, a3);
	strcat(b3, KeyFile);

	char* result = malloc(strlen(b2)+strlen(b3)+1);
	strcpy(result, b2);
	strcat(result, b3);

	system(result);

}

/**
 * This is the encryption algorithm of the ABE scheme
 */
void ABEEncrypt(int Policy[ ], element_t plaintext, struct ABECiphertext* abeciphertext)
{
	for(int i = 0; i < ATT_NUM; i++)
		abeciphertext->Policy[i] = Policy[i];

	element_init_GT(abeciphertext->C_hat, pairing);
	element_t s;
	element_init_Zr(s, pairing);
	element_random(s);

	element_t temp;
	element_init_GT(temp, pairing);
	element_pow_zn(temp, PK.Y, s);
	element_mul(abeciphertext->C_hat, plaintext, temp);

	element_init_G1(abeciphertext->C_prime, pairing);
	element_pow_zn(abeciphertext->C_prime, PK.g, s);

	for(int i = 0; i < ATT_NUM; i++)
	{
		if(Policy[i] == 1)
		{
			element_init_G1(abeciphertext->C[i], pairing);
			element_pow_zn(abeciphertext->C[i], PK.T[i], s);
		}
		if(Policy[i] == 2)
		{
			element_init_G1(abeciphertext->C[i], pairing);
			element_pow_zn(abeciphertext->C[i], PK.T[ATT_NUM+i], s);
		}
		if(Policy[i] == 0)
		{
			element_init_G1(abeciphertext->C[i], pairing);
			element_pow_zn(abeciphertext->C[i], PK.T[2*ATT_NUM+i], s);
		}

	}

	element_clear(temp);
}

/**
 * This is run by data owner to encrypt an AES encryption key
 * The ciphertext correponds to the second part stored in an index
 */
void ABEFileKeyEncrypt(char* KeyFile, int Policy[ ])
{
	//read the AES key stored in a file named KeyFile
	FILE *pFile=fopen(KeyFile,"r");
	char *Key;  
	fseek(pFile,0,SEEK_END); 
	int len=ftell(pFile); 
	Key=malloc(sizeof(char)*(len+1));
	rewind(pFile);
	fread(Key,1,len,pFile); 
	Key[len]=0;
	//printf("%s\n", Key);
	fclose(pFile);

	//partition the symmetric key into two parts expKey1 and expKey2, so that they can be encrypted
	//by ABE algorithm
	unsigned char* expKey1 = malloc(sizeof(char)*129);
	for(int i = 0; i < 128; i++)
	{
		expKey1[i] = Key[i];
	}
	expKey1[128] = 0;
	//printf("expkey1 is %s \n", expKey1);

	unsigned char* expKey2 = malloc(sizeof(char)*48);
	for(int i = 0; i < strlen(Key)-128; i++)
	{
		expKey2[i] = Key[128+i];
	}
	expKey2[47] = 0;
	//covert expKey1 and expKey2 into pairing elements pbcKey1 and pbcKey2
	element_t pbcKey1;
	element_init_GT(pbcKey1, pairing);
	element_from_bytes(pbcKey1, expKey1);

	element_t pbcKey2;
	element_init_GT(pbcKey2, pairing);
	element_from_bytes(pbcKey2, expKey2);

	
	ABEEncrypt(Policy, pbcKey1, &ind.abeaesciphertext.abeaesciphertext[0]);
	ABEEncrypt(Policy, pbcKey1, &ind.abeaesciphertext.abeaesciphertext[1]);

}

/**
 * This is run by data owner to genrate index for an uploaded file
 */
void SecureIndexGeneration(int Policy[], char* keywords[])
{
	ind1.Keywords_Num = 1;
	element_t s;
	for(int i = 0; i < ATT_NUM; i++)
		ind1.Policy[i] = Policy[i];

	element_init_Zr(s, pairing);
	element_random(s);

	element_init_G1(ind1.D_hat, pairing);
	element_pow_zn(ind1.D_hat, PK.g, s);

	element_init_GT(ind1.D_prime, pairing);
	element_pow_zn(ind1.D_prime, PK.Y, s);

	element_t temp;
	element_init_Zr(temp, pairing);

	for(int i = 0; i < ATT_NUM; i++)
	{
		if(i < ind1.Keywords_Num)
		{
			if(Policy[i] == 1)
			{
				element_from_hash(temp, keywords[i], strlen(keywords[i]));
				element_div(temp, s, temp);
				element_init_G1(ind1.D[i], pairing);
				element_pow_zn(ind1.D[i], PK.T[i], temp);
			}
			if(Policy[i] == 2)
			{
				element_from_hash(temp, keywords[i], strlen(keywords[i]));
				element_div(temp, s, temp);
				element_init_G1(ind1.D[i], pairing);
				element_pow_zn(ind1.D[i], PK.T[ATT_NUM+i], temp);
			}
			if(Policy[i] == 0)
			{
				element_from_hash(temp, keywords[i], strlen(keywords[i]));
				element_div(temp, s, temp);
				element_init_G1(ind1.D[i], pairing);
				element_pow_zn(ind1.D[i], PK.T[2*ATT_NUM+i], temp);
			}
		}

		if(i >= ind1.Keywords_Num)
		{
			if(Policy[i] == 1)
			{
				element_init_G1(ind1.D[i], pairing);
				element_pow_zn(ind1.D[i], PK.T[i], s);
			}
			if(Policy[i] == 2)
			{
				element_init_G1(ind1.D[i], pairing);
				element_pow_zn(ind1.D[i], PK.T[ATT_NUM+i], s);
			}
			if(Policy[i] == 0)
			{
				element_init_G1(ind1.D[i], pairing);
				element_pow_zn(ind1.D[i], PK.T[2*ATT_NUM+i], s);
			}

		} 
	}
	element_clear(temp);
}

void TrapdoorGeneration(struct PrivateKey PrivK, char* keyword)
{
	element_t u;
	element_init_Zr(u,pairing);
	element_random(u);
	//element_set1(u);  

	element_init_G1(trapdoor1.Q_hat, pairing);
	element_pow_zn(trapdoor1.Q_hat, PrivK.K_hat, u);

	element_init_Zr(trapdoor1.Q_prime, pairing);
	element_set(trapdoor1.Q_prime, u);

	element_t temp;
	element_init_Zr(temp, pairing);

	element_t KW;
	element_init_Zr(KW, pairing);
	element_from_hash(KW, keyword, strlen(keyword));

	for(int i = 0; i < ATT_NUM; i++)
	{
		if(i == 0)
		{
			element_mul(temp, KW, u);
			element_init_G1(trapdoor1.Q[i], pairing);
			element_pow_zn(trapdoor1.Q[i], PrivK.K[i], temp);

			element_init_G1(trapdoor1.Qf[i], pairing);
			element_pow_zn(trapdoor1.Qf[i], PrivK.F[i], temp);
		}
		else
		{
			element_init_G1(trapdoor1.Q[i], pairing);
			element_pow_zn(trapdoor1.Q[i], PrivK.K[i], u);

			element_init_G1(trapdoor1.Qf[i], pairing);
			element_pow_zn(trapdoor1.Qf[i], PrivK.F[i], u);
		}  
	}
}
void SearchIndex(struct Trapdoor trapdoor)
{  struct Index indd;
	char *file_name;
	file_name=malloc(30);
	memset(file_name,0,30);
	struct ABEAESCiphertext AESKEYCIPHERTEXT;
	int k;
	//query call
	//database connection
	MYSQL *con = mysql_init(NULL);

	if (con == NULL) 
	{
		fprintf(stderr, "%s\n", mysql_error(con));
		exit(1);
	}

	if (mysql_real_connect(con, "localhost", "root", "supriya","filekey", 0, NULL, 0) == NULL) 
	{
		finish_with_error(con);
	}


	//concatenating the string for Cstorage
	char c_storage[15*ATT_NUM],str[10];
	memset(c_storage,0,sizeof(c_storage));

	for(int i=1;i<=ATT_NUM;i++){
		memset(str,0,sizeof(str));
		if(i==ATT_NUM)
			sprintf(str,"Cst%d",i);
		else
			sprintf(str,"Cst%d,",i);
		strcat(c_storage,str);

	}

	//concatenating the string for C1storage
	char c1_storage[15*ATT_NUM];
	memset(c1_storage,0,sizeof(c1_storage));

	for(int i=1;i<=ATT_NUM;i++){
		memset(str,0,sizeof(str));
		if(i==ATT_NUM)
			sprintf(str,"Cst%d",i);
		else
			sprintf(str,"Cst%d,",i);
		strcat(c1_storage,str);

	}

	//concatenating the string for Dstorage
	char d_storage[15*ATT_NUM];
	memset(d_storage,0,sizeof(d_storage));

	for(int i=1;i<=ATT_NUM;i++){
		memset(str,0,sizeof(str));
		if(i==ATT_NUM)
			sprintf(str,"Dst%d",i);
		else
			sprintf(str,"Dst%d,",i);
		strcat(d_storage,str);
	}
	//Query for creating the table
	char query[1000];
	memset(query,0,sizeof(query));
	sprintf(query,"SELECT * from Keystb");
	if (mysql_query(con, query)) {
		finish_with_error(con);
	}
	MYSQL_RES *result = mysql_store_result(con);
	if (result == NULL) 
	{
		finish_with_error(con);
	}

	int Policy[ATT_NUM];

	int num_fields = mysql_num_fields(result);

	MYSQL_ROW row;
	char ds[5000];
	char val[1];

	element_t Dhatstor,Dprimestor,C0hatst,C0primest,C1hatst,C1primest,Dst,C0st,C1st;
	char file[30];
	int found;
	found=0;
	memset(file,0,30);
	while ((row = mysql_fetch_row(result))) 
	{ 
		memset(ds,0,sizeof(ds));
		for(int i = 0; i < num_fields; i++) 
		{ 
			memset(ds,0,sizeof(ds));
			sprintf(ds,"%s", row[i] ? row[i] : "NULL");
			if(i == 1){ //policy
				for(int j = 0,k=0;k<ATT_NUM;j++){
					if(ds[j] != ' '){
						Policy[k++]=ds[j]-'0';
					}
				}
			} 
			if(i==2){
				strcpy(file,ds);
			}
			if(i==3){ //Dhatstorage
				element_init_G1(ind.D_hat, pairing);
				element_set_str(ind.D_hat,ds,10);
				//element_printf("Dhatstorage %B\n", ind.D_hat);
			}

			else if(i==4){ //Dprimestorage

				element_init_GT(ind.D_prime, pairing);
				element_set_str(ind.D_prime,ds,10);
				//element_printf("Dprimestorage %B\n", ind.D_prime);
			}

			else if(i==5){ //C0hatstorage
				element_init_GT(ind.abeaesciphertext.abeaesciphertext[0].C_hat, pairing);
				element_set_str(ind.abeaesciphertext.abeaesciphertext[0].C_hat,ds,10);
				//element_printf("C0hatstorage %B\n",ind.abeaesciphertext.abeaesciphertext[0].C_hat);

			}

			else if(i==6){ //C0primestorage
				element_init_G1(ind.abeaesciphertext.abeaesciphertext[0].C_prime, pairing);
				element_set_str(ind.abeaesciphertext.abeaesciphertext[0].C_prime,ds,10);
				//element_printf("C0primestorage %B\n",ind.abeaesciphertext.abeaesciphertext[0].C_prime);

			}

			else if(i==7){ //C1hatStorage
				element_init_GT(ind.abeaesciphertext.abeaesciphertext[1].C_hat, pairing);
				element_set_str(ind.abeaesciphertext.abeaesciphertext[1].C_hat,ds,10);
				//element_printf("C1hatstorage %B\n",ind.abeaesciphertext.abeaesciphertext[1].C_hat);
			}

			else if(i==8){ //C1primestorage
				element_init_G1(ind.abeaesciphertext.abeaesciphertext[1].C_prime, pairing);
				element_set_str(ind.abeaesciphertext.abeaesciphertext[1].C_prime,ds,10);
				//element_printf("C1primestorage %B\n", ind.abeaesciphertext.abeaesciphertext[1].C_prime);		

			}
			//Dstorage
			else if(i >= 9 && i < 9+ATT_NUM){
				element_init_G1(ind.D[i-9], pairing);
				element_set_str(ind.D[i-9],ds,10);
				// element_printf("Dstorage[%d] %B\n", (i-9),ind.D[i-9]);
			}

			//C0storage 
			else if(i >= 9+ATT_NUM && i < 9+(2*ATT_NUM)){

				element_init_G1(ind.abeaesciphertext.abeaesciphertext[0].C[i-9-ATT_NUM], pairing);
				element_set_str(ind.abeaesciphertext.abeaesciphertext[0].C[i-9-ATT_NUM],ds,10);
				//element_printf("C0storage[%d] %B\n", (i-9-ATT_NUM),ind.abeaesciphertext.abeaesciphertext[0].C[i-9-ATT_NUM]);
			}

			//C1storage
			else if(i >= 9+(2*ATT_NUM) && i < 9+(3*ATT_NUM)){
				element_init_G1(ind.abeaesciphertext.abeaesciphertext[1].C[i-9-(2*ATT_NUM)], pairing);
				element_set_str(ind.abeaesciphertext.abeaesciphertext[1].C[i-9-(2*ATT_NUM)],ds,10);
				//element_printf("C1storage[%d] %B\n", (i-9-(2*ATT_NUM)),ind.abeaesciphertext.abeaesciphertext[1].C[i-9-(2*ATT_NUM)]);
			}
		} 

		for(int j=0;j<ATT_NUM;j++){
			ind.abeaesciphertext.abeaesciphertext[0].Policy[j]=Policy[j];
			ind.abeaesciphertext.abeaesciphertext[1].Policy[j]=Policy[j];
			ind.Policy[j]=Policy[j];
		} 

		int search = Search(ind, trapdoor);

		memset(fileresult,0,50);
		if( search == 1)
		{
			found=1;
			sprintf(fileresult,"%s contains the interested keyword",file);
			printf("Server: %s contains the interested keyword\n",file);
			if ((send(client_fd,fileresult, 50,0))== -1) 
			{
				// fprintf(stderr, "Failure Sending Message\n");
				close(client_fd);
				break;
			}
			//ABEFileKeyDecrypt(ind.abeaesciphertext, "DK.bin");
			//FileDecryption("file.enc", "DK.bin", "decfile.txt");
		}
		else if(search == 2){
			printf("you do not have the search capacity for %s\n",file);
			sprintf(fileresult,"You do not have the search capacity ");
			if ((send(client_fd,fileresult, 50,0))== -1) 
			{
				// fprintf(stderr, "Failure Sending Message\n");
				close(client_fd);
				break;
			}
		}
		//else
		//	printf("no, it does not contain the interested keyword\n");
		
	}
	memset(fileresult,0,50);
	sprintf(fileresult,"search END");
	if ((send(client_fd,fileresult, 50,0))== -1) 
	{
		// fprintf(stderr, "Failure Sending Message\n");
		close(client_fd);
	}

}
void main()
{
	int yes=1;

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
		printf("Server: Got connection from client %s\n", inet_ntoa(dest.sin_addr));
		while(1) 
		{

			memset(&buffer, 0, sizeof(buffer));
			if(1==recv_trapdoor()){
				printf("Server: Trapdoor received\n");
				SearchIndex(trapdoor);
			}
			else{
				printf("server: Error in receiving trapdoor request\n");
			}
			close(client_fd);
			break;
		}
	}	  
}

