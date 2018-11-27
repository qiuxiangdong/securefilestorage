#include "common.h"
struct PrivateKey PrivK;
struct PublicKey PK;
pairing_t pairing;
struct Trapdoor trapdoor;
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define BACKLOG 5
#define PORT 3490

void TrapdoorGeneration(struct PrivateKey PrivK, char* keyword)
{
	element_t u;
	element_init_Zr(u,pairing);
	element_random(u);
	//element_set1(u);  

	element_init_G1(trapdoor.Q_hat, pairing);
	element_pow_zn(trapdoor.Q_hat, PrivK.K_hat, u);

	element_init_Zr(trapdoor.Q_prime, pairing);
	element_set(trapdoor.Q_prime, u);

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
			element_init_G1(trapdoor.Q[i], pairing);
			element_pow_zn(trapdoor.Q[i], PrivK.K[i], temp);

			element_init_G1(trapdoor.Qf[i], pairing);
			element_pow_zn(trapdoor.Qf[i], PrivK.F[i], temp);
		}
		else
		{
			element_init_G1(trapdoor.Q[i], pairing);
			element_pow_zn(trapdoor.Q[i], PrivK.K[i], u);

			element_init_G1(trapdoor.Qf[i], pairing);
			element_pow_zn(trapdoor.Qf[i], PrivK.F[i], u);
		}

	}

}
void send_trapdoor(char* hostIP)
{
	char s[16384];
	FILE *fp = fopen("./a.param", "r");
	size_t count = fread(s, 1, 16384, fp);
	if (!count) pbc_die("input error");
	fclose(fp);
	if (pairing_init_set_buf(pairing, s, count)) pbc_die("pairing init failed");
	struct sockaddr_in server_info;
	struct hostent *he;
	int socket_fd,num;
	int i;

	if ((he = gethostbyname(hostIP))==NULL) {
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
		perror("connect");
		exit(1);
	}

	int m = element_length_in_bytes_compressed(trapdoor.Q_hat);
	int k = element_length_in_bytes(trapdoor.Q_prime);
	//printf("m k is %d %d\n",m, k);

	//All the following strings should be received from data user. 
	unsigned char* Qhatstorage = malloc(65);
	unsigned char* Qprimestorage = malloc(20);
	unsigned char** Qstorage = malloc(sizeof(unsigned char*)*ATT_NUM);
	for(i = 0; i < ATT_NUM; i++)
		Qstorage[i] = malloc(65);
	unsigned char** Qfstorage = malloc(sizeof(unsigned char*)*ATT_NUM);
	for(i = 0; i < ATT_NUM; i++)
		Qfstorage[i] = malloc(65);

	element_to_bytes_compressed(Qhatstorage,trapdoor.Q_hat);
	element_to_bytes(Qprimestorage,trapdoor.Q_prime);
	for(i = 0; i < ATT_NUM; i++)
	{
		element_to_bytes_compressed(Qstorage[i],trapdoor.Q[i]);
		element_to_bytes_compressed(Qfstorage[i],trapdoor.Qf[i]);
	}

	//sending attributelist
	if ((send(socket_fd,trapdoor.AttributeList, sizeof(trapdoor.AttributeList),0))== -1) {
		fprintf(stderr, "Failure Sending AttributeList\n");
		close(socket_fd);
		exit(1);
	}
	if ((send(socket_fd,Qhatstorage, 65,0))== -1) {
		fprintf(stderr, "Failure Sending Qhatstorage\n");
		close(socket_fd);
		exit(1);
	}
	// printf("Qprimestor: %s\n",Qprimestorage);
	if ((send(socket_fd,Qprimestorage,20,0))== -1) {
		fprintf(stderr, "Failure Sending Qprimestorage\n");
		close(socket_fd);
		exit(1);
	}
	for(i=0;i<ATT_NUM;i++){
		if ((send(socket_fd,Qstorage[i], 65,0))== -1) {
			fprintf(stderr, "Failure Sending Qstorage\n");
			close(socket_fd);
			exit(1);
		}
	}
	for(i=0;i<ATT_NUM;i++){
		if ((send(socket_fd,Qfstorage[i], 65,0))== -1) {
			fprintf(stderr, "Failure Sending Qfstorage\n");
			close(socket_fd);
			exit(1);
		}
	}
	char result[50];
	while(0!=strcmp(result,"search END")){
		memset(result,0,50);
		if ((num = recv(socket_fd, result, 50,0))== -1) {
			perror("recv");
			exit(1);
		}
		printf("%s\n",result);
		fflush(stdout);
	}
	close(socket_fd);
}
int main(int argc, char *argv[])
{
	char s[16384];
	FILE *fp = fopen("./a.param", "r");
	size_t count = fread(s, 1, 16384, fp);
	if (!count) pbc_die("input error");
	fclose(fp);
	if (pairing_init_set_buf(pairing, s, count)) pbc_die("pairing init failed");
	if (argc != 2) {
		fprintf(stderr, "Usage: client hostname\n");
		exit(1);
	}

	char* buffer;
	buffer=malloc(ATT_NUM+1);
	memset(buffer,0,ATT_NUM+1);

	element_init_G1(PrivK.K_hat, pairing);
	for(int i = 0; i < ATT_NUM; i++)
		element_init_G1(PrivK.K[i], pairing);
	for(int i = 0; i < ATT_NUM; i++)
		element_init_G1(PrivK.F[i], pairing);


	ReadPrivKfromFile("PrivK.bin", &PrivK);
	char* keyword = malloc(10);
	memset(keyword,0,10);
	printf("Client: Enter Keyword List:\n");
	scanf("%s",keyword);


	FILE *fp2=fopen("attributelist.txt","r");
	fgets(buffer,ATT_NUM+1,fp2);
	//printf("attribute: %s\n",buffer);

	TrapdoorGeneration(PrivK, keyword);
	for(int i = 0; i < ATT_NUM; i++){
		trapdoor.AttributeList[i] = buffer[i]-48;
		//printf("attributelist[%d] =%d\n",i,trapdoor.AttributeList[i]);
	}
	// element_printf("Q_hat %B\n", trapdoor.Q_hat);  
	send_trapdoor(argv[1]);


	return 0;
}

















