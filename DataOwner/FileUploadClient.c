#include "common.h"
struct Index ind;
pairing_t pairing;
struct PublicKey PK;
struct PrivateKey PrivK;
struct Trapdoor trapdoor;
#define PORT 3490
#define MAXSIZE 10240


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
	int i;
	for( i = 0; i < ATT_NUM; i++)
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

	for(i = 0; i < ATT_NUM; i++)
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
	fclose(pFile);
	int i;
	//partition the symmetric key into two parts expKey1 and expKey2, so that they can be encrypted
	//by ABE algorithm
	unsigned char* expKey1 = malloc(sizeof(char)*129);
	for(i = 0; i < 128; i++)
	{
		expKey1[i] = Key[i];
	}
	expKey1[128] = 0;
	// printf("expkey1 is %s \n", expKey1);

	unsigned char* expKey2 = malloc(sizeof(char)*48);
	for(i = 0; i < strlen(Key)-128; i++)
	{
		expKey2[i] = Key[128+i];
	}
	expKey2[47] = 0;
	//printf("expkey2 is %s \n", expKey2);

	//covert expKey1 and expKey2 into pairing elements pbcKey1 and pbcKey2
	element_t pbcKey1;
	element_init_GT(pbcKey1, pairing);
	element_from_bytes(pbcKey1, expKey1);

	element_t pbcKey2;
	element_init_GT(pbcKey2, pairing);
	element_from_bytes(pbcKey2, expKey2);

	//element_printf("pbcKey1 is %B\n", pbcKey1);
	//element_printf("pbcKey2 is %B\n", pbcKey2);

	ABEEncrypt(Policy, pbcKey1, &ind.abeaesciphertext.abeaesciphertext[0]);
	ABEEncrypt(Policy, pbcKey1, &ind.abeaesciphertext.abeaesciphertext[1]);

}

/**
 * This is run by data owner to genrate index for an uploaded file
 */
void SecureIndexGeneration(int Policy[], char* keywords[])
{
	ind.Keywords_Num = 1;
	element_t s;
	int i;
	for(i = 0; i < ATT_NUM; i++)
		ind.Policy[i] = Policy[i];

	element_init_Zr(s, pairing);
	element_random(s);

	element_init_G1(ind.D_hat, pairing);
	element_pow_zn(ind.D_hat, PK.g, s);

	element_init_GT(ind.D_prime, pairing);
	element_pow_zn(ind.D_prime, PK.Y, s);

	element_t temp;
	element_init_Zr(temp, pairing);

	for(i = 0; i < ATT_NUM; i++)
	{
		if(i < ind.Keywords_Num)
		{
			if(Policy[i] == 1)
			{
				element_from_hash(temp, keywords[i], strlen(keywords[i]));
				element_div(temp, s, temp);
				element_init_G1(ind.D[i], pairing);
				element_pow_zn(ind.D[i], PK.T[i], temp);
			}
			if(Policy[i] == 2)
			{
				element_from_hash(temp, keywords[i], strlen(keywords[i]));
				element_div(temp, s, temp);
				element_init_G1(ind.D[i], pairing);
				element_pow_zn(ind.D[i], PK.T[ATT_NUM+i], temp);
			}
			if(Policy[i] == 0)
			{
				element_from_hash(temp, keywords[i], strlen(keywords[i]));
				element_div(temp, s, temp);
				element_init_G1(ind.D[i], pairing);
				element_pow_zn(ind.D[i], PK.T[2*ATT_NUM+i], temp);
			}
		}

		if(i >= ind.Keywords_Num)
		{
			if(Policy[i] == 1)
			{
				element_init_G1(ind.D[i], pairing);
				element_pow_zn(ind.D[i], PK.T[i], s);
			}
			if(Policy[i] == 2)
			{
				element_init_G1(ind.D[i], pairing);
				element_pow_zn(ind.D[i], PK.T[ATT_NUM+i], s);
			}
			if(Policy[i] == 0)
			{
				element_init_G1(ind.D[i], pairing);
				element_pow_zn(ind.D[i], PK.T[2*ATT_NUM+i], s);
			}

		}  
	}
	element_clear(temp);
}

int main(int argc, char *argv[])
{
	struct sockaddr_in server_info;
	struct hostent *he;
	int socket_fd,num;
	char *buffer;
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
		perror("connect");
		exit(1);
	}
	buffer=malloc(5000*sizeof(char));
	memset(buffer,0,5000);
	char *file,*encrypted_file;
	file=(char*)malloc(40);
	encrypted_file=(char*)malloc(20);
	memset(file,0,40);
	memset(encrypted_file,0,20);
	printf("Client: Enter file name for Server:\n");
	scanf("%s",file);
	char s[16384];
	FILE *fp = fopen("./a.param", "r");
	size_t count = fread(s, 1, 16384, fp);
	if (!count) pbc_die("input error");
	fclose(fp);
	if (pairing_init_set_buf(pairing, s, count)) 
		pbc_die("pairing init failed");

	element_init_GT(PK.Y, pairing);
	element_init_G1(PK.g, pairing);
	int i;
	for(i = 0; i < PARAM_NUM; i++)
		element_init_G1(PK.T[i], pairing);

	readPKfromFile("PK.bin", &PK);

	int Policy[ATT_NUM];
	for(i = 0; i < ATT_NUM; i++)
	{
		Policy[i] = 0;
	}

   	char *token;
        char file_tmp[20];
        memset(file_tmp,0,sizeof(file_tmp));
        strcpy(file_tmp,file);
	token = strtok(file_tmp,".");


	strcpy(encrypted_file,token);

	strcat(encrypted_file,".enc");

	Policy[0] = 1;
	Policy[1] = 0;
	char Keyword[10];
	memset(Keyword,0,10);
	printf("Client: Enter Keyword List:\n");
	scanf("%s",Keyword);

	//encrypt the keywords, AES key as well the files
	//char* keywords[1] = {"ABE"};
	//printf("Keyword: %s\n",Keyword);
	
	char* keywords[1];//=(char*)malloc();
	keywords[0]=Keyword;
	//    strcpy(keywords[0],Keyword);
	//printf("Keyword[1]: %s\n",Keyword);
	//generate the first part of the index
	SecureIndexGeneration(Policy, keywords);
	//encrypt the uploaded file
	SecretKeyGen("key.bin");

	FileEncryption(file, "key.bin", encrypted_file);

	//generate the second part of the index
	ABEFileKeyEncrypt("key.bin", Policy);
//	strcpy(encrypted_file,"file.enc");
	fp=fopen(encrypted_file,"r");
	fgets(buffer,4999,fp);
	//sending index of the file

	/**
	 * The following codes are element_t and unsigned char* transformation. You could check whether 
	 * your codes are correct by first run the codes below and after the server side receives these
	 * values (all the unsigned char*), run the codes I put there to compare
	 */

	//the first part of index
	unsigned char *Dhatstorage = malloc(65);
	unsigned char *Dprimestorage = malloc(128);
	unsigned char** Dstorage = malloc(sizeof(unsigned char*)*ATT_NUM);
	for(i = 0; i < ATT_NUM; i++)
		Dstorage[i] = malloc(65);

	//element_printf("ind.D_hat before transmission is %B\n", ind.D_hat);
	element_to_bytes_compressed(Dhatstorage, ind.D_hat);
	//element_printf("ind.D_prime before transmission is %B\n", ind.D_prime);
	element_to_bytes(Dprimestorage, ind.D_prime);
	//for(i = 0; i < ATT_NUM; i++)
	//element_printf("ind.D is %B\n", ind.D[i]);  
	for(i = 0; i < ATT_NUM; i++)
		element_to_bytes_compressed(Dstorage[i], ind.D[i]);

	//the second part of index
	unsigned char *C0hatstorage = malloc(128);
	unsigned char *C0primestorage = malloc(65);
	unsigned char** C0storage = malloc(sizeof(unsigned char*)*ATT_NUM);
	for(i = 0; i < ATT_NUM; i++)
		C0storage[i] = malloc(65);

	//  element_printf(" ind.abeaesciphertext.abeaesciphertext[0].C_hat is %B\n", ind.abeaesciphertext.abeaesciphertext[0].C_hat);
	element_to_bytes(C0hatstorage, ind.abeaesciphertext.abeaesciphertext[0].C_hat);
	// element_printf(" ind.abeaesciphertext.abeaesciphertext[0].C_prime is %B\n", ind.abeaesciphertext.abeaesciphertext[0].C_prime);
	element_to_bytes_compressed(C0primestorage, ind.abeaesciphertext.abeaesciphertext[0].C_prime);
	// for(i = 0; i < ATT_NUM; i++)
	// element_printf("ind.abeaesciphertext.abeaesciphertext[0].C[i] is %B\n", ind.abeaesciphertext.abeaesciphertext[0].C[i]);  
	for( i = 0; i < ATT_NUM; i++)
		element_to_bytes_compressed(C0storage[i], ind.abeaesciphertext.abeaesciphertext[0].C[i]);                                

	unsigned char *C1hatstorage = malloc(128);
	unsigned char *C1primestorage = malloc(65);
	unsigned char** C1storage = malloc(sizeof(unsigned char*)*ATT_NUM);
	for(i = 0; i < ATT_NUM; i++)
		C1storage[i] = malloc(65);

	//  element_printf(" ind.abeaesciphertext.abeaesciphertext[1].C_hat is %B\n", ind.abeaesciphertext.abeaesciphertext[1].C_hat);
	element_to_bytes(C1hatstorage, ind.abeaesciphertext.abeaesciphertext[1].C_hat);
	// element_printf(" ind.abeaesciphertext.abeaesciphertext[1].C_prime is %B\n", ind.abeaesciphertext.abeaesciphertext[1].C_prime);
	element_to_bytes_compressed(C1primestorage, ind.abeaesciphertext.abeaesciphertext[1].C_prime);
	/* for( i = 0; i < ATT_NUM; i++)
	   element_printf("ind.abeaesciphertext.abeaesciphertext[1].C[i] is %B\n", ind.abeaesciphertext.abeaesciphertext[1].C[i]);  
	 */
	for(i = 0; i < ATT_NUM; i++)
		element_to_bytes_compressed(C1storage[i], ind.abeaesciphertext.abeaesciphertext[1].C[i]);    


	if ((send(socket_fd,(char*)&ind.Keywords_Num, sizeof(int),0))== -1) {
		fprintf(stderr, "Failure Sending Dhat\n");
		close(socket_fd);
		exit(1);
	}

	if ((send(socket_fd,ind.Policy, sizeof(ind.Policy),0))== -1) {
		fprintf(stderr, "Failure Sending Policy\n");
		close(socket_fd);
		exit(1);
	}
	if ((send(socket_fd,Dhatstorage, 65,0))== -1) {
		fprintf(stderr, "Failure Sending Dhatstorage\n");
		close(socket_fd);
		exit(1);
	}

	element_t dhat;
	element_init_G1(dhat, pairing);
	element_from_bytes_compressed(dhat, Dhatstorage);
	//element_printf("Dhatstorage %B\n", dhat);

	if ((send(socket_fd,Dprimestorage, 128,0))== -1) {
		fprintf(stderr, "Failure Sending Dprime\n");
		close(socket_fd);
		exit(1);
	}
	element_t dprime;
	element_init_GT(dprime, pairing);
	element_from_bytes(dprime, Dprimestorage);
	//element_printf("Dprimestorage %B\n", dprime);

	for(i=0;i<ATT_NUM;i++){
		if ((send(socket_fd,Dstorage[i],65,0))== -1) {
			fprintf(stderr, "Failure Sending Dstorage\n");
			close(socket_fd);
			exit(1);
		}
		element_t dstor;
		element_init_G1(dstor, pairing);
		element_from_bytes_compressed(dstor, Dstorage[i]);
		//element_printf("Dstorage[%d] %B\n", i,dstor);
	}


	if ((send(socket_fd,C0hatstorage, 128,0))== -1) {
		fprintf(stderr, "Failure Sending C0hatstorage\n");
		close(socket_fd);
		exit(1);
	}

	element_t c0hatstor;
	element_init_GT(c0hatstor, pairing);
	element_from_bytes(c0hatstor, C0hatstorage);
	//element_printf("C0hatstorage %B\n", c0hatstor);

	if ((send(socket_fd,C0primestorage,65,0))== -1) {
		fprintf(stderr, "Failure Sending C0primestorage\n");
		close(socket_fd);
		exit(1);
	}
	element_t c0primestor;
	element_init_G1(c0primestor, pairing);
	element_from_bytes_compressed(c0primestor, C0primestorage);
	//element_printf("C0primestorage %B\n", c0primestor);

	for(i=0;i<ATT_NUM;i++){
		if ((send(socket_fd,C0storage[i], 65,0))== -1) {
			fprintf(stderr, "Failure Sending C0storage\n");
			close(socket_fd);
			exit(1);
		}
		element_t c0stor;
		element_init_G1(c0stor, pairing);
		element_from_bytes_compressed(c0stor, C0storage[i]);
		//element_printf("C0storage[%d] %B\n", i,c0stor);
	}

	if ((send(socket_fd,C1hatstorage, 128,0))== -1) {
		fprintf(stderr, "Failure Sending C1hatstorage\n");
		close(socket_fd);
		exit(1);
	}
	element_t c1hatstor;
	element_init_GT(c1hatstor, pairing);
	element_from_bytes(c1hatstor, C1hatstorage);
	//element_printf("C1hatstorage received is %B\n", c1hatstor);
	if ((send(socket_fd,C1primestorage, 65,0))== -1) {
		fprintf(stderr, "Failure Sending C1primestorage\n");
		close(socket_fd);
		exit(1);
	}
	element_t c1primestor;
	element_init_G1(c1primestor, pairing);
	element_from_bytes_compressed(c1primestor, C1primestorage);
	//element_printf("C1primestorage %B\n", c1primestor);
	for(i=0;i<ATT_NUM;i++){
		if ((send(socket_fd,C1storage[i], 65,0))== -1) {
			fprintf(stderr, "Failure Sending C1storage\n");
			close(socket_fd);
			exit(1);
		}
		element_t c1stor;
		element_init_G1(c1stor, pairing);
		element_from_bytes_compressed(c1stor, C1storage[i]);
		//element_printf("C1storage[%d] %B\n", i,c1stor);


	}
	int len=strlen(encrypted_file);
	if ((send(socket_fd,(char*)&len, sizeof(int),0))== -1) {
		fprintf(stderr, "Failure Sending Dhat\n");
		close(socket_fd);
		exit(1);
	}
	if ((send(socket_fd,encrypted_file, strlen(encrypted_file),0))<= 0) {
		fprintf(stderr, "Failure Sending Message\n");
		close(socket_fd);
		exit(1);
	}


	if ((send(socket_fd,buffer, strlen(buffer),0))<= 0) {
	      fprintf(stderr, "Failure Sending Message\n");
	      close(socket_fd);
	      exit(1);
	}
	char* reply=malloc(100*sizeof(char));
	memset(reply,0,100);
	num=recv(socket_fd, reply,100,0);
	if ( num <= 0 )
	{
		printf("Either Connection Closed or Error\n");
		return 0;
	}
	printf("Client:Message Received From Server: %s\n",reply);
	close(socket_fd);  

	return 0;
}








