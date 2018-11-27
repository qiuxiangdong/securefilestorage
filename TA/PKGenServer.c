#include "common.h"
struct MasterKey MK;
struct PublicKey PK;
pairing_t pairing;

unsigned char *Khatstorage;
unsigned char** Kstorage;
unsigned char** Fstorage;
int m;
void readMKfromFile(char* filename)
{
  char s[16384];
  FILE *fp = fopen("./a.param", "r");
  size_t count = fread(s, 1, 16384, fp);
  if (!count) pbc_die("input error");
  fclose(fp);
  if (pairing_init_set_buf(pairing, s, count)) pbc_die("pairing init failed");
  
  int k = 20;
  FILE *fp2;
  fp2 = fopen(filename, "rb");
  if(fp2 ==NULL)
    exit(1);
  
  unsigned char* ybuffer = malloc(k);
  for(int i = 0; i < k; i++)
    ybuffer[i] = fgetc(fp2);
  
  unsigned char** tbuffer = malloc(sizeof(unsigned char*)*PARAM_NUM);
  for(int i = 0; i < PARAM_NUM; i++)
    tbuffer[i] = malloc(k);
  
  for(int j = 0; j < PARAM_NUM; j++)
  {
    for(int i = 0; i < k; i++)
      tbuffer[j][i] = fgetc(fp2);
  }
  
  element_init_Zr(MK.y, pairing);

  for(int i = 0; i < PARAM_NUM; i++)
    element_init_Zr(MK.t[i], pairing);
  
  element_from_bytes(MK.y, ybuffer);
//  element_printf("yreadfrom is %B\n", MK.y);
  
  for(int i = 0; i < PARAM_NUM; i++)
  {
    element_from_bytes(MK.t[i], tbuffer[i]);
  //  element_printf("tgreadfrom is %B\n", MK.t[i]);
  }
}

void ABEKeyGen(int AttributeList[ ], struct PrivateKey* PrivK)
{
  element_init_GT(PK.Y, pairing);
  element_init_G1(PK.g, pairing);
  for(int i = 0; i < PARAM_NUM; i++)
    element_init_G1(PK.T[i], pairing);
  
  readPKfromFile("PK.bin", &PK);
  //element_printf("ABEKeyGen used PK->g %B\n", PK.g);

  element_t r[ATT_NUM];
  element_t r_sum;
  element_init_Zr(r_sum, pairing);
  
  for(int i = 0; i < ATT_NUM; i++)
  {
    element_init_Zr(r[i], pairing);
    element_random(r[i]);
    element_add(r_sum, r_sum, r[i]);
  }
  
  element_t temp;
  element_init_Zr(temp, pairing);
  element_sub(temp, MK.y, r_sum);
  element_pow_zn(PrivK->K_hat, PK.g, temp);
  
  for(int i = 0; i < ATT_NUM; i++)
  {
    if(AttributeList[i] == 1)
    {
      element_div(temp, r[i], MK.t[i]);
      element_pow_zn(PrivK->K[i], PK.g, temp); 
    }
    else
    {
      element_div(temp, r[i], MK.t[ATT_NUM+i]);
      element_pow_zn(PrivK->K[i], PK.g, temp); 
    }
    
    element_div(temp, r[i], MK.t[2*ATT_NUM+i]);
    element_pow_zn(PrivK->F[i], PK.g, temp); 
    
  }
  
  element_clear(temp);
  
  //store the entries into file PrivK.bin
  m = element_length_in_bytes_compressed(PrivK->K_hat);
  
  Khatstorage = malloc(m);
  element_to_bytes_compressed(Khatstorage, PrivK->K_hat);
  
  Kstorage = malloc(sizeof(unsigned char*)*ATT_NUM);
  for(int i = 0; i < ATT_NUM; i++)
    Kstorage[i] = malloc(m);
  for(int i = 0; i < ATT_NUM; i++)
    element_to_bytes_compressed(Kstorage[i], PrivK->K[i]);
  
  Fstorage = malloc(sizeof(unsigned char*)*ATT_NUM);
  for(int i = 0; i < ATT_NUM; i++)
    Fstorage[i] = malloc(m);
  for(int i = 0; i < ATT_NUM; i++)
    element_to_bytes_compressed(Fstorage[i], PrivK->F[i]);
  
//  for(int i = 0; i < ATT_NUM; i++)
 // {
  //  for(int j = 0; j < m; j++)
   //   printf("%c\n", Fstorage[i][j]);
 // }
  
  FILE *fp1;
  fp1 = fopen("PrivK.bin", "w");
  if(fp1 ==NULL)
    exit(1);
  fwrite(Khatstorage, 1, m, fp1);
  for(int i = 0; i < ATT_NUM; i++)
    fwrite(Kstorage[i], 1, m, fp1);
  for(int i = 0; i < ATT_NUM; i++)
    fwrite(Fstorage[i], 1, m, fp1);
  fclose(fp1);
  
}

int main()
{
    struct sockaddr_in server;
    struct sockaddr_in dest;
    int status,socket_fd, client_fd,num;
    socklen_t size;
    char buffer[10240];
    char *buff;
    memset(buffer,0,sizeof(buffer));
    int yes =1;
    if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0))== -1) {
        fprintf(stderr, "Socket failure!!\n");
        exit(1);
    }

    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) 	{
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
	printf("Server: Waiting for client\n");
    if ((listen(socket_fd, BACKLOG))== -1){
        fprintf(stderr, "Listening Failure\n");
        exit(1);
    }
while(1){
   size = sizeof(struct sockaddr_in);
   if ((client_fd = accept(socket_fd, (struct sockaddr *)&dest, &size))==-1 ) {
   	perror("accept");
        exit(1);
   }
   printf("Server: Connection from client %s\n", inet_ntoa(dest.sin_addr));
    while(1) {
	memset(&buffer, 0, sizeof(buffer));
	if ((num = recv(client_fd, buffer, ATT_NUM,0))== -1) {
            perror("recv");
            exit(1);
    	}
	else if (num == 0) {
            printf("Connection closed\n");
            //So I can now wait for another client
            break;
    	}
	buffer[num] = '\0';
	printf("Server:Msg Received %s\n", buffer);                    
        readMKfromFile("MSK.bin");
        struct PrivateKey PrivK;
        char s[16384];
        FILE *fp = fopen("./a.param", "r");
        size_t count = fread(s, 1, 16384, fp);
        if (!count) pbc_die("input error");
             fclose(fp);
	if (pairing_init_set_buf(pairing, s, count))
		pbc_die("pairing init failed");
        element_init_G1(PrivK.K_hat, pairing);
  
	for(int i = 0; i < ATT_NUM; i++)
	{
	    element_init_G1(PrivK.K[i], pairing);
	    element_init_G1(PrivK.F[i], pairing);
  	}
  
	int AttributeList[ATT_NUM];
  	for(int i=0;i<ATT_NUM;i++){
		AttributeList[i]=buffer[i]-48;
	}
	
	ABEKeyGen(AttributeList, &PrivK);
	int i;
	send(client_fd,(char*)&m,sizeof(int),0);
	send(client_fd,Khatstorage,m,0);
	for(i=0;i<ATT_NUM;i++){
		send(client_fd,Kstorage[i],m,0);
//	  	element_printf("PrivK->k[i] is %B\n", PrivK.K[i]);
		free(Kstorage[i]);
	}

	for(i=0;i<ATT_NUM;i++)
		send(client_fd,Fstorage[i],m,0);
	  	//element_printf("PrivK->f[i] is %B\n", PrivK.F[i]);
		free(Fstorage[i]);
  	}

        close(client_fd);
     }
     printf("Private Key sent to File Owner\n");
//   close(socket_fd);
        return 0;
}
