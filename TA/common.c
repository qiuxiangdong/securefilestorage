#include "common.h"
pairing_t pairing;

void readPKfromFile(char* filename, struct PublicKey* PK)
{
  char s[16384];
  FILE *fp = fopen("./a.param", "r");
  size_t count = fread(s, 1, 16384, fp);
  if (!count) pbc_die("input error");
  fclose(fp);
  //printf("\nstring of parameters is %s\n", s);//output the description of pairing "e"
  if (pairing_init_set_buf(pairing, s, count)) pbc_die("pairing init failed");
  
  //n, m, t is the system parameter, this might be chanaged in real-world application
  //here, we fix these values for simplicity
  int n = 128;
  int m = 65;
  int t = 65;
  
  FILE *fp2;
  fp2 = fopen(filename, "rb");
  if(fp2 ==NULL)
    exit(1);
  
  unsigned char* Ybuffer = malloc(n);
  for(int i = 0; i < n; i++)
    Ybuffer[i] = fgetc(fp2);
  
  unsigned char* gbuffer = malloc(m);
  for(int i = 0; i < m; i++)
    gbuffer[i] = fgetc(fp2);
  
  unsigned char** Tbuffer = malloc(sizeof(unsigned char*)*PARAM_NUM);
  for(int i = 0; i < PARAM_NUM; i++)
    Tbuffer[i] = malloc(t);
  
  for(int j = 0; j < PARAM_NUM; j++)
  {
    for(int i = 0; i < t; i++)
      Tbuffer[j][i] = fgetc(fp2);
  }
  
//  element_t Yreadfrom;
//  element_init_GT(Yreadfrom, pairing);
  //  element_from_bytes(Yreadfrom, Ystorage);

  
//  element_from_bytes(Yreadfrom, Ybuffer);
//  element_printf("Yreadfrom is %B\n", Yreadfrom);
  element_from_bytes(PK->Y, Ybuffer);
  
//  element_from_bytes_compressed(greadfrom, gbuffer);
//  element_printf("greadfrom is %B\n", greadfrom);

  element_from_bytes_compressed(PK->g, gbuffer);

  for(int i = 0; i < PARAM_NUM; i++)
  {
 //   element_from_bytes_compressed(Treadfrom[i], Tbuffer[i]);
  //  element_printf("Tgreadfrom is %B\n", Treadfrom[i]);
     element_from_bytes_compressed(PK->T[i], Tbuffer[i]);
  }
  
  element_printf("PK.Y is %B\n", PK->Y);
  element_printf("PK.g is %B\n", PK->g);
  // printf("%d   %d  %d\n", n, m, t);
  for(int i = 0; i < PARAM_NUM; i++)
    element_printf("PK.T is %B\n", PK->T[i]);
}

void ReadPrivKfromFile(char* filename, struct PrivateKey* PrivK)
{
  char s[16384];
  FILE *fp = fopen("./a.param", "r");
  size_t count = fread(s, 1, 16384, fp);
  if (!count) pbc_die("input error");
  fclose(fp);
  //printf("\nstring of parameters is %s\n", s);//output the description of pairing "e"
  if (pairing_init_set_buf(pairing, s, count)) pbc_die("pairing init failed");
  
  int m = 65;
  FILE *fp2;
  fp2 = fopen(filename, "rb");
  if(fp2 ==NULL)
    exit(1);
  
  unsigned char* khatbuffer = malloc(m);
  for(int i = 0; i < m; i++)
    khatbuffer[i] = fgetc(fp2);
  
  unsigned char** Kbuffer = malloc(sizeof(unsigned char*)*ATT_NUM);
  for(int i = 0; i < ATT_NUM; i++)
    Kbuffer[i] = malloc(m);
  
  for(int j = 0; j < ATT_NUM; j++)
  {
    for(int i = 0; i < m; i++)
      Kbuffer[j][i] = fgetc(fp2);
  }
  
  unsigned char** Fbuffer = malloc(sizeof(unsigned char*)*ATT_NUM);
  for(int i = 0; i < ATT_NUM; i++)
    Fbuffer[i] = malloc(m);
  
  for(int j = 0; j < ATT_NUM; j++)
  {
    for(int i = 0; i < m; i++)
    {
      Fbuffer[j][i] = fgetc(fp2);
      printf("%c\n", Fbuffer[j][i]);
    }
  }

  element_from_bytes_compressed(PrivK->K_hat, khatbuffer);
  element_printf("PrivK.khat readfrom is %B\n", PrivK->K_hat);
  
  for(int i = 0; i < ATT_NUM; i++)
  {
    element_from_bytes_compressed(PrivK->K[i], Kbuffer[i]);
    element_printf("PrivK.K readfrom is %B\n", PrivK->K[i]);
  }
  
  for(int i = 0; i < ATT_NUM; i++)
  {
    element_from_bytes_compressed(PrivK->F[i], Fbuffer[i]);
    element_printf("PrivK.F readefrom is %B\n", PrivK->F[i]);
  }
  
}

/*
int main()
{
  char s[16384];
  FILE *fp = fopen("./a.param", "r");
  size_t count = fread(s, 1, 16384, fp);
  if (!count) pbc_die("input error");
  fclose(fp);
  if (pairing_init_set_buf(pairing, s, count)) pbc_die("pairing init failed");
  
  struct PublicKey PK;
  element_init_GT(PK.Y, pairing);
  
  element_init_G1(PK.g, pairing);

  for(int i = 0; i < PARAM_NUM; i++)
    element_init_G1(PK.T[i], pairing);
  
  readPKfromFile("PK.bin", &PK);
  
  element_printf("PK->Y is %B\n", PK.Y);
  element_printf("PK->g is %B\n", PK.g);
  
  for(int i = 0; i < PARAM_NUM; i++)
    element_printf("PK->T is %B\n", PK.T[i]);
  
  return 0;
}

 */