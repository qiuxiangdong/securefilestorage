#include "common.h"
struct MasterKey MK;
struct PublicKey PK;
pairing_t pairing;

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
  element_printf("yreadfrom is %B\n", MK.y);
  
  for(int i = 0; i < PARAM_NUM; i++)
  {
    element_from_bytes(MK.t[i], tbuffer[i]);
    element_printf("tgreadfrom is %B\n", MK.t[i]);
  }
}

void ABEKeyGen(int AttributeList[ ], struct PrivateKey* PrivK)
{
  element_init_GT(PK.Y, pairing);
  element_init_G1(PK.g, pairing);
  for(int i = 0; i < PARAM_NUM; i++)
    element_init_G1(PK.T[i], pairing);
  
  readPKfromFile("PK.bin", &PK);
  element_printf("ABEKeyGen used PK->g %B\n", PK.g);

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
  int m = element_length_in_bytes_compressed(PrivK->K_hat);
  element_printf("PrivK->K_hat is %B\n", PrivK->K_hat);
  
  printf("%d \n",m);
  for(int i = 0; i < ATT_NUM; i++)
    element_printf("PrivK.K is %B\n", PrivK->K[i]);
  for(int i = 0; i < ATT_NUM; i++)
    element_printf("PrivK.F is %B\n", PrivK->F[i]);
  
  unsigned char *Khatstorage = malloc(m);
  element_to_bytes_compressed(Khatstorage, PrivK->K_hat);
  
  unsigned char** Kstorage = malloc(sizeof(unsigned char*)*ATT_NUM);
  for(int i = 0; i < ATT_NUM; i++)
    Kstorage[i] = malloc(m);
  for(int i = 0; i < ATT_NUM; i++)
    element_to_bytes_compressed(Kstorage[i], PrivK->K[i]);
  
  unsigned char** Fstorage = malloc(sizeof(unsigned char*)*ATT_NUM);
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
  readMKfromFile("MSK.bin");
  struct PrivateKey PrivK;
  char s[16384];
  FILE *fp = fopen("./a.param", "r");
  size_t count = fread(s, 1, 16384, fp);
  if (!count) pbc_die("input error");
  fclose(fp);
  if (pairing_init_set_buf(pairing, s, count)) pbc_die("pairing init failed");
  element_init_G1(PrivK.K_hat, pairing);
  
  for(int i = 0; i < ATT_NUM; i++)
  {
    element_init_G1(PrivK.K[i], pairing);
    element_init_G1(PrivK.F[i], pairing);
  }
  
  int AttributeList[ATT_NUM];
  for(int i = 0; i < ATT_NUM; i++)
    AttributeList[i] = 0;//0 denotes not care
  AttributeList[0] = 1;
  AttributeList[3] = 1;
  AttributeList[9] = 1;

  ABEKeyGen(AttributeList, &PrivK);
  
  return 0;
}

