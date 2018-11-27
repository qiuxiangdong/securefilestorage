#include "common.h"

/**
 * store the public paramgter and master secret key into files
 * the public parameters and the file a.param will be distributed
 * to each user in the system (including users and the server)
 * the master secret key will be kept secret to TA, used to generate
 * private key for each users. The public key will be stored in file
 * PK.bin, the master secret key will be stored in file MSK.bin
 */
void SystemSetup()
{
  //initialize the public parameter "e", which is the pairing used in the whole system
  struct PublicKey PK;
  struct MasterKey MK;
  pairing_t pairing;
  char s[16384];
  FILE *fp = fopen("./a.param", "r");
  size_t count = fread(s, 1, 16384, fp);
  if (!count) pbc_die("input error");
  fclose(fp);
  //printf("\nstring of parameters is %s\n", s);//output the description of pairing "e"
  if (pairing_init_set_buf(pairing, s, count)) pbc_die("pairing init failed");
  
  //generate public parameter g
  element_init_G1(PK.g, pairing);
  element_random(PK.g);
  
  //generate value of y in the master secret key
  element_init_Zr(MK.y, pairing);
  element_random(MK.y);
  
  //generate value of Y in the public key
  element_init_GT(PK.Y, pairing);
  element_t temp;
  element_init_GT(temp, pairing);
  pairing_apply(temp, PK.g, PK.g, pairing);
  element_pow_zn(PK.Y, temp, MK.y);
  element_clear(temp);
  
  //generate value of t and T in master secret key and public key respectively
  for(int i = 0; i < PARAM_NUM; i++)
  {
    element_init_Zr(MK.t[i], pairing);
    element_random(MK.t[i]);
    element_init_G1(PK.T[i], pairing);
    element_pow_zn(PK.T[i], PK.g, MK.t[i]);
  }
  
  //store public parameters into the file PK.bin
  int n = element_length_in_bytes(PK.Y);
  int m = element_length_in_bytes_compressed(PK.g);
  int t = element_length_in_bytes_compressed(PK.T[0]);
  element_printf("PK.Y is %B\n", PK.Y);
  element_printf("PK.g is %B\n", PK.g);
  // printf("%d   %d  %d\n", n, m, t);
  for(int i = 0; i < PARAM_NUM; i++)
    element_printf("PK.T is %B\n", PK.T[i]);
  
  unsigned char *Ystorage = malloc(n);
  unsigned char *gstorage = malloc(m);
  unsigned char** Tstorage = malloc(sizeof(unsigned char*)*PARAM_NUM);
  for(int i = 0; i < PARAM_NUM; i++)
    Tstorage[i] = malloc(t);
  
  element_to_bytes(Ystorage, PK.Y);
  element_to_bytes_compressed(gstorage, PK.g);

  for(int i = 0; i < PARAM_NUM; i++)
    element_to_bytes_compressed(Tstorage[i], PK.T[i]);
  
  FILE *fp1;
  fp1 = fopen("PK.bin", "w");
  if(fp1 ==NULL)
    exit(1);
  fwrite(Ystorage, 1, n, fp1);
  fwrite(gstorage, 1, m, fp1);
  for(int i = 0; i < PARAM_NUM; i++)
    fwrite(Tstorage[i], 1, t, fp1);
  fclose(fp1);
  
  //store master secret key into the file MSK.bin
  int k = element_length_in_bytes(MK.y);
  printf("\n k is %d\n", k);
  element_printf("MK.y is %B\n", MK.y);
  for(int i = 0; i < PARAM_NUM; i++)
    element_printf("MK.t is %B\n", MK.t[i]);
  
  unsigned char *ystorage = malloc(k);
  unsigned char** tstorage = malloc(sizeof(unsigned char*)*PARAM_NUM);
  for(int i = 0; i < PARAM_NUM; i++)
    tstorage[i] = malloc(k);
  
  element_to_bytes(ystorage, MK.y);
  for(int i = 0; i < PARAM_NUM; i++)
    element_to_bytes(tstorage[i], MK.t[i]);
  
  FILE *fp2;
  fp2 = fopen("MSK.bin", "w");
  if(fp2 ==NULL)
    exit(1);
  fwrite(ystorage, 1, k, fp2);
  for(int i = 0; i < PARAM_NUM; i++)
    fwrite(tstorage[i], 1, k, fp2);
  fclose(fp2);
  
}

int main()
{
  SystemSetup();
  return 0;
}

