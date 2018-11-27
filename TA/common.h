#ifndef COMMON_H
#define COMMON_H
#include </usr/local/include/pbc/pbc.h>
#include </usr/local/include/pbc/pbc_test.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 3490
#define BACKLOG 10

#define ATT_NUM 10 // this is the attribute number in the whole system
#define PARAM_NUM 3*ATT_NUM //this is size of "part of " the public parameters


struct PublicKey //this is the data structure of public key (TA publishes this to the public)
{
  element_t g;//G_1
  element_t Y;//G_T
  element_t T[PARAM_NUM];//G_1
};

/**
 * this is the data structure of master key,
 * TA keeps this key secret to itself
 */
struct MasterKey
{
  element_t y;//Z_r
  element_t t[PARAM_NUM];//Z_r
};

/**
 * this is the data strucuture of a private key
 * it is distributed by TA, each user keeps this 
 * key secret to themself
 */

struct PrivateKey 
{
  //if attribute list could be contained here, then it will be better
  element_t K_hat;
  element_t K[ATT_NUM];
  element_t F[ATT_NUM];
};

//this is 
struct ABECiphertext
{
  int Policy[ATT_NUM];
  element_t C_hat; //G_T
  element_t C_prime; //G_1
  element_t C[ATT_NUM]; //G_1
};

struct ABEAESCiphertext
{
  struct ABECiphertext abeaesciphertext[2];
};
// this is the data structure of an index for each file
struct Index
{
  //the first part of an index
  int Keywords_Num; // the number of keywords in the file
  int Policy[ATT_NUM];
  element_t D_hat;//G_1
  element_t D_prime;//G_T
  element_t D[ATT_NUM];//G_1
  //the second part of an index
  struct ABEAESCiphertext abeaesciphertext;
};

// this is trapdoor data structure
struct Trapdoor 
{
  int AttributeList[ATT_NUM];
  element_t Q_hat; //G1
  element_t Q_prime; //Z_r
  element_t Q[ATT_NUM];//G_1
  element_t Qf[ATT_NUM];//G_1
};

/*
 * The following algorithms are run TA
 */
void SystemSetup( );//run by TA at the system setup phase, run only once
void readMKfromFile(char* filename);//run by TA during the private key genration phase
void ABEKeyGen(int AttributeList[ ], struct PrivateKey* PrivK);//run by TA during the private key genration phase

void readPKfromFile(char* filename, struct PublicKey* PK);//common function run by data owner, data user, metadata server

/*
 * The following algorithms are run by the data owner
 */
void SecretKeyGen(char* filename);//generate the AES key
void FileEncryption(char* PlaintextFile, char* KeyFile, char* CiphertextFile);//encrypt the files with AES
void ABEEncrypt(int Policy[ ], element_t plaintext, struct ABECiphertext* abeciphertext);//ABE encryption algorithm
void SecureIndexGeneration(int Policy[ ], char* keywords[ ]);//generate index for each file

/*
 * The following algorithms are run the data user
 */
void ReadPrivKfromFile(char* filename, struct PrivateKey* PrivK);//get her ABE private key from file
void TrapdoorGeneration(struct PrivateKey PrivK, char* keyword);//genrate trapdoor
void ABEDecrypt(struct ABECiphertext abeciphertext, element_t *m);//ABE decryption algorithm
void ABEFileKeyDecrypt(struct ABEAESCiphertext abeaes, char* keyfilename);//get the AES key
void FileDecryption(char* CiphertextFile, char* KeyFile, char* PlaintextFile);//decrypt the encrytped file         

/*
 * The following algorithm is run by the server
 */
int Search(struct Index ind, struct Trapdoor trapdoor);//run by server

#endif
