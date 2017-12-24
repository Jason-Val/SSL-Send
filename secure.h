#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <string.h>

void encrypt(const unsigned char *plain, int plainlen, unsigned char *enc, int *enclen, const unsigned char *key, int keylen, unsigned char **ek, int *ekl, unsigned char **iv, int *ivl);

void secure_init();
void secure_cleanup(unsigned char *ek, unsigned char *iv);

int sec_seal(EVP_PKEY **key, unsigned char **ek, int *ekl, const unsigned char *msg, int msglen, unsigned char *iv, unsigned char *emsg);

int loadKey(unsigned char **key, int num);
int writeKey(RSA *rsa, FILE *fp, unsigned char **key, int (*i2d_TYPE)(const RSA*,unsigned char **pp));

void print(const char* name, const unsigned char* msg, int len);

int decrypt(unsigned char *plain, unsigned char *enc, int enclen, unsigned char *ek, int ekl, unsigned char *iv);

int sec_open(EVP_PKEY *key, unsigned char *ek, int ekl, unsigned char *msg, unsigned char *iv, const unsigned char *emsg, int emsglen);
