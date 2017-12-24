#include "secure.h"

void handleErrors(void) {
	ERR_print_errors_fp(stderr);
	abort();
}

void secure_init()
{
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
}

void secure_cleanup(unsigned char *ek, unsigned char *iv)
{
	if (ek)
		OPENSSL_free(ek);
	if (iv)
		OPENSSL_free(iv);
}

//passed in:	plain, plainlen, key, (keylen)
//passed out:	enc, enclen, ek, eklen, iv, ivlen
void encrypt(const unsigned char *plain, int plainlen, unsigned char *enc, int *enclen, const unsigned char *key, int keylen, unsigned char **ek, int *ekl, unsigned char **iv, int *ivl)
{
	EVP_PKEY *rkey;
	RSA *rsa;
	const unsigned char *p = key;
	
	if(!(rsa = d2i_RSAPublicKey(NULL, &p, keylen)))
		handleErrors();
	
	if(!(rkey = EVP_PKEY_new()))
		handleErrors();
	
	if (1 != (EVP_PKEY_assign_RSA(rkey, RSAPublicKey_dup(rsa))))
		handleErrors();
	
	RSA_free(rsa);
	
	/*		encrypt msg			*/
	*ek = OPENSSL_malloc(EVP_PKEY_size(rkey));
	*iv = OPENSSL_malloc(EVP_MAX_IV_LENGTH);
	memset(*iv, 0, EVP_MAX_IV_LENGTH);
	*ekl = 0;
	*ivl = EVP_MAX_IV_LENGTH;
	
	*enclen = sec_seal(&rkey, ek, ekl, plain, plainlen, *iv, enc);
}

int sec_seal(EVP_PKEY **key, unsigned char **ek, int *ekl, const unsigned char *msg, int msglen, unsigned char *iv, unsigned char *emsg)
{
	EVP_CIPHER_CTX *ctx;
	int emsglen;
	int len;
	
	if (!(ctx = EVP_CIPHER_CTX_new())) 
		handleErrors();
	
	if (1 != EVP_SealInit(ctx, EVP_aes_256_cbc(), ek, 
		ekl, iv, key, 1))
		handleErrors();
	
	if (1 != EVP_SealUpdate(ctx, emsg, &len, msg, msglen))
		handleErrors();
	emsglen = len;
	
	if (1 != EVP_SealFinal(ctx, emsg + len, &len))
		handleErrors();
	emsglen += len;
	
	EVP_CIPHER_CTX_free(ctx);
	/*
	printf("\n\n\tAfter seal:\n");
	print("message: ", emsg, emsglen);
	print("iv: ", iv, sizeof(iv));
	print("encrypted key: ", *ek, *ekl);
	*/
	return emsglen;
}

//passed in:	enc, enclen, key, (keylen), ek, eklen, plain
//passed out:	enc, enclen
//returned:		plainlen
int decrypt(unsigned char *plain, unsigned char *enc, int enclen, unsigned char *ek, int ekl, unsigned char *iv)
{
	int keylen;
	unsigned char *key = NULL;
	EVP_PKEY *lkey;
	RSA *rsa;
	
	
	keylen = loadKey(&key, 1);
	const unsigned char *p = key;
	if(!(rsa = d2i_RSAPrivateKey(NULL, &p, keylen)))
		handleErrors();
	
	if(!(lkey = EVP_PKEY_new()))
		handleErrors();
	if (1 != (EVP_PKEY_assign_RSA(lkey, RSAPrivateKey_dup(rsa))))
		handleErrors();
	RSA_free(rsa);
	
	int plainlen = sec_open(lkey, ek, ekl, plain, iv, enc, enclen);
	//printf("msg: %s\n", plain);
	
	if (plainlen < 2048) {
		plain[plainlen] = '\0';
	}
	
	return plainlen;
}

int sec_open(EVP_PKEY *key, unsigned char *ek, int ekl, unsigned char *msg, unsigned char *iv, const unsigned char *emsg, int emsglen)
{
	
	EVP_CIPHER_CTX *ctx;
	int len;
	int msglen;
	
	if (!(ctx = EVP_CIPHER_CTX_new())) 
		handleErrors();
	
	if (1 != EVP_OpenInit(ctx, EVP_aes_256_cbc(), ek, 
		ekl, iv, key))
		handleErrors();
	
	if (1 != EVP_OpenUpdate(ctx, msg, &len, emsg, emsglen))
		handleErrors();
	msglen = len;
	
	if (1 != EVP_OpenFinal(ctx, msg + len, &len))
		handleErrors();
	msglen += len;
	
	EVP_CIPHER_CTX_free(ctx);
	
	return msglen;
}


int loadKey(unsigned char **key, int num)
{
	FILE *fp;
	unsigned char buf[4];
	int buflen;
	int keylen;
	int c;
	int count = 0;
	if ((fp = fopen(".keys", "r"))) {			//keys have already been generated; use those
		do
		{
            printf("Opened .keys file! \n");
			memset(buf, 0, 4);
            printf("Set buffer to 0\n");
            
            //printf("%s\n", *key);
            
			if (!key && *key) {
				OPENSSL_free(*key);
			}
            printf("key was freed successfully if necessary \n");
			c = fread(buf, 1, 4, fp);
			keylen = strtol(buf, 0, 10);
            printf("File was read, keylen extracted \n");
			*key = OPENSSL_malloc(sizeof(unsigned char) * keylen);
            printf("memory was allocated\n");
			c = fread(*key, keylen, 1, fp);
            printf("Key was read into memory\n");
			count++;
		} while (count <= num);
	}
	else if ((fp = fopen(".keys", "w"))) {		//no .keys file found; make new keys
		RSA *rsa = NULL;
		if (!(rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL)))
			handleErrors();
		
		unsigned char *tmpkey;
		int tmpkeylen;
		
		if (!num) {
			keylen = writeKey(rsa, fp, key, &i2d_RSAPublicKey);
			tmpkeylen = writeKey(rsa, fp, &tmpkey, &i2d_RSAPrivateKey);
		}
		else {
			tmpkeylen = writeKey(rsa, fp, &tmpkey, &i2d_RSAPublicKey);
			keylen = writeKey(rsa, fp, key, &i2d_RSAPrivateKey);
		}
		RSA_free(rsa);
	} else handleErrors();
	
	fclose(fp);
	return keylen;
}

int writeKey(RSA *rsa, FILE *fp, unsigned char **key, int (*i2d_TYPE)(const RSA*,unsigned char **pp))
{
	unsigned char buf[4];
	int buflen;
	int c;
	
	int keylen;
	keylen = i2d_TYPE(rsa, NULL);
	*key = OPENSSL_malloc(keylen);
	unsigned char *tmpkey = *key;
	i2d_TYPE(rsa, &tmpkey);
	
	int i;
	buflen = sprintf(buf, "%d", keylen);
	for (i = 4; i > buflen; i--) {
		buf[i-1] = '\0';
	}
	c = fwrite(buf, 1, 4, fp);
	c = fwrite(*key, keylen, 1, fp);
	return keylen;
}

void print(const char* name, const unsigned char* msg, int len)
{
	printf("%s size: %d\n", name, len);
	printf("%s value:    ", name);
	int i;
    for(i=0; i < len; i++)
        printf("%02X", msg[i]);
    printf("\n");
}
