#include <iostream>
#include <string>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include "pki_base.h"

#ifndef PKI_KEY_H
#define PKI_KEY_H

#define MAX_KEY_LENGTH 4096


class pki_key: private pki_base
{
    friend class pki_x509req;
    protected:
	EVP_PKEY *key;
	bool onlyPubKey;
	string BN2string(BIGNUM *bn);
    public:
		
	/* constructor to generate a key .....
	 * d     is the description
	 * bits  is the keylength in bits
	 * cb    a callback for e.g. a progress bar
	 */ 
	pki_key(const string d, void (*cb)(int, int,void *),void *prog,int bits,int type = EVP_PKEY_RSA);   
	
	/* constructor to load a key from a file
	 * fname    = filename
	 * pem_password_cb = password callback function
	 */
	pki_key(const string fname, pem_password_cb *cb,int type=EVP_PKEY_RSA);
	
	/* destructor */
	~pki_key();
	
	/* constructor from database 
	 * p = pointer to data
	 * size = size of datastruct
	 */
	virtual void fromData(unsigned char *p, int size);
	virtual unsigned char *toData(int *size);
	virtual bool compare(pki_key *refkey);
        string length();
        string modulus();
        string pubEx();
        string privEx();
	void writeKey(const string fname, EVP_CIPHER *enc, 
			pem_password_cb *cb, bool PEM);
	void writePublic(const string fname, bool PEM);
	void writePKCS8(const string fname, pem_password_cb *cb);
	bool isPrivKey();
	bool isPubKey();
};

#endif
