#include <iostream>
#include <string>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/stack.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include "pki_key.h"
#include "pki_x509.h"

#ifndef PKI_PKCS12_H
#define PKI_PKCS12_H



class pki_pkcs12: public pki_base
{
    friend class pki_x509;
    friend class pki_key;
    protected:
	PKCS12 *pkcs12;
	pki_x509 *cert;
	pki_key *key;
	STACK_OF(X509) *certstack;
	pem_password_cb *passcb;
    public:
		
	pki_pkcs12(const string d, pki_x509 *acert, pki_key *akey, pem_password_cb *cb);   
	pki_pkcs12(const string fname, pem_password_cb *cb);
	
	/* destructor */
	~pki_pkcs12();
	void addCaCert(pki_x509 *acert);
	//bool fromData(unsigned char *p, int size);
	//unsigned char *toData(int *size);
	//bool compare(pki_base *ref);
	void writePKCS12(const string fname);
};

#endif
