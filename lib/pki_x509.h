#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include "pki_key.h"

#ifndef PKI_X509_H
#define PKI_X509_H

class pki_x509 : public pki_base
{
	   pki_x509 *parent; // the signer
	   bool trust;
	   X509 *cert;
	public:
	   pki_x509(pki_key *key, const string cn, 
		   const string c, const string l,
		   const string st,const string o,
		   const string ou,const string email,
		   const string d, int days=365);
	   pki_x509();
	   pki_x509(const string fname);
	   virtual void fromData(unsigned char *p, int size);
	   virtual unsigned char *toData(int *size);
	   virtual bool compare(pki_base *refcert);
	   string getDNs(int nid);
	   string getDNi(int nid);
	   void writeReq(const string fname, bool PEM);
	   bool verify(pki_x509 *signer);
	   pki_key *getKey();
	   string notAfter();
	   string notBefore();
};

#endif
