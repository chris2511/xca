#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include "pki_key.h"
#include "pki_x509req.h"

#ifndef PKI_X509_H
#define PKI_X509_H

class pki_x509 : public pki_base
{
	private:
	   bool trust;
	   X509 *cert;
	   pki_x509 *psigner;
	   pki_x509 *pkey;
	public:
	   pki_x509(string d, pki_x509req *req, pki_x509 *signer, pki_key* signkey, int days, int serial);
	   pki_x509();
	   pki_x509(const string fname);
	   virtual bool fromData(unsigned char *p, int size);
	   virtual unsigned char *toData(int *size);
	   virtual bool compare(pki_base *refcert);
	   string getDNs(int nid);
	   string getDNi(int nid);
	   void writeCert(const string fname, bool PEM);
	   bool verify(pki_x509 *signer);
	   pki_key *getKey();
	   string notAfter();
	   string notBefore();
	   pki_x509 *getSigner();
	   void delSigner();
	   string fingerprint(EVP_MD *digest);
	   string printV3ext();
	   int checkDate();
};

#endif
