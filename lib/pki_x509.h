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
	   pki_x509 *psigner;
	   pki_x509 *pkey;
           X509V3_CTX ext_ctx;
	   X509 *cert;
	   ASN1_TIME *revoked;
	   int trust;
	   bool efftrust;
	public:
	   pki_x509(string d, pki_x509req *req, pki_x509 *signer, int days, int serial);
	   pki_x509();
	   pki_x509(const string fname);
	   ~pki_x509();
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
	   string revokedAt();
	   string asn1TimeToString(ASN1_TIME *a);
	   pki_x509 *getSigner();
	   void delSigner();
	   string fingerprint(EVP_MD *digest);
	   string printV3ext();
	   string getSerial();
	   int checkDate();
	   void addV3ext(int nid, string exttext);
	   void sign(pki_key *signkey);
	   X509 *getCert(){ return cert;}
	   int getTrust();
	   void setTrust(int t);
	   bool getEffTrust();
	   void setEffTrust(bool t);
	   void setRevoked(bool rev);
	   bool isRevoked();
};

#endif
