#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include "pki_key.h"

#ifndef PKI_X509REQ_H
#define PKI_X509REQ_H

class pki_x509req : public pki_base
{
	   X509_REQ *request;
	public:
	   pki_x509req(pki_key *key, const string cn, 
		   const string c, const string l,
		   const string st,const string o,
		   const string ou,const string email,
		   const string d);
	   pki_x509req();
	   pki_x509req(const string fname);
	   virtual void fromData(unsigned char *p, int size);
	   virtual unsigned char *toData(int *size);
	   virtual bool compare(pki_base *refreq);
	   string getDN(int nid);
	   void writeReq(const string fname, bool PEM);
	   int verify();
	   pki_key *getKey();
};

#endif
