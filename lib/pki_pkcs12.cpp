#include "pki_pkcs12.h"


pki_pkcs12::pki_pkcs12(const string d, pki_x509 *acert, pki_key *akey, pem_password_cb *cb):
	pki_base(d)
{
	key = akey;
	cert = acert;
	certstack = sk_X509_new_null();
	pkcs12 = NULL;
	passcb = cb;
	openssl_error();	
}

pki_pkcs12::pki_pkcs12(const string fname, pem_password_cb *cb)
	:pki_base(fname)
{ 
	
}	


pki_pkcs12::~pki_pkcs12()
{
	sk_X509_free(certstack);
	PKCS12_free(pkcs12);
}


void pki_pkcs12::addCaCert(pki_x509 *ca)
{ 
	if (ca == 0) return;
	sk_X509_push(certstack, ca->getCert());
}	

void pki_pkcs12::writePKCS12(const string fname)
{ 
	char pass[30];
	char desc[100];
	strncpy(desc,getDescription().c_str(),100);
	PASS_INFO p;
	string title = "Password for the PKCS#12 bag";
	string description = "Please enter the password to encrypt the PKCS#12 bag.";
	p.title = &title;
	p.description = &description;
	if (!pkcs12) {
		if (cert == NULL || key == NULL) {
			pki_error("No key or no Cert and no pkcs12....");
			return;
		}
		passcb(pass, 30, 0, &p); 
		CERR << desc << key->getKey() << cert->getCert() <<endl;
		CERR << "before PKCS12_create...." <<endl;
		pkcs12 = PKCS12_create(pass, desc, key->getKey(), cert->getCert(), certstack, 0, 0, 0, 0, 0);
		if (openssl_error()) return;
		CERR << "after PKCS12_create...." <<endl;
	}
	FILE *fp = fopen(fname.c_str(),"wb");
	if (fp != NULL) {
	    CERR << "writing PKCS#12" << endl;
            i2d_PKCS12_fp(fp, pkcs12);
            openssl_error();
        }
	else pki_error("Error opening file");
}
