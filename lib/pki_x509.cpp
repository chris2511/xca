
#include "pki_x509.h"


pki_x509::pki_x509(pki_key *key, const string cn,
		const string c, const string l,
		const string st,const string o,
		const string ou,const string email, 
		const string d)
		:pki_base( d )
{
	cert = X509_new();
	openssl_error();
	if (key== NULL) {
		cerr << "key ist null\n";
		return;
	}
	openssl_error();
	X509_set_version(cert, 0L);
	openssl_error();
	X509_set_pubkey(cert, key->key);
	openssl_error();
	
	X509_NAME *subj = X509_get_subject_name(cert);
	X509_NAME_add_entry_by_NID(subj,NID_commonName, MBSTRING_ASC,
		(unsigned char*)cn.c_str(),-1,-1,0);
	X509_NAME_add_entry_by_NID(subj,NID_countryName, MBSTRING_ASC, 
		(unsigned char*)c.c_str() , -1, -1, 0);
	X509_NAME_add_entry_by_NID(subj,NID_localityName, MBSTRING_ASC, 
		(unsigned char*)l.c_str() , -1, -1, 0);
	X509_NAME_add_entry_by_NID(subj,NID_stateOrProvinceName, MBSTRING_ASC, 
		(unsigned char*)st.c_str() , -1, -1, 0);
	X509_NAME_add_entry_by_NID(subj,NID_organizationName, MBSTRING_ASC, 
		(unsigned char*)o.c_str() , -1, -1, 0);
	X509_NAME_add_entry_by_NID(subj,NID_organizationalUnitName, MBSTRING_ASC, 
		(unsigned char*)ou.c_str() , -1, -1, 0);
	X509_NAME_add_entry_by_NID(subj,NID_pkcs9_emailAddress, MBSTRING_ASC, 
		(unsigned char*)email.c_str() , -1, -1, 0);

	const EVP_MD *digest = EVP_md5();
	X509_sign(cert, key->key, digest);
	openssl_error();
}



pki_x509::pki_x509() : pki_base()
{
	cert = X509_new();
	openssl_error();
}


pki_x509::pki_x509(const string fname)
{
	FILE *fp = fopen(fname.c_str(),"r");
	cert = NULL;
	if (fp != NULL) {
	   cert = PEM_read_X509(fp, NULL, NULL, NULL);
	   if (!cert) {
		openssl_error();
		rewind(fp);
		printf("Fallback to private key DER\n"); 
	   	cert = d2i_X509_fp(fp, NULL);
	   }
	   int r = fname.rfind('.');
	   int l = fname.rfind('/');
	   desc = fname.substr(l,r);
	   if (desc == "") desc = fname;
	   openssl_error();
	}	
	else error = "Fehler beim Öffnen der Datei";
	fclose(fp);
}


void pki_x509::fromData(unsigned char *p, int size)
{
	cert = d2i_X509(NULL, &p, size);
	openssl_error();
}


string pki_x509::getDN(int nid)
{
	char buf[200];
	string s;
	X509_NAME *subj = X509_get_subject_name(cert);
	X509_NAME_get_text_by_NID(subj, nid, buf, 200);
	s = buf;
	return s;
}


unsigned char *pki_x509::toData(int *size)
{
	unsigned char *p, *p1;
	*size = i2d_X509(cert, NULL);
	openssl_error();
	p = (unsigned char*)OPENSSL_malloc(*size);
	p1 = p;
	i2d_X509(cert, &p1);
	openssl_error();
	return p;
}


void pki_x509::writeReq(const string fname, bool PEM)
{
	FILE *fp = fopen(fname.c_str(),"w");
	if (fp != NULL) {
	   if (cert){
		if (PEM) 
		   PEM_write_X509(fp, cert);
		else
		   i2d_X509_fp(fp, cert);
	        openssl_error();
	   }
	}
	else error = "Fehler beim Öffnen der Datei";
	fclose(fp);
}

bool pki_x509::compare(pki_base *refreq)
{
	const EVP_MD *digest=EVP_md5();
	unsigned char d1[EVP_MAX_MD_SIZE], d2[EVP_MAX_MD_SIZE];	
	unsigned int d1_len,d2_len;
	X509_digest(cert, digest, d1, &d1_len);
	X509_digest(((pki_x509 *)refreq)->cert, digest, d2, &d2_len);
	if ((d1_len == d2_len) && 
	    (d1_len >0) &&
	    (memcmp(d1,d2,d1_len) == 0) )return true;
	return false;
}

	
bool pki_x509::verify()
{
	 EVP_PKEY *pkey = X509_get_pubkey(cert);
	 bool x = (X509_verify(cert,pkey) <= 0);
	 EVP_PKEY_free(pkey);
	 return x;
}

pki_key *pki_x509::getKey()
{
	 EVP_PKEY *pkey = X509_get_pubkey(cert);
	 pki_key *key = new pki_key("");	
	 key->key=pkey;
	 key->onlyPubKey=true;
	 return key;
}
