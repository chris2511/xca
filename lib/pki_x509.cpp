
#include "pki_x509.h"


pki_x509::pki_x509(pki_key *key, const string cn,
		const string c, const string l,
		const string st,const string o,
		const string ou,const string email, 
		const string d,int days=365)
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
	if (cn != "")
	X509_NAME_add_entry_by_NID(subj,NID_commonName, MBSTRING_ASC,
		(unsigned char*)cn.c_str(),-1,-1,0);
	if (c != "")
	X509_NAME_add_entry_by_NID(subj,NID_countryName, MBSTRING_ASC, 
		(unsigned char*)c.c_str() , -1, -1, 0);
	if (l != "")
	X509_NAME_add_entry_by_NID(subj,NID_localityName, MBSTRING_ASC, 
		(unsigned char*)l.c_str() , -1, -1, 0);
	if (st != "")
	X509_NAME_add_entry_by_NID(subj,NID_stateOrProvinceName, MBSTRING_ASC, 
		(unsigned char*)st.c_str() , -1, -1, 0);
	if (o != "")
	X509_NAME_add_entry_by_NID(subj,NID_organizationName, MBSTRING_ASC, 
		(unsigned char*)o.c_str() , -1, -1, 0);
	if (ou != "")
	X509_NAME_add_entry_by_NID(subj,NID_organizationalUnitName, MBSTRING_ASC, 
		(unsigned char*)ou.c_str() , -1, -1, 0);
	if (email != "")
	X509_NAME_add_entry_by_NID(subj,NID_pkcs9_emailAddress, MBSTRING_ASC, 
		(unsigned char*)email.c_str() , -1, -1, 0);

	const EVP_MD *digest = EVP_md5();

	/* Set version to V3 */
	if(!X509_set_version(cert, 2)) {
		error="set Version faoiled";
		return;
	}
	ASN1_INTEGER_set(X509_get_serialNumber(cert),0L);

	X509_set_issuer_name(cert,subj);
	X509_gmtime_adj(X509_get_notBefore(cert),0);
	X509_gmtime_adj(X509_get_notAfter(cert), (long)60*60*24*days);

	/* Set up V3 context struct */
	X509V3_CTX ext_ctx;

	X509V3_set_ctx(&ext_ctx, cert, cert, NULL, NULL, 0);

	if (!X509_sign(cert, key->key, digest)) {
		error="Error signing the request";
	}
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
		printf("Fallback to certificate DER\n"); 
	   	cert = d2i_X509_fp(fp, NULL);
	   }
	   int r = fname.rfind('.');
	   int l = fname.rfind('/');
	   desc = fname.substr(l+1,r-l-1);
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


string pki_x509::getDNs(int nid)
{
	char buf[200] = "";
	string s;
	X509_NAME *subj = X509_get_subject_name(cert);
	X509_NAME_get_text_by_NID(subj, nid, buf, 200);
	s = buf;
	return s;
}

string pki_x509::getDNi(int nid)
{
	char buf[200] = "";
	string s;
	X509_NAME *iss = X509_get_issuer_name(cert);
	X509_NAME_get_text_by_NID(iss, nid, buf, 200);
	s = buf;
	return s;
}

string pki_x509::notBefore()
{
	BIO * bio = BIO_new(BIO_s_mem());
	char buf[200] = "";
	ASN1_TIME_print(bio,X509_get_notBefore(cert));
	BIO_gets(bio,buf,200);
	string time = buf;
	BIO_free(bio);
	return time;
}

string pki_x509::notAfter()
{
	BIO * bio = BIO_new(BIO_s_mem());
	char buf[200];
	ASN1_TIME_print(bio,X509_get_notAfter(cert));
	BIO_gets(bio,buf,200);
	string time = buf;
	BIO_free(bio);
	return time;
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

	
int pki_x509::verify()
{
	 EVP_PKEY *pkey = X509_get_pubkey(cert);
	 int ret=0;
	 int i = X509_verify(cert,pkey);
	 if (i<0) ret = pki_base::VERIFY_ERROR;
	 if (i>0) ret = pki_base::VERIFY_SELFSIGNED;
	 if (i==0) ret = pki_base::VERIFY_TRUSTED;
	 /* FIXME: check trusted state.....
	 else {
	   ret = pki_base::VERIFY_ERROR
	   X509_STORE_CTX *csc = X509_STORE_CTX_new();
	   if (csc != NULL) {
	     X509_STORE_CTX_init(csc,ctx,x,uchain);
	     //if(tchain) X509_STORE_CTX_trusted_stack(csc, tchain);
	     //if(purpose >= 0) X509_STORE_CTX_set_purpose(csc, purpose);
	     //if(issuer_checks)
	     //	X509_STORE_CTX_set_flags(csc, X509_V_FLAG_CB_ISSUER_CHECK);
	     i=X509_verify_cert(csc);
	     X509_STORE_CTX_free(csc);
	 }
	 */
	 EVP_PKEY_free(pkey);
	 openssl_error();
	 return ret;
}

pki_key *pki_x509::getKey()
{
	 EVP_PKEY *pkey = X509_get_pubkey(cert);
	 pki_key *key = new pki_key("");	
	 key->key=pkey;
	 key->onlyPubKey=true;
	 return key;
}
