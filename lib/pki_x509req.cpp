
#include "pki_x509req.h"


pki_x509req::pki_x509req(pki_key *key, const string cn,
		const string c, const string l,
		const string st,const string o,
		const string ou,const string email, 
		const string d)
		:pki_base( d )
{
	request = X509_REQ_new();
	openssl_error();
	if (key== NULL) {
		cerr << "key ist null\n";
		return;
	}
	openssl_error();
	X509_REQ_set_version(request, 0L);
	openssl_error();
	X509_REQ_set_pubkey(request, key->key);
	openssl_error();
	
	X509_NAME *subj = X509_REQ_get_subject_name(request);
	X509_NAME_add_entry_by_NID(subj,NID_commonName, MBSTRING_ASC,
		(unsigned char*)cn.data(),-1,-1,0);
	X509_NAME_add_entry_by_NID(subj,NID_countryName, MBSTRING_ASC, 
		(unsigned char*)c.data() , -1, -1, 0);
	X509_NAME_add_entry_by_NID(subj,NID_localityName, MBSTRING_ASC, 
		(unsigned char*)l.data() , -1, -1, 0);
	X509_NAME_add_entry_by_NID(subj,NID_stateOrProvinceName, MBSTRING_ASC, 
		(unsigned char*)st.data() , -1, -1, 0);
	X509_NAME_add_entry_by_NID(subj,NID_organizationName, MBSTRING_ASC, 
		(unsigned char*)o.data() , -1, -1, 0);
	X509_NAME_add_entry_by_NID(subj,NID_organizationalUnitName, MBSTRING_ASC, 
		(unsigned char*)ou.data() , -1, -1, 0);
	X509_NAME_add_entry_by_NID(subj,NID_pkcs9_emailAddress, MBSTRING_ASC, 
		(unsigned char*)email.data() , -1, -1, 0);

	const EVP_MD *digest = EVP_md5();
	X509_REQ_sign(request,key->key ,digest);
	openssl_error();
}



pki_x509req::pki_x509req() : pki_base()
{
	request = X509_REQ_new();
	openssl_error();
}


pki_x509req::pki_x509req(const string fname)
{
	FILE *fp = fopen(fname.data(),"r");
	request = NULL;
	if (fp != NULL) {
	   request = PEM_read_X509_REQ(fp, NULL, NULL, NULL);
	   if (!request) {
		openssl_error();
		rewind(fp);
		printf("Fallback to privatekey DER\n"); 
	   	request = d2i_X509_REQ_fp(fp, NULL);
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


void pki_x509req::fromData(unsigned char *p, int size)
{
	request = d2i_X509_REQ(NULL, &p, size);
	openssl_error();
}


string pki_x509req::getDN(int nid)
{
	char buf[200];
	string s;
	X509_NAME *subj = X509_REQ_get_subject_name(request);
	X509_NAME_get_text_by_NID(subj, nid, buf, 200);
	s = buf;
	return s;
}

/*
QStringList *pki_x509req::getDN()
{
#define BUFLEN 200
	X509_NAME_get_text_by_NID(subj,NID_commonName)
	char buf[BUFLEN];
	QString s;
	QStringList *l = new QStringList();
	X509_NAME *subj = X509_REQ_get_subject_name(request);
	X509_NAME_get_text_by_NID(subj,NID_commonName,
			buf, BUFLEN);
	s = buf;
	l->append(s);
	X509_NAME_get_text_by_NID(subj,NID_countryName,
			buf, BUFLEN);
	s = buf;
	l->append(s);
	X509_NAME_get_text_by_NID(subj,NID_stateOrProvinceName,
			buf, BUFLEN);
	s = buf;
	l->append(s);
	X509_NAME_get_text_by_NID(subj,NID_localityName,
			buf, BUFLEN);
	s = buf;
	l->append(s);
	X509_NAME_get_text_by_NID(subj,NID_organizationName,
			buf, BUFLEN);
	s = buf;
	l->append(s);
	X509_NAME_get_text_by_NID(subj,NID_organizationalUnitName,
			buf, BUFLEN);
	s = buf;
	l->append(s);
	X509_NAME_get_text_by_NID(subj,NID_pkcs9_emailAddress,
			buf, BUFLEN);
	s = buf;
	l->append(s);
	
	return l;
}
*/

unsigned char *pki_x509req::toData(int *size)
{
	unsigned char *p, *p1;
	*size = i2d_X509_REQ(request, NULL);
	openssl_error();
	p = (unsigned char*)OPENSSL_malloc(*size);
	p1 = p;
	i2d_X509_REQ(request, &p1);
	openssl_error();
	return p;
}


void pki_x509req::writeReq(const string fname, bool PEM)
{
	FILE *fp = fopen(fname.data(),"w");
	if (fp != NULL) {
	   if (request){
		if (PEM) 
		   PEM_write_X509_REQ(fp, request);
		else
		   i2d_X509_REQ_fp(fp, request);
	        openssl_error();
	   }
	}
	else error = "Fehler beim Öffnen der Datei";
	fclose(fp);
}

bool pki_x509req::compare(pki_x509req *refreq)
{
	const EVP_MD *digest=EVP_md5();
	unsigned char d1[EVP_MAX_MD_SIZE], d2[EVP_MAX_MD_SIZE];	
	unsigned int d1_len,d2_len;
	X509_REQ_digest(request, digest, d1, &d1_len);
	X509_REQ_digest(refreq->request, digest, d2, &d2_len);
	if ((d1_len == d2_len) && 
	    (d1_len >0) &&
	    (memcmp(d1,d2,d1_len) == 0) )return true;
	return false;
}

	
