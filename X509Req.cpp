
#include "X509Req.h"
#include <iostream.h>


X509Req::X509Req(RSAkey *key, const char *cn,
		const char *c, const char *l,
		const char *st,const char *o,
		const char *ou,const char *email, 
		QObject *parent, const char *name = 0)
		:QObject( parent, name)
{
	request = X509_REQ_new();
	openssl_error();
	if (key== NULL) {
		cerr << "key ist null\n";
		return;
	}
	EVP_PKEY *pkey = key->evpkey();
	openssl_error();
	X509_REQ_set_version(request, 0L);
	openssl_error();
	cerr << "HIIIIEEER\n";
	openssl_error();
	X509_REQ_set_pubkey(request, pkey);
	cerr << "HIER\n";
	cerr << "ende...\n";
	openssl_error();
	
	X509_NAME *subj = X509_REQ_get_subject_name(request);
	X509_NAME_add_entry_by_NID(subj,NID_commonName, MBSTRING_ASC,
		(unsigned char*)cn,-1,-1,0);
	X509_NAME_add_entry_by_NID(subj,NID_countryName, MBSTRING_ASC, 
		(unsigned char*)c , -1, -1, 0);
	X509_NAME_add_entry_by_NID(subj,NID_localityName, MBSTRING_ASC, 
		(unsigned char*)l , -1, -1, 0);
	X509_NAME_add_entry_by_NID(subj,NID_stateOrProvinceName, MBSTRING_ASC, 
		(unsigned char*)st , -1, -1, 0);
	X509_NAME_add_entry_by_NID(subj,NID_organizationName, MBSTRING_ASC, 
		(unsigned char*)o , -1, -1, 0);
	X509_NAME_add_entry_by_NID(subj,NID_organizationalUnitName, MBSTRING_ASC, 
		(unsigned char*)ou , -1, -1, 0);
	X509_NAME_add_entry_by_NID(subj,NID_pkcs9_emailAddress, MBSTRING_ASC, 
		(unsigned char*)email , -1, -1, 0);

	const EVP_MD *digest=EVP_md5();
	X509_REQ_sign(request,pkey,digest);
	openssl_error();
	FILE *fp = fopen("request.pem","w");
	PEM_write_X509_REQ(fp,request);
	fclose(fp); 
}


X509Req::X509Req(unsigned char *p, int size)
{
	request = d2i_X509_REQ(NULL, &p, size);
	openssl_error();
}

		
QString X509Req::description()
{
	return desc;
}


void X509Req::setDescription(QString d)
{
	desc=d;
}

unsigned char *X509Req::getReq(int *size)
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


char *X509Req::getError()
{
	char *x = error;
	error = NULL;
	return x;
}


	
char *X509Req::openssl_error()
{
	error = NULL;
	char *errtxt = NULL;
	while (int i = ERR_get_error() ) {
	   errtxt = ERR_error_string(i ,NULL);
	   if (errtxt) {
		fprintf(stderr, "OpenSSL: %s\n", errtxt);
	   }
	   error = errtxt;
	}
	return error;
}



X509Req::X509Req(QString fname)
{
	FILE *fp = fopen(fname.latin1(),"r");
	request = NULL;
	if (fp != NULL) {
	   request = PEM_read_X509_REQ(fp, NULL, NULL, NULL);
	   if (!request) {
		openssl_error();
		rewind(fp);
		printf("Fallback to privatekey DER\n"); 
	   	request = d2i_X509_REQ_fp(fp, NULL);
	   }
	   int r = fname.findRev('.',-4);
	   int l = fname.findRev('/');
	   desc = fname.mid(l+1,r-l-1);
	   if (desc.isEmpty()) desc=fname;
	   openssl_error();
	}	
	else error = "Fehler beim Öffnen der Datei";
	fclose(fp);
}

/*
	FILE *fp = fopen("request.pem","w");
	PEM_write_X509_REQ(fp,request);
	fclose(fp); 
*/

