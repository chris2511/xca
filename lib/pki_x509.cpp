
#include "pki_x509.h"


pki_x509::pki_x509(string d, pki_x509req *req, pki_x509 *signer, int days, int serial)
		:pki_base( d )
{
	X509_NAME *issn, *reqn;
	if (!req) return ;	
	if ((cert = X509_new()) == NULL) return ;
	if (signer) {
  		issn = X509_get_subject_name(signer->cert);
	}
	else {
  		issn = X509_REQ_get_subject_name(req->request);
	}
	
	// copy Requestinfo to New cert
	
	X509_set_pubkey(cert, X509_REQ_get_pubkey(req->request));
  	reqn = X509_REQ_get_subject_name(req->request);
        X509_set_subject_name(cert, X509_NAME_dup(reqn));
        X509_set_issuer_name(cert, X509_NAME_dup(issn));
	
	/* Set version to V3 */
	X509_set_version(cert, 2);
	if (openssl_error()) return;
	
	ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);

	X509_gmtime_adj(X509_get_notBefore(cert),0);
	X509_gmtime_adj(X509_get_notAfter(cert), (long)60*60*24*days);
	if (signer == NULL) // selfsigned....
		signer=this;

	/* Set up V3 context struct */
	X509V3_set_ctx(&ext_ctx, signer->cert, cert, req->request, NULL, 0);

	trust = true;
	psigner = signer;
}


pki_x509::pki_x509() : pki_base()
{
	cert = X509_new();
	openssl_error();
	psigner = NULL;
	trust = false;
}

pki_x509::~pki_x509()
{
	X509_free(cert);
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
	else pki_error("Error opening file");
	fclose(fp);
	trust = false;
	psigner = NULL;
}


void pki_x509::addV3ext(int nid, string exttext)
{	
	X509_EXTENSION *ext;
	char c[200];
	if (exttext == "") return;
	strncpy(c, exttext.c_str(), 200);
	ext =  X509V3_EXT_conf_nid(NULL, &ext_ctx, nid, c);
	X509_add_ext(cert, ext, -1);
	X509_EXTENSION_free(ext);
}

	
	
void pki_x509::sign(pki_key *signkey)
{
	const EVP_MD *digest = EVP_md5();
	X509_sign(cert, signkey->key, digest);
	openssl_error();
}

	
bool pki_x509::fromData(unsigned char *p, int size)
{
	cert = d2i_X509(NULL, &p, size);
	if (openssl_error()) return false;
	return true;
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


void pki_x509::writeCert(const string fname, bool PEM)
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
	else pki_error("Error opening the file");
	fclose(fp);
}

bool pki_x509::compare(pki_base *refreq)
{
	if (!X509_cmp(cert, ((pki_x509 *)refreq)->cert))
		return true;
	return false;
}

	
bool pki_x509::verify(pki_x509 *signer)
{
	if (psigner == signer) return true;
	if ((psigner != NULL )||( signer == NULL)) return false;
	X509_NAME *subject =  X509_get_subject_name(signer->cert);
	X509_NAME *issuer = X509_get_issuer_name(cert);
	openssl_error();
	if (X509_NAME_cmp(subject, issuer)) {
		return false;
	}
	EVP_PKEY *pkey = X509_get_pubkey(signer->cert);
	int i = X509_verify(cert,pkey);
	openssl_error();
	if (i>0) {
		cerr << "psigner set for: " << getDescription().c_str() << endl;
		psigner = signer;
		return true;
	}
	return false;
}


pki_key *pki_x509::getKey()
{
	EVP_PKEY *pkey = X509_get_pubkey(cert);
	pki_key *key = new pki_key(pkey);	
	return key;
}



string pki_x509::fingerprint(EVP_MD *digest)
{
	 int j;
	 string fp="";
	 char zs[4];
         unsigned int n;
         unsigned char md[EVP_MAX_MD_SIZE];
         X509_digest(cert, digest, md, &n);
	 if (openssl_error()) return fp;
         for (j=0; j<(int)n; j++)
         {
              sprintf(zs, "%02X%c",md[j], (j+1 == (int)n) ?'\0':':');
	      fp += zs;
         }
	 return fp;
}


int pki_x509::checkDate()
{
	time_t tnow = time(NULL);
	if (ASN1_UTCTIME_cmp_time_t(X509_get_notAfter(cert), tnow) == -1)
		return -1;
	if (ASN1_UTCTIME_cmp_time_t(X509_get_notBefore(cert), tnow) == -1)
	 	return 0;
	else 
		return 1;
}


pki_x509 *pki_x509::getSigner() { return (psigner); }


void pki_x509::delSigner() { psigner=NULL; }

string pki_x509::printV3ext()
{
	ASN1_OBJECT *obj;
	BIO *bio = BIO_new(BIO_s_mem());
	int i, len, n = X509_get_ext_count(cert);
	char buffer[200];
	X509_EXTENSION *ex;
	string text="";
	for (i=0; i<n; i++) {
		text += "<b><u>";
		ex = X509_get_ext(cert,i);
		obj = X509_EXTENSION_get_object(ex);
		len = i2t_ASN1_OBJECT(buffer, 200, obj);
		buffer[len] = '\0';
		text+=buffer;
		text+=": ";
		if (X509_EXTENSION_get_critical(ex))
			text += " <font color=\"red\">critical</font>:";
		if(!X509V3_EXT_print(bio, ex, 0, 0))
			M_ASN1_OCTET_STRING_print(bio,ex->value);
        		len = BIO_read(bio, buffer, 200);
		text+="</u></b><br><tt>";
		buffer[len] = '\0';
		text+=buffer;
		text+="</tt><br>";
	}
	BIO_free(bio);
	openssl_error();
	return text;
}

string pki_x509::getSerial()
{
	char buf[100];
	BIO *bio = BIO_new(BIO_s_mem());
	i2a_ASN1_INTEGER(bio, cert->cert_info->serialNumber);
	int len = BIO_read(bio, buf, 100);
	buf[len]='\0';
	string x = buf;
	BIO_free(bio);
	openssl_error();
	return x;
}
