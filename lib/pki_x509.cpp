/*
 * Copyright (C) 2001 Christian Hohnstaedt.
 *
 *  All rights reserved.
 *
 *
 *  Redistribution and use in source and binary forms, with or without 
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  - Neither the name of the author nor the names of its contributors may be 
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * This program links to software with different licenses from:
 *
 *	http://www.openssl.org which includes cryptographic software
 * 	written by Eric Young (eay@cryptsoft.com)"
 *
 *	http://www.sleepycat.com
 *
 *	http://www.trolltech.com
 * 
 *
 *
 * http://www.hohnstaedt.de/xca
 * email: christian@hohnstaedt.de
 *
 * $Id$
 *
 */                           



#include "pki_x509.h"


pki_x509::pki_x509(string d,pki_key *clientKey, pki_x509req *req, pki_x509 *signer, int days, int serial)
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

	trust = 2;
	efftrust = 2;
	psigner = signer;
	pkey = clientKey;
	revoked = NULL;
	caSerial=0;
	caTemplate="";
	crlDays=30;
}

pki_x509::pki_x509(X509 *c) : pki_base()
{
	cert = c;
	openssl_error();
	psigner = NULL;
	pkey= NULL;
	trust = 0;
	efftrust = 0;
	revoked = NULL;
	caSerial=1;
	caTemplate="";
	crlDays=30;
	lastCrl=NULL;
}

pki_x509::pki_x509(const pki_x509 *crt) 
	:pki_base(crt->desc)
{
	cert = X509_dup(crt->cert);
	openssl_error();
	psigner = crt->psigner;
	pkey= crt->pkey;
	trust = crt->trust;
	efftrust = crt->efftrust;
	revoked = M_ASN1_TIME_dup(crt->revoked);
	caSerial = crt->caSerial;
	caTemplate = crt->caTemplate;
	crlDays = crt->crlDays;
	lastCrl = M_ASN1_TIME_dup(crt->lastCrl);
}

pki_x509::pki_x509() : pki_base()
{
	cert = X509_new();
	openssl_error();
	psigner = NULL;
	pkey= NULL;
	trust = 0;
	efftrust = 0;
	revoked = NULL;
	caSerial = 1;
	caTemplate = "";
	crlDays = 0;
	lastCrl = NULL;
}

pki_x509::pki_x509(const string fname)
{
	FILE *fp = fopen(fname.c_str(),"r");
	cert = NULL;
	if (fp != NULL) {
	   cert = PEM_read_X509(fp, NULL, NULL, NULL);
	   if (!cert) {
		ign_openssl_error();
		rewind(fp);
		printf("Fallback to certificate DER\n"); 
	   	cert = d2i_X509_fp(fp, NULL);
	   }
	   openssl_error();
	   int r = fname.rfind('.');
	   int l = fname.rfind('/');
	   desc = fname.substr(l+1,r-l-1);
	   if (desc == "") desc = fname;
	   openssl_error();
	}	
	else pki_error("Error opening file");
	fclose(fp);
	trust = 1;
	efftrust = 1;
	psigner = NULL;
	revoked = NULL;
	pkey = NULL;
	caSerial=1;
	caTemplate="";
	crlDays=30;
	lastCrl=NULL;
}

pki_x509::~pki_x509()
{
	if (cert) {
		X509_free(cert);
	}
	if (revoked) {
		ASN1_TIME_free(revoked);
	}
}


void pki_x509::addV3ext(int nid, string exttext)
{	
	X509_EXTENSION *ext;
	char c[200] = "";
	if (exttext.length() == 0) return;
	strncpy(c, exttext.c_str(), 200);
	ext =  X509V3_EXT_conf_nid(NULL, &ext_ctx, nid, c);
	if (!ext) {
		string x="v3 Extension: " + exttext;
		pki_error(x);
		return;
	}
	X509_add_ext(cert, ext, -1);
	X509_EXTENSION_free(ext);
}

bool pki_x509::canSign()
{
	BASIC_CONSTRAINTS *bc;
	int crit;
	if (!pkey) return false;
	if (pkey->isPubKey()) return false;
	bc = (BASIC_CONSTRAINTS *)X509_get_ext_d2i(cert, NID_basic_constraints, &crit, NULL);
	openssl_error();
	if (!bc) return false;	
	if (!bc->ca) return false;
	return true;
}
	
void pki_x509::sign(pki_key *signkey)
{
	const EVP_MD *digest = EVP_md5();
	X509_sign(cert, signkey->key, digest);
	openssl_error();
}



/* Save the Certificate to data and back:
 * Version 1:
 * 	int Version
 * 	int size of cert
 * 	cert
 * 	int trust
 * 	int size of revTime
 * 	revocationtime
 */

	
bool pki_x509::fromData(unsigned char *p, int size)
{
	int version, sCert, sRev, sLastCrl;
	unsigned char *p1 = p;
	version = intFromData(&p1);
	if (version >=1 || version <= 3) {
		sCert = intFromData(&p1);
		cert = d2i_X509(NULL, &p1, sCert);
		trust = intFromData(&p1);
		CERR << "Trust: " << trust <<endl;
		sRev = intFromData(&p1);
		if (sRev) {
		   revoked= d2i_ASN1_TIME(NULL, &p1, sRev);
		}
		else {
		   revoked = NULL;
		}
		
		if (version == 1) {
			caTemplate="";
			caSerial=1;
			lastCrl = NULL;
			crlDays=30;
		}
		
		if (version >= 2 ) {
			caSerial = intFromData(&p1);
			caTemplate = stringFromData(&p1);
		}
		if (version >= 3 ) {
			crlDays = intFromData(&p1);
			sLastCrl = intFromData(&p1);
			if (sLastCrl) {
			   lastCrl = d2i_ASN1_TIME(NULL, &p1, sLastCrl);
			}
			else {
			   lastCrl = NULL;
			}
		}
	}
	else { // old version
		cert = d2i_X509(NULL, &p, size);
		revoked = NULL;
		trust = 1;
		efftrust = 1;
	}	
	if (openssl_error()) return false;
	return true;
}


unsigned char *pki_x509::toData(int *size)
{
#define PKI_DB_VERSION (int)3
	unsigned char *p, *p1;
	int sCert = i2d_X509(cert, NULL);
	int sRev = (revoked ? i2d_ASN1_TIME(revoked, NULL) : 0);
	int sLastCrl = (lastCrl ? i2d_ASN1_TIME(lastCrl, NULL) : 0);
	// calculate the needed size 
	*size = caTemplate.length() + 1 + sCert + sRev + sLastCrl + (7 * sizeof(int));
	openssl_error();
	CERR <<"CertSize: "<<sCert << "  RevSize: " <<sRev <<" CRLdatesize: "<< sLastCrl<< endl;
	p = (unsigned char*)OPENSSL_malloc(*size);
	p1 = p;
	intToData(&p1, (PKI_DB_VERSION)); // version
	intToData(&p1, sCert); // sizeof(cert)
	i2d_X509(cert, &p1); // cert
	intToData(&p1, trust); // trust
	intToData(&p1, sRev); // sizeof(revoked)
	if (sRev) {
		i2d_ASN1_TIME(revoked, &p1); // revokation date
	}
	// version 2
	intToData(&p1, caSerial); // the serial if this is a CA
	stringToData(&p1, caTemplate); // the name of the template to use for signing
	// version 3
	intToData(&p1, crlDays); // the CRL period
	intToData(&p1, sLastCrl); // size of last CRL
	if (sLastCrl) {
		i2d_ASN1_TIME(lastCrl, &p1); // last CRL date
	}
	openssl_error();
	return p;
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
	return asn1TimeToString(X509_get_notBefore(cert));
}


string pki_x509::notAfter()
{
	return asn1TimeToString(X509_get_notAfter(cert));
}

string pki_x509::revokedAt()
{
	return asn1TimeToString(revoked);
}


string pki_x509::asn1TimeToString(ASN1_TIME *a)
{
	string time = "";
	if (!a) return time;
	BIO * bio = BIO_new(BIO_s_mem());
	char buf[200];
	ASN1_TIME_print(bio, a);
	BIO_gets(bio, buf, 200);
	time = buf;
	BIO_free(bio);
	return time;
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


pki_key *pki_x509::getPubKey()
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
pki_key *pki_x509::getKey() { return (pkey); }


bool pki_x509::setKey(pki_key *key) 
{
	bool ret=false;
	if (!pkey && key) {
		CERR << "KEYCOUNTUP" << endl;
		key->incUcount();
		ret=true;
	}
	pkey = key;
	return ret;
}

void pki_x509::delKey() { pkey = NULL; }

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
		if (X509_EXTENSION_get_critical(ex)) {
			text += " <font color=\"red\">critical</font>:";
		}
		if(!X509V3_EXT_print(bio, ex, 0, 0)) {
			M_ASN1_OCTET_STRING_print(bio,ex->value);
		}
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

int pki_x509::getTrust()
{
	return trust;
}

void pki_x509::setTrust(int t)
{
	if (t>=0 && t<=2)
		trust = t;
}

int pki_x509::getEffTrust()
{
	return efftrust;
}

void pki_x509::setEffTrust(int t)
{
	if (t>= 0 && t<= 2)
		efftrust = t;
}


bool pki_x509::isRevoked()
{
	return (revoked != NULL);
}


void pki_x509::setRevoked(bool rev)
{
	if (rev) {
		setEffTrust(0);
		setTrust(0);
		if (revoked) return;
		revoked = ASN1_TIME_new();
		if (openssl_error()) return;
		X509_gmtime_adj(revoked,0);
	}
	else {
		if (!revoked) return;
		ASN1_TIME_free(revoked);
		revoked = NULL;
	}
}

int pki_x509::calcEffTrust()
{
	int mytrust = trust;
	if (mytrust != 1) {
		efftrust = mytrust;
		return mytrust;
	}
	if (getSigner() == this && trust == 1) { // inherit trust, but self signed
		trust=0;
		efftrust=0;
		return 0;
	}
	//we must look at the parent certs
	pki_x509 *signer = getSigner();
	pki_x509 *prevsigner = this;
	while (mytrust==1 && signer != NULL && signer != prevsigner) {
		mytrust = signer->getTrust();
		prevsigner = signer;
		signer = signer->getSigner();
	}
	
	if (mytrust == 1) mytrust = 0;
	efftrust = mytrust;
	return mytrust;
}

int pki_x509::getIncCaSerial() { return caSerial++; }

int pki_x509::getCaSerial() { return caSerial; }

void pki_x509::setCaSerial(int s) { if (s>0) caSerial = s; }

int pki_x509::getCrlDays() {return crlDays;}

void pki_x509::setCrlDays(int s){if (s>0) crlDays = s;}

string pki_x509::getTemplate(){ return caTemplate; }

void pki_x509::setTemplate(string s) {if (s.length()>0) caTemplate = s; }

void pki_x509::setLastCrl(ASN1_TIME *time)
{
	if (!time) return;
	lastCrl=M_ASN1_TIME_dup(time);
	openssl_error();
}
