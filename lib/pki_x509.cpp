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

pki_x509::pki_x509(X509 *c) : pki_base()
{
	init();
	cert = c;
	openssl_error();
}

pki_x509::pki_x509(const pki_x509 &crt) 
	:pki_base(crt.desc)
{
	init();
	cert = X509_dup(crt.cert);
	openssl_error();
	psigner = crt.psigner;
	setKey(crt.pkey);
	trust = crt.trust;
	efftrust = crt.efftrust;
	revoked = crt.revoked;
	caSerial = crt.caSerial;
	caTemplate = crt.caTemplate;
	crlDays = crt.crlDays;
	lastCrl = crt.lastCrl;
	isrevoked = isrevoked;
	openssl_error();
}

pki_x509::pki_x509() : pki_base()
{
	init();
	cert = X509_new();
	X509_set_version(cert, 2);
	openssl_error();
}

pki_x509::pki_x509(const string fname)
{
	FILE *fp = fopen(fname.c_str(),"r");
	init();
	if (fp != NULL) {
	   cert = PEM_read_X509(fp, NULL, NULL, NULL);
	   if (!cert) {
		ign_openssl_error();
		rewind(fp);
		CERR("Fallback to certificate DER"); 
	   	cert = d2i_X509_fp(fp, NULL);
	   }
	   openssl_error();
	   int r = fname.rfind('.');
#ifdef WIN32
	   int l = fname.rfind('\\');
#else
	   int l = fname.rfind('/');
#endif
	   desc = fname.substr(l+1,r-l-1);
	   if (desc == "") desc = fname;
	   openssl_error();
	}	
	else fopen_error(fname);
	fclose(fp);
	trust = 1;
	efftrust = 1;
}

pki_x509::~pki_x509()
{
	if (cert) {
		X509_free(cert);
	}
	openssl_error();
}

void pki_x509::init()
{
	psigner = NULL;
	pkey= NULL;
	trust = 0;
	efftrust = 0;
	revoked.now();
	caSerial = 1;
	caTemplate = "";
	crlDays = 30;
	lastCrl.now();
	className = "pki_x509";
	cert = NULL;
	isrevoked = false;
}

void pki_x509::setSerial(a1int &serial)
{
	if (cert->cert_info->serialNumber != NULL ) {
		ASN1_INTEGER_free(cert->cert_info->serialNumber);
	}
	cert->cert_info->serialNumber = serial.get();
	openssl_error();
}

a1int pki_x509::getSerial()
{
	a1int a(X509_get_serialNumber(cert));
	return a;
}

void pki_x509::setNotBefore(a1time &a1)
{
	if (X509_get_notBefore(cert) != NULL ) {
		ASN1_TIME_free(X509_get_notBefore(cert));
	}
	X509_get_notBefore(cert) = a1.get();
	openssl_error();
}

void pki_x509::setNotAfter(a1time &a1)
{
	if (X509_get_notAfter(cert) != NULL ) {
		ASN1_TIME_free(X509_get_notAfter(cert));
	}
	X509_get_notAfter(cert) = a1.get();
	openssl_error();
}

a1time pki_x509::getNotBefore()
{
	a1time a(X509_get_notBefore(cert));
	return a;
}

a1time pki_x509::getNotAfter()
{
	a1time a(X509_get_notAfter(cert));
	return a;
}

x509name pki_x509::getSubject()
{
	x509name x(cert->cert_info->subject);
	openssl_error();
	return x;
}

x509name pki_x509::getIssuer()
{
	x509name x(cert->cert_info->issuer);
	openssl_error();
	return x;
}

void pki_x509::setSubject(x509name &n)
{
	if (cert->cert_info->subject != NULL)
		X509_NAME_free(cert->cert_info->subject);
	cert->cert_info->subject = n.get();
}

void pki_x509::setIssuer(x509name &n)
{
	if ((cert->cert_info->issuer) != NULL)
		X509_NAME_free(cert->cert_info->issuer);
	cert->cert_info->issuer = n.get();
}

void pki_x509::addV3ext(int nid, string exttext)
{	
	X509_EXTENSION *ext;
	int len; 
	char *c = NULL;
	if ((len = exttext.length()) == 0) return;
	len++;
	c = (char *)OPENSSL_malloc(len);
	openssl_error();
	strncpy(c, exttext.c_str(), len);
	ext =  X509V3_EXT_conf_nid(NULL, NULL, nid, c);
	OPENSSL_free(c);
	if (!ext) {
		string x="v3 Extension: " + exttext;
		openssl_error(x);
		return;
	}
	X509_add_ext(cert, ext, -1);
	X509_EXTENSION_free(ext);
	openssl_error();
}

bool pki_x509::canSign()
{
	BASIC_CONSTRAINTS *bc;
	int crit;
	if (!pkey || pkey->isPubKey()) return false;
	bc = (BASIC_CONSTRAINTS *)X509_get_ext_d2i(cert, NID_basic_constraints, &crit, NULL);
	openssl_error();
	if (!bc || !bc->ca) return false;
	return true;
}
	
bool pki_x509::hasSubAltName()
{
	STACK_OF(GENERAL_NAME) *subAlt;
	int crit;
	subAlt = (STACK_OF(GENERAL_NAME) *)X509_get_ext_d2i(cert, NID_subject_alt_name, &crit, NULL);
	openssl_error();
	CERR("hasSubAlt: "<< sk_GENERAL_NAME_num(subAlt));
	if (sk_GENERAL_NAME_num(subAlt) < 1) return false;	
	return true;
}
	
void pki_x509::sign(pki_key *signkey)
{
	if (!signkey) {
		openssl_error("There is no key for signing !");
	}
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

	
void pki_x509::fromData(unsigned char *p, int size)
{
	int version, sCert, sRev, sLastCrl;
	unsigned char *p1 = p;
	version = intFromData(&p1);
	if (version >=1 || version <= 3) {
		sCert = intFromData(&p1);
		cert = d2i_X509(NULL, &p1, sCert);
		trust = intFromData(&p1);
		CERR( "Trust: " << trust );
		sRev = intFromData(&p1);
		if (sRev) {
		   revoked= d2i_ASN1_TIME(NULL, &p1, sRev);
		   CERR("revoked time");
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
			   CERR("last CRL"<< sLastCrl);
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
	openssl_error();
}


unsigned char *pki_x509::toData(int *size)
{
#define PKI_DB_VERSION (int)3
	CERR("cert toData");
	unsigned char *p, *p1;
	int sCert = i2d_X509(cert, NULL);
	MARK	
	int sRev = revoked.derSize();
	MARK	
	int sLastCrl = lastCrl.derSize();
	MARK	
	// calculate the needed size 
	*size = caTemplate.length() + 1 + sCert + sRev + sLastCrl + (7 * sizeof(int));
	openssl_error();
	CERR("CertSize: "<<sCert << "  RevSize: " <<sRev <<" CRLdatesize: "<< sLastCrl);
	p = (unsigned char*)OPENSSL_malloc(*size);
	p1 = p;
	intToData(&p1, (PKI_DB_VERSION)); // version
	intToData(&p1, sCert); // sizeof(cert)
	i2d_X509(cert, &p1); // cert
	intToData(&p1, trust); // trust
	intToData(&p1, sRev); // sizeof(revoked)
	if (sRev) {
		p1 = revoked.i2d(p1); // revokation date
	}
	// version 2
	intToData(&p1, caSerial); // the serial if this is a CA
	stringToData(&p1, caTemplate); // the name of the template to use for signing
	// version 3
	intToData(&p1, crlDays); // the CRL period
	intToData(&p1, sLastCrl); // size of last CRL
	if (sLastCrl) {
		p1 = lastCrl.i2d(p1); // last CRL date
	}
	openssl_error();
	return p;
}

void pki_x509::writeCert(const string fname, bool PEM, bool append)
{
	FILE *fp;
	if (append)
		fp = fopen(fname.c_str(),"a");
	else
		fp = fopen(fname.c_str(),"w");

	if (fp != NULL) {
	   if (cert){
		if (PEM) 
		   PEM_write_X509(fp, cert);
		else
		   i2d_X509_fp(fp, cert);
	        openssl_error();
	   }
	}
	else fopen_error(fname);
	fclose(fp);
}

bool pki_x509::compare(pki_base *ref)
{
	bool ret = !X509_cmp(cert, ((pki_x509 *)ref)->cert);
	ign_openssl_error();
	return ret;
}

bool pki_x509::cmpIssuerAndSerial(pki_x509 *refcert)
{
	/*
	if (!refcert || !refcert->cert) return false;
	if (getSerial() != refcert->getSerial()) return false;
	X509_NAME *issuer = X509_get_issuer_name(cert);
	X509_NAME *refissuer = X509_get_issuer_name(refcert->cert);
	openssl_error();
	return !X509_NAME_cmp(issuer, refissuer);
	*/
	bool ret =  X509_issuer_and_serial_cmp(cert, refcert->cert);
	openssl_error();
	return ret;
			  
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
	pki_key *pkey = signer->getPubKey();
	int i = X509_verify(cert,pkey->key);
	ign_openssl_error();
	if (pkey) delete(pkey);
	if (i>0) {
		CERR("psigner set for: " << getIntName().latin1() );
		psigner = signer;
		return true;
	}
	return false;
}


pki_key *pki_x509::getPubKey()
{
	EVP_PKEY *pkey = X509_get_pubkey(cert);
	openssl_error();
	pki_key *key = new pki_key(pkey);	
	return key;
}



string pki_x509::fingerprint(const EVP_MD *digest)
{
	 int j;
	 string fp="";
	 char zs[4];
         unsigned int n;
         unsigned char md[EVP_MAX_MD_SIZE];
         X509_digest(cert, digest, md, &n);
	 openssl_error();
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
	int ret=0;
	if (ASN1_UTCTIME_cmp_time_t(X509_get_notAfter(cert), tnow) == -1)
		ret = -1;
	if (!(ASN1_UTCTIME_cmp_time_t(X509_get_notBefore(cert), tnow) == -1))
	 	ret = 1;
	openssl_error();
	return ret;
}

int pki_x509::resetTimes(pki_x509 *signer)
{
	int ret = 0;
	if (!signer) return -1;
	if (ASN1_STRING_cmp(X509_get_notAfter(cert), X509_get_notAfter(signer->cert)) == 1) {
		// client cert is longer valid....
		CERR("adjust notAfter");
		if (X509_get_notAfter(cert)) ASN1_TIME_free(X509_get_notAfter(cert));
		X509_get_notAfter(cert) = M_ASN1_TIME_dup(X509_get_notAfter(signer->cert));
		ret=1;
	}
	if (ASN1_STRING_cmp(X509_get_notBefore(cert), X509_get_notBefore(signer->cert)) == -1) {
		// client cert is longer valid....
		CERR("adjust notBefore");
		if (X509_get_notBefore(cert)) ASN1_TIME_free(X509_get_notBefore(cert));
		X509_get_notBefore(cert) = M_ASN1_TIME_dup(X509_get_notBefore(signer->cert));
		ret=2;
	}
	openssl_error();
	return ret;
}
	

pki_x509 *pki_x509::getSigner() { return (psigner); }
pki_key *pki_x509::getKey() { return (pkey); }


bool pki_x509::setKey(pki_key *key) 
{
	bool ret=false;
	if (!pkey && key) {
		X509_set_pubkey(cert, key->getKey());
		pkey = key;
		ret=true;
	}
	return ret;
}

void pki_x509::delKey() { pkey = NULL; }

void pki_x509::delSigner() { psigner=NULL; }

string pki_x509::printV3ext()
{
#define V3_BUF 100
	ASN1_OBJECT *obj;
	BIO *bio = BIO_new(BIO_s_mem());
	int i, len, n = X509_get_ext_count(cert);
	char buffer[V3_BUF+1];
	X509_EXTENSION *ex;
	string text="";
	for (i=0; i<n; i++) {
		text += "<b><u>";
		ex = X509_get_ext(cert,i);
		obj = X509_EXTENSION_get_object(ex);
		len = i2t_ASN1_OBJECT(buffer, V3_BUF, obj);
		if (len <0 || len > V3_BUF) openssl_error("V3 buffer too small, this is a bug!");
		buffer[len] = '\0';
		CERR("extension: "<< buffer <<", length: " << len);
		text += buffer;
		text += ": ";
		if (X509_EXTENSION_get_critical(ex)) {
			text += " <font color=\"red\">critical</font>:";
		}
		if(!X509V3_EXT_print(bio, ex, 0, 0)) {
			M_ASN1_OCTET_STRING_print(bio,ex->value);
		}
		text+="</u></b><br><tt>";
        	do {
			len = BIO_read(bio, buffer, V3_BUF);
			buffer[len] = '\0';
			text+=buffer;
			CERR("extension-length: "<< len);
		} while (len == V3_BUF);
		text+="</tt><br>";
	}
	BIO_free(bio);
	openssl_error();
	return text;
}

int pki_x509::getTrust()
{
	if (trust > 2) trust = 2;
	if (trust < 0) trust = 0;
	return trust;
}

void pki_x509::setTrust(int t)
{
	if (t>=0 && t<=2)
		trust = t;
}

int pki_x509::getEffTrust()
{
	if (efftrust > 2) efftrust = 2;
	if (efftrust < 0) efftrust = 0;
	return efftrust;
}

void pki_x509::setEffTrust(int t)
{
	if (t>= 0 && t<= 2)
		efftrust = t;
}


bool pki_x509::isRevoked()
{
	return isrevoked ;
}


void pki_x509::setRevoked(bool rev)
{
	if (rev) {
		setEffTrust(0);
		setTrust(0);
		revoked.now();
		openssl_error();
	}
	isrevoked = rev;
	openssl_error();
}
void pki_x509::setRevoked(a1time &when)
{
	isrevoked = true;
	revoked = when;
	openssl_error();	
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

void pki_x509::setLastCrl(a1time &time)
{
	lastCrl = time;
	openssl_error();
}

QString pki_x509::tinyCAfname()
{
	QString col;
	x509name x = getSubject();
	col = x.getEntryByNid(NID_commonName) 
	    +(x.getEntryByNid(NID_commonName) == "" ? " :" : ":")
	    + x.getEntryByNid(NID_pkcs9_emailAddress) 
	    +(x.getEntryByNid(NID_pkcs9_emailAddress) == "" ? " :" : ":")
	    + x.getEntryByNid(NID_organizationalUnitName) 
	    +(x.getEntryByNid(NID_organizationalUnitName) == "" ? " :" : ":")
	    + x.getEntryByNid(NID_organizationName) 
	    +(x.getEntryByNid(NID_organizationName) == "" ? " :" : ":")
	    + x.getEntryByNid(NID_localityName) 
	    +(x.getEntryByNid(NID_localityName) == "" ? " :" : ":")
	    + x.getEntryByNid(NID_stateOrProvinceName) 
	    +(x.getEntryByNid(NID_stateOrProvinceName) == "" ? " :" : ":")
	    + x.getEntryByNid(NID_countryName) 
	    +(x.getEntryByNid(NID_countryName) == "" ? " :" : ":");

	int len = col.length();
	unsigned char *buf = (unsigned char *)OPENSSL_malloc(len * 2 + 3);
	
	EVP_EncodeBlock(buf, (unsigned char *)col.latin1(), len );
	col = (char *)buf;
	OPENSSL_free(buf);
	col += ".pem";
	CERR("base64 Encoding: " <<col);
	return col;
}

