/* vi: set sw=4 ts=4: */
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
#include "func.h"

QPixmap *pki_x509::icon[4] = { NULL, NULL, NULL, NULL };

pki_x509::pki_x509(X509 *c) 
{
	init();
	cert = c;
	openssl_error();
}

pki_x509::pki_x509(const pki_x509 *crt) 
{
	init();
	cert = X509_dup(crt->cert);
	openssl_error();
	psigner = crt->psigner;
	setRefKey(crt->getRefKey());
	trust = crt->trust;
	efftrust = crt->efftrust;
	revoked = crt->revoked;
	caSerial = crt->caSerial;
	caTemplate = crt->caTemplate;
	crlDays = crt->crlDays;
	lastCrl = crt->lastCrl;
	isrevoked = isrevoked;
	openssl_error();
}

pki_x509::pki_x509() 
{
	init();
	cert = X509_new();
	X509_set_version(cert, 2);
	openssl_error();
}

pki_x509::pki_x509(const QString fname)
{
	FILE *fp = fopen(fname.latin1(),"r");
	init();
	if (fp != NULL) {
		cert = PEM_read_X509(fp, NULL, NULL, NULL);
		if (!cert) {
			ign_openssl_error();
			rewind(fp);
	   		cert = d2i_X509_fp(fp, NULL);
		}
		setIntName(rmslashdot(fname));
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
	trust = 0;
	efftrust = 0;
	revoked.now();
	caSerial = 1;
	caTemplate = "";
	crlDays = 30;
	lastCrl.now();
	class_name = "pki_x509";
	cert = NULL;
	isrevoked = false;
}

void pki_x509::setSerial(const a1int &serial)
{
	if (cert->cert_info->serialNumber != NULL ) {
		ASN1_INTEGER_free(cert->cert_info->serialNumber);
	}
	cert->cert_info->serialNumber = serial.get();
	openssl_error();
}

a1int pki_x509::getSerial() const
{
	a1int a(X509_get_serialNumber(cert));
	return a;
}

void pki_x509::setNotBefore(const a1time &a1)
{
	if (X509_get_notBefore(cert) != NULL ) {
		ASN1_TIME_free(X509_get_notBefore(cert));
	}
	X509_get_notBefore(cert) = a1.get();
	openssl_error();
}

void pki_x509::setNotAfter(const a1time &a1)
{
	if (X509_get_notAfter(cert) != NULL ) {
		ASN1_TIME_free(X509_get_notAfter(cert));
	}
	X509_get_notAfter(cert) = a1.get();
	openssl_error();
}

a1time pki_x509::getNotBefore() const
{
	a1time a(X509_get_notBefore(cert));
	return a;
}

a1time pki_x509::getNotAfter() const
{
	a1time a(X509_get_notAfter(cert));
	return a;
}

x509name pki_x509::getSubject() const
{
	x509name x(cert->cert_info->subject);
	openssl_error();
	return x;
}

x509name pki_x509::getIssuer() const
{
	x509name x(cert->cert_info->issuer);
	openssl_error();
	return x;
}

void pki_x509::setSubject(const x509name &n)
{
	if (cert->cert_info->subject != NULL)
		X509_NAME_free(cert->cert_info->subject);
	cert->cert_info->subject = n.get();
}

void pki_x509::setIssuer(const x509name &n)
{
	if ((cert->cert_info->issuer) != NULL)
		X509_NAME_free(cert->cert_info->issuer);
	cert->cert_info->issuer = n.get();
}

void pki_x509::addV3ext(const x509v3ext &e)
{	
	if (!e.isValid()) return;
	X509_EXTENSION *ext = e.get();
	X509_add_ext(cert, ext, -1);
	X509_EXTENSION_free(ext);
	openssl_error();
}

bool pki_x509::canSign()
{
	BASIC_CONSTRAINTS *bc;
	int crit;
	if (!privkey || privkey->isPubKey()) return false;
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
	
void pki_x509::sign(pki_key *signkey, const EVP_MD *digest)
{
	if (!signkey) {
		openssl_error("There is no key for signing !");
	}
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
			   lastCrl.d2i(p1, sLastCrl);
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
	unsigned char *p, *p1;
	int sCert = i2d_X509(cert, NULL);
	int sRev = revoked.derSize();
	int sLastCrl = lastCrl.derSize();
	// calculate the needed size 
	*size = caTemplate.length() + 1 + sCert + sRev + sLastCrl + (7 * sizeof(int));
	openssl_error();
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
	intToData(&p1, caSerial.getLong()); // the serial if this is a CA
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

void pki_x509::writeCert(const QString fname, bool PEM, bool append)
{
	FILE *fp;
	char *_a = "a", *_w="w", *p = _w;
	if (append) p=_a;
	fp = fopen(fname.latin1(), p);
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

void pki_x509::setPubKey(pki_key *key)
{
	 X509_set_pubkey(cert, key->getKey());
}

QString pki_x509::fingerprint(const EVP_MD *digest)
{
	int j;
	QString fp="";
	char zs[4];
	unsigned int n;
	unsigned char md[EVP_MAX_MD_SIZE];
	X509_digest(cert, digest, md, &n);
	openssl_error();
	for (j=0; j<(int)n; j++) {
		sprintf(zs, "%02X%c",md[j], (j+1 == (int)n) ?'\0':':');
		fp += zs;
	}
	return fp;
}

int pki_x509::checkDate()
{
	a1time a; a.now();
	int ret = 0;
	if (getNotAfter() <  a) ret = -1;
	if (getNotBefore() > a) ret = 1;
	openssl_error();
	return ret;
}

int pki_x509::resetTimes(pki_x509 *signer)
{
	int ret = 0;
	if (!signer) return -1;
	if (getNotAfter() > signer->getNotAfter()) {
		// client cert is longer valid....
		CERR("adjust notAfter");
		setNotAfter(signer->getNotAfter());
		ret=1;
	}
	if (getNotBefore() < signer->getNotBefore()) {
		// client cert is longer valid....
		CERR("adjust notBefore");
		setNotBefore(signer->getNotBefore());
		ret=2;
	}
	openssl_error();
	return ret;
}
	

pki_x509 *pki_x509::getSigner() { return (psigner); }

void pki_x509::delSigner(pki_x509 *s) 
{
	if (s == psigner) 
		psigner = NULL;
}

QString pki_x509::printV3ext()
{
	extList el;
	el.setStack(cert->cert_info->extensions);
	QString text = el.getHtml("<br>");
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

a1time &pki_x509::getRevoked()
{
	return revoked;
}
	
void pki_x509::setRevoked(const a1time &when)
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

a1int pki_x509::getIncCaSerial() { return caSerial++; }

a1int pki_x509::getCaSerial() { return caSerial; }

void pki_x509::setCaSerial(a1int s) { caSerial = s; }

int pki_x509::getCrlDays() {return crlDays;}

void pki_x509::setCrlDays(int s){if (s>0) crlDays = s;}

QString pki_x509::getTemplate(){ return caTemplate; }

void pki_x509::setTemplate(QString s) {if (s.length()>0) caTemplate = s; }

void pki_x509::setLastCrl(const a1time &time)
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

x509rev pki_x509::getRev()
{
	x509rev a;
	a.setDate(getRevoked());
	a.setSerial(getSerial());
	return a;
}
	
void pki_x509::updateView()
{
	pki_base::updateView();
	QString truststatus[] = 
		{ tr("Not trusted"), tr("Trust inherited"), tr("Always Trusted") };
	int pixnum = 0;
	if (!pointer) return;
	if (getRefKey()) {
		pixnum += 1;
	}
	if (calcEffTrust() == 0){ 
		pixnum += 2;
	}	
	pointer->setPixmap(0, *icon[pixnum]);
	pointer->setText(0, getIntName());
	pointer->setText(1, getSubject().getEntryByNid(NID_commonName));
	pointer->setText(2, getSerial().toHex() );  
	pointer->setText(3, getNotAfter().toSortable() );  
	pointer->setText(4, truststatus[ getTrust() ]);  
	if (isRevoked())
		pointer->setText(5, getRevoked().toSortable());
}

QString pki_x509::getSigAlg()
{
	QString alg = OBJ_nid2ln(OBJ_obj2nid(cert->sig_alg->algorithm));
	return alg;
}

const EVP_MD *pki_x509::getDigest()
{
	return EVP_get_digestbyobj(cert->sig_alg->algorithm);
}
