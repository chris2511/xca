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


#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include "pki_key.h"
#include "pki_x509req.h"

#ifndef PKI_X509_H
#define PKI_X509_H

#define TIMEFORM_PRETTY 1
#define TIMEFORM_PLAIN 2
#define TIMEFORM_SORTABLE 3


class pki_x509 : public pki_base
{
	friend class pki_crl;
	friend class db_x509;
	private:
	   pki_x509 *psigner;
	   pki_key *pkey;
           X509V3_CTX ext_ctx;
	   ASN1_TIME *revoked, *lastCrl;
	   int trust;
	   int efftrust;
	   int caSerial;
	   int crlDays;
	   string caTemplate;
	   X509 *cert;
	   void init();
	public:
	   pki_x509(string d, pki_key *clientKey, pki_x509req *req, pki_x509 *signer, int days, int serial);
	   pki_x509(X509 *c);
	   pki_x509(const pki_x509 *crt);
	   pki_x509();
	   pki_x509(const string fname);
	   ~pki_x509();
	   virtual void fromData(unsigned char *p, int size);
	   virtual unsigned char *toData(int *size);
	   virtual bool compare(pki_base *refcert);
	   bool canSign();
	   string getDNs(int nid);
	   string getDNi(int nid);
	   void writeCert(const string fname, bool PEM, bool append = false);
	   bool verify(pki_x509 *signer);
	   pki_key *getKey();
	   pki_key *getPubKey(); // will be created temporarily and must be freed
	   void delKey();
	   bool setKey(pki_key *key);
	   string notAfter(int format = TIMEFORM_PRETTY);
	   string notBefore(int format = TIMEFORM_PRETTY);
	   string revokedAt(int format = TIMEFORM_PRETTY);
	   pki_x509 *getSigner();
	   void delSigner();
	   string fingerprint(const EVP_MD *digest);
	   string printV3ext();
	   string getSerial();
	   long getSerialLong();
	   int checkDate();
	   void addV3ext(int nid, string exttext);
	   void sign(pki_key *signkey);
	   X509 *getCert(){ return cert;}
	   int getTrust();
	   void setTrust(int t);
	   int getEffTrust();
	   void setEffTrust(int t);
	   void setRevoked(bool rev);
	   bool isRevoked();
	   int calcEffTrust();
	   int getIncCaSerial();
	   int getCaSerial();
	   void setCaSerial(int s);
	   void setTemplate(string s);
	   string getTemplate();
	   void setCrlDays(int s);
	   int getCrlDays();
	   void setLastCrl(ASN1_TIME *time);
	   int resetTimes(pki_x509 *signer);
	   bool hasSubAltName();
	   bool cmpIssuerAndSerial(pki_x509 *refcert);
	   void setDates(int days);
	   void setSerial(int serial);
	   string tinyCAfname();
	   string asn1TimeToSortable(ASN1_TIME *a);
	   string asn1TimeToString(ASN1_TIME *a, int format);
	   string asn1TimeToPlain(ASN1_TIME *a);
	   string asn1TimeToPretty(ASN1_TIME *a);
	   int asn1TimeYMDG(ASN1_TIME *a, int *y, int *m, int *d, int *g);
	   string subjectOneLine();
};

#endif
