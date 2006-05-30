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
 *	written by Eric Young (eay@cryptsoft.com)"
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

#ifndef PKI_X509_H
#define PKI_X509_H

#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include "pki_key.h"
#include "pki_x509req.h"
#include "pki_x509super.h"
#include "asn1time.h"
#include "asn1int.h"
#include "x509rev.h"
#include "x509v3ext.h"

class pki_x509 : public pki_x509super
{
	//friend class pki_crl;
	//friend class db_x509;
	private:
	   pki_x509 *psigner;
	   a1time revoked, lastCrl;
	   bool isrevoked;
	   int trust;
	   int efftrust;
	   a1int caSerial;
	   int crlDays;
	   QString caTemplate;
	   X509 *cert;
	   void init();
	public:
	   static QPixmap *icon[4];
	   pki_x509(X509 *c);
	   pki_x509(const pki_x509 *crt);
	   pki_x509(const QString name = "");
	   ~pki_x509();

	   void fload(const QString fname);
	   void writeDefault(const QString fname);
	   a1int hashInfo(const EVP_MD *md) const;
	   a1int getQASerial(const a1int &secret) const;
	   bool verifyQASerial(const a1int &secret) const;
	   void setSerial(const a1int &serial);
	   a1int getSerial() const;
	   void setNotBefore(const a1time &a1);
	   void setNotAfter(const a1time &a1);
	   a1time getNotBefore() const;
	   a1time getNotAfter() const;
	   x509name getSubject() const;
	   x509name getIssuer() const;
	   void setSubject(const x509name &n);
	   void setIssuer(const x509name &n);

	   unsigned char *toData(int *size);
	   void fromData(const unsigned char *p, db_header_t *head);
	   bool compare(pki_base *refcert);
	   bool canSign();
	   void writeCert(const QString fname, bool PEM, bool append = false);
	   bool verify(pki_x509 *signer);
	   pki_key *getPubKey() const;
	   void setPubKey(pki_key *key);
	   pki_x509 *getSigner();
	   void delSigner(pki_base *s);
	   QString fingerprint(const EVP_MD *digest);
	   QString printV3ext();
	   int checkDate();
	   void addV3ext(const x509v3ext &e);
	   void sign(pki_key *signkey, const EVP_MD *digest);
	   X509 *getCert(){ return cert;}
	   int getTrust();
	   void setTrust(int t);
	   int getEffTrust();
	   void setEffTrust(int t);
	   void setRevoked(bool rev);
	   void setRevoked(const a1time &when);
	   a1time &getRevoked();
	   bool isRevoked();
	   int calcEffTrust();
	   a1int getIncCaSerial();
	   a1int getCaSerial();
	   void setCaSerial(a1int s);
	   void setTemplate(QString s);
	   QString getTemplate();
	   void setCrlDays(int s);
	   int getCrlDays();
	   void setLastCrl(const a1time &time);
	   int resetTimes(pki_x509 *signer);
	   bool hasSubAltName();
	   bool cmpIssuerAndSerial(pki_x509 *refcert);
	   QString tinyCAfname();
	   void updateView();
	   x509rev getRev();
	   QString getSigAlg();
	   x509v3ext getExtByNid(int nid);
	   const EVP_MD *getDigest();
	   extList getExt();
	   QVariant column_data(int col);
	   QVariant getIcon();
};

#endif
