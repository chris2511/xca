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


#ifndef PKI_CRL_H
#define PKI_CRL_H

#include <iostream>
#include <openssl/pem.h>
#include "pki_x509.h"
#include "x509name.h"
#include "asn1time.h"
#include "asn1int.h"

class pki_crl: public pki_base
{
    friend class pki_x509;
    protected:
	pki_x509 *issuer;
	X509_CRL *crl;
    public:
	pki_crl(const QString name = "");
	/* destructor */
	~pki_crl();
	void fload(const QString fname);
	void writeDefault(const QString fname);
	static QPixmap *icon;
	void createCrl(const QString d, pki_x509 *iss);
	void addRev(const x509rev &rev);
	void addExt(int nid, QString value);
	void write(QString fname);
	void addV3ext(const x509v3ext &e);
	void sign(pki_key *key, const EVP_MD *md = EVP_md5());
	void writeCrl(const QString fname, bool pem = true);
	pki_x509 *getIssuer();	
	void setIssuer(pki_x509 *iss);
	x509name getIssuerName();
	void setLastUpdate(const a1time &t);
	void setNextUpdate(const a1time &t);
	a1time getNextUpdate();
	a1time getLastUpdate();
	virtual void fromData(const unsigned char *p, int size);
	virtual unsigned char *toData(int *size);
	virtual bool compare(pki_base *refcrl);
	int numRev();
	bool verify(pki_key *pkey);
	x509rev getRev(int num);
	QString printV3ext();
	x509v3ext getExtByNid(int nid);
	a1int getVersion();
	void updateView();
};

#endif
