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


#include <iostream>
#include <string>
#include <openssl/pem.h>
#include "pki_x509.h"

#ifndef PKI_CRL_H
#define PKI_CRL_H

class pki_crl: public pki_base
{
    friend class pki_x509;
    protected:
	pki_x509 *issuer;
	X509V3_CTX ctx;
    public:
	X509_CRL *crl;
	pki_crl(const string d, pki_x509 *iss);
	pki_crl(const string fname);
	pki_crl();
	/* destructor */
	~pki_crl();
	
	void addRevoked(const pki_x509 *rev);
	void addExt(int nid, string value);
	void write(string fname);
	void addV3ext(int nid, string exttext);
	void sign(pki_key *key);
	void writeCrl(const string fname);
	pki_x509 *getIssuer();	
	ASN1_TIME *pki_crl::getDate();
	virtual void fromData(unsigned char *p, int size);
	virtual unsigned char *toData(int *size);
	virtual bool compare(pki_base *refcrl);
	int numRev();
	string issuerName();
	X509_NAME *getIssuerX509_NAME();
	bool verify(pki_key *pkey);
	long getSerial(int num);
	ASN1_TIME *getRevDate(int num);
	string printV3ext();
			       
};

#endif
