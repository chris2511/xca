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
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include "pki_base.h"

#ifndef PKI_KEY_H
#define PKI_KEY_H

#define MAX_KEY_LENGTH 4096


class pki_key: public pki_base
{
    friend class pki_x509req;
    friend class pki_x509;
    friend class pki_crl;
    protected:
	EVP_PKEY *key;
	string BN2string(BIGNUM *bn);
	int ucount; // usage counter
    public:
	static char passwd[40];
		
	/* constructor to generate a key .....
	 * d     is the description
	 * bits  is the keylength in bits
	 * cb    a callback for e.g. a progress bar
	 */ 
	pki_key(const string d, void (*cb)(int, int,void *),void *prog,int bits,int type = EVP_PKEY_RSA);   
	
	/* constructor to load a key from a file
	 * fname    = filename
	 * pem_password_cb = password callback function
	 */
	pki_key(const string fname, pem_password_cb *cb,int type = EVP_PKEY_RSA);
	
	// copy constructor
	pki_key::pki_key(const pki_key *pk);
	
	/* destructor */
	~pki_key();
	
	/* constructor from database 
	 * p = pointer to data
	 * size = size of datastruct
	 */
	
	pki_key(const string d, int type=EVP_PKEY_RSA);
	pki_key(EVP_PKEY *pkey);
	void init();
	void fromData(unsigned char *p, int size);
	unsigned char *toData(int *size);
	bool compare(pki_base *ref);
        string length();
        string modulus();
        string pubEx();
        string privEx();
	void writeKey(const string fname, EVP_CIPHER *enc, 
			pem_password_cb *cb, bool PEM);
	void writePublic(const string fname, bool PEM);
	void writePKCS8(const string fname, pem_password_cb *cb);
	bool isPrivKey();
	bool isPubKey();
	int verify();
	int getType();
	EVP_PKEY *getKey(){ return key;}
	int incUcount();
	int decUcount();
	int getUcount();
};

#endif
