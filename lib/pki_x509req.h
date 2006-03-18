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

#ifndef PKI_X509REQ_H
#define PKI_X509REQ_H

#include <openssl/x509.h>
#include <openssl/pem.h>
#include "pki_key.h"
#include "x509v3ext.h"
#include "pki_x509super.h"
#include "x509name.h"


class pki_x509;

class pki_x509req : public pki_x509super
{
	private:
	   //loading spkac file and convert it to a request
	   void load_spkac(const QString filename);
	   //for checking spkac content-fields
	   int fix_data(int nid, int *type);
	   
	protected:
	   X509_REQ *request;
	   NETSCAPE_SPKI *spki;

	public:
	   extList getV3Ext();
	   static QPixmap *icon[3];
	   pki_x509req(QString name = "");
	   void fload(const QString fname);
	   void writeDefault(const QString fname);
	   ~pki_x509req();
	   void fromData(const unsigned char *p, db_header_t *head);
	   unsigned char *toData(int *size);
	   bool compare(pki_base *refreq);
	   x509name getSubject() const;
	   bool isSpki() const;
	   void writeReq(const QString fname, bool pem);

	   int verify();
	   pki_key *getPubKey() const;
	   void createReq(pki_key *key, const x509name &dn, const EVP_MD *md,
			   extList el);
	   QString getSigAlg();
	   void setSubject(const x509name &n);
	   /* SPKAC special functions */
	   void setSPKIFromData(const unsigned char *p, int size);
	   void setSPKIBase64(const char *p);
	   void set_spki(NETSCAPE_SPKI *_spki);
	   QVariant column_data(int col);
	   QVariant getIcon();
};

#endif
