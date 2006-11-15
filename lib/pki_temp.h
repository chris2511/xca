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

#ifndef PKI_TEMP_H
#define PKI_TEMP_H

#include "pki_base.h"
#include "x509name.h"
#include "asn1time.h"

class pki_temp: public pki_base
{
	protected:
		int version;
		int dataSize();
	public:
		static QPixmap *icon;
		x509name xname;
		QString subAltName, issAltName, crlDist, authInfAcc, certPol;
		QString nsComment, nsBaseUrl, nsRevocationUrl, nsCARevocationUrl,
			nsRenewalUrl, nsCaPolicyUrl, nsSslServerName, destination;
		bool bcCrit, keyUseCrit, eKeyUseCrit, subKey, authKey, validMidn;
		int nsCertType, pathLen, keyUse, eKeyUse, ca;
		int validN, validM;

		// methods

		pki_temp(const pki_temp *pk);
		pki_temp(const QString d);
		void loadTemp(const QString fname);
		void writeDefault(const QString fname);
		/* destructor */
		~pki_temp();
		void fromData(const unsigned char *p, int size, int version);
		void fromData(const unsigned char *p, db_header_t *head );
		void oldFromData(unsigned char *p, int size);

		unsigned char *toData(int *size);
		bool compare(pki_base *ref);
		void writeTemp(QString fname);
		QVariant column_data(int col);
		QVariant getIcon();
		QString type2Text(int type);
};

#endif
