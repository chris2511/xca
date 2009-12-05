/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2009 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef PKI_TEMP_H
#define PKI_TEMP_H

#include "pki_base.h"
#include "x509name.h"
#include "asn1time.h"
#include "pki_x509.h"

class pki_temp: public pki_base
{
	protected:
		int dataSize();
	public:
		static QPixmap *icon;
		x509name xname;
		QString subAltName, issAltName, crlDist, authInfAcc, certPol;
		QString nsComment, nsBaseUrl, nsRevocationUrl,
			nsCARevocationUrl, nsRenewalUrl, nsCaPolicyUrl,
			nsSslServerName, destination, adv_ext, eKeyUse;
		bool bcCrit, keyUseCrit, eKeyUseCrit, subKey, authKey,
			validMidn, noWellDefined;
		int nsCertType, pathLen, keyUse, ca;
		int validN, validM;

		// methods
		extList fromCert(pki_x509 *cert);

		pki_temp(const pki_temp *pk);
		pki_temp(const QString d = QString());
		void fload(const QString fname);
		void writeDefault(const QString fname);
		~pki_temp();
		void fromData(const unsigned char *p, int size, int version);
		void fromData(const unsigned char *p, db_header_t *head );
		void oldFromData(unsigned char *p, int size);

		unsigned char *toData(int *size);
		bool compare(pki_base *ref);
		void writeTemp(QString fname);
		QVariant column_data(int col);
		QVariant getIcon(int column);
};

#endif
