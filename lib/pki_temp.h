/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2011 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PKI_TEMP_H
#define __PKI_TEMP_H

#include "pki_base.h"
#include "x509name.h"
#include "asn1time.h"
#include "pki_x509.h"

#define D5 "-----"
#define PEM_STRING_XCA_TEMPLATE "XCA TEMPLATE"

class pki_temp: public pki_x509name
{
		Q_OBJECT
	protected:
		int dataSize();
		void try_fload(QString fname, const char *mode);
	public:
		static QPixmap *icon;
		x509name xname;
		QString subAltName, issAltName, crlDist, authInfAcc, certPol;
		QString nsComment, nsBaseUrl, nsRevocationUrl,
			nsCARevocationUrl, nsRenewalUrl, nsCaPolicyUrl,
			nsSslServerName, destination, adv_ext, eKeyUse, pathLen;
		bool bcCrit, keyUseCrit, eKeyUseCrit, subKey, authKey,
			validMidn, noWellDefined;
		int nsCertType, keyUse, ca;
		int validN, validM;

		// methods
		extList fromCert(pki_x509super *cert_or_req);

		pki_temp(const pki_temp *pk);
		pki_temp(const QString d = QString());
		void fload(const QString fname);
		void writeDefault(const QString fname);
		~pki_temp();
		void fromData(const unsigned char *p, int size, int version);
		void fromData(const unsigned char *p, db_header_t *head );
		void oldFromData(const unsigned char *p, int size);

		QByteArray toData();
		bool compare(pki_base *ref);
		void writeTemp(QString fname);
		QVariant column_data(dbheader *hd);
		QVariant getIcon(dbheader *hd);
		virtual QString getMsg(msg_type msg);
		x509name getSubject() const;
		BIO *pem(BIO *b, int format);
		QByteArray toExportData();
		void fromPEM_BIO(BIO *, QString);
		void fromExportData(QByteArray data);
};

#endif
