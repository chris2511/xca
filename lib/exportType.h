/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2021 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __EXPORTTYPE_H
#define __EXPORTTYPE_H

#include <QMetaType>
#include <QString>

class exportType {
    public:
	enum etype { Separator, PEM, PEM_chain, PEM_unrevoked, PEM_all,
		DER, PKCS7, PKCS7_chain, PKCS7_unrevoked, PKCS7_all,
		PKCS12, PKCS12_chain, PEM_cert_key, PEM_cert_pk8,
		PEM_key, PEM_private, PEM_private_encrypt, DER_private,
		DER_key, PKCS8, PKCS8_encrypt, SSH2_public,
		PEM_selected, PKCS7_selected, Index, vcalendar, vcalendar_ca,
		PVK_private, PVK_encrypt, SSH2_private, ETYPE_max };
	enum etype type;
	QString extension;
	QString desc;
	exportType(enum etype t, const QString &e, const QString &d)
		: type(t), extension(e), desc(d)
	{
	}
	exportType() : type(Separator) { }
	bool isPEM() const {
		switch (type) {
		case PEM:
		case PEM_chain:
		case PEM_unrevoked:
		case PEM_all:
		case PEM_cert_key:
		case PEM_cert_pk8:
		case PEM_key:
		case PEM_private:
		case PEM_private_encrypt:
		case PEM_selected:
		case SSH2_private:
			return true;
		default:
			return false;
		}
	}
};
Q_DECLARE_METATYPE(exportType);

#endif
