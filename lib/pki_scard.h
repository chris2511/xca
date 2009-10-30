/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef PKI_SCARD_H
#define PKI_SCARD_H

#include <qstring.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#include "pkcs11.h"
#include "pki_key.h"

class pki_scard: public pki_key
{
	protected:
		QString card_serial;
		QString card_manufacturer;
		QString bit_length;
		QString card_label;
		QString slot_label;
		QString object_id;
		void init(void);
		static ENGINE *p11_engine;

	public:
		pki_scard(const QString name);
		virtual ~pki_scard();
		static QPixmap *icon[1];
		void load_token(pkcs11 &p11, CK_OBJECT_HANDLE object);
		int init_p11engine(void) const;
		void fromData(const unsigned char *p, db_header_t *head);
		unsigned char *toData(int *size);
		bool isPubKey() const;
		QString getTypeString(void);
		QString getManufacturer() const { return card_manufacturer; }
		QString getSerial() const { return card_serial; }
		QString getLabel() const { return slot_label; }
		QString getId() const { return object_id; }
		QString getCardLabel() const { return card_label; }
		EVP_PKEY *decryptKey() const;
		QString length();
		int verify();
		bool isScard();
		QVariant getIcon();
};

#endif
