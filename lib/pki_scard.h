/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2009 - 2011 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PKI_SCARD_H
#define __PKI_SCARD_H

#include <QString>
#include <openssl/pem.h>
#include <openssl/evp.h>

#include "pkcs11.h"
#include "pki_key.h"

class pki_scard: public pki_key
{
		Q_OBJECT
	protected:
		QString card_serial;
		QString card_manufacturer;
		QString card_model;
		QString card_label;
		QString slot_label;
		QString object_id;
		QList<CK_MECHANISM_TYPE> mech_list;
		void init(void);

	public:
		pki_scard(const QString name);
		virtual ~pki_scard();
		static QPixmap *icon[1];
		static bool only_token_hashes;
		void load_token(pkcs11 &p11, CK_OBJECT_HANDLE object);
		bool prepare_card(slotid *slot, bool verifyPubkey=true) const;
		void fromData(const unsigned char *p, db_header_t *head);
		QByteArray toData();
		bool isPubKey() const;
		QString getTypeString(void) const;
		QString getManufacturer() const
		{
			return card_manufacturer;
		}
		QString getSerial() const
		{
			return card_serial;
		}
		QString getModel() const
		{
			return card_model;
		}
		QString getLabel() const
		{
			return slot_label;
		}
		QString getId() const
		{
			return object_id;
		}
		pk11_attr_data getIdAttr() const;
		QString getCardLabel() const
		{
			return card_label;
		}
		EVP_PKEY *decryptKey() const;
		QString scardLogin(pkcs11 &p11, bool so, bool force=false)const;
		void changePin();
		void initPin();
		void changeSoPin();
		int verify();
		bool isToken();
		QVariant getIcon(dbheader *hd);
		QList<CK_MECHANISM_TYPE> getMech_list()
		{
			return mech_list;
		}
		pk11_attlist objectAttributes(bool priv) const;
		pk11_attlist objectAttributesNoId(EVP_PKEY *pk, bool priv) const;
		void setMech_list(QList<CK_MECHANISM_TYPE> ml) { mech_list = ml; };
		QList<int> possibleHashNids();
		EVP_PKEY *load_pubkey(pkcs11 &p11, CK_OBJECT_HANDLE object) const;
		const EVP_MD *getDefaultMD();
		void generateKey_card(int type, slotid slot, int size,
					int curve_nid, QProgressBar *bar);
		void deleteFromToken();
		void deleteFromToken(slotid slot);
		void store_token(slotid slot, EVP_PKEY *pkey);
		int renameOnToken(slotid slot, QString name);
		QString getMsg(msg_type msg);
		bool visible();
};

#endif
