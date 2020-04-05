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

#define VIEW_tokens_card_manufacturer 10
#define VIEW_tokens_card_serial 11
#define VIEW_tokens_card_model 12
#define VIEW_tokens_card_label 13
#define VIEW_tokens_slot_label 14
#define VIEW_tokens_object_id  15

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
		void load_token(pkcs11 &p11, CK_OBJECT_HANDLE object);
		bool prepare_card(slotid *slot) const;
		bool find_key_on_card(slotid *slot) const;
		void fromData(const unsigned char *p, db_header_t *head);
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
		void updateLabel(QString label);
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
		QVariant getIcon(const dbheader *hd) const;
		QList<CK_MECHANISM_TYPE> getMech_list()
		{
			return mech_list;
		}
		pk11_attlist objectAttributes(bool priv) const;
		pk11_attlist objectAttributesNoId(EVP_PKEY *pk, bool priv) const;
		void setMech_list(QList<CK_MECHANISM_TYPE> ml) { mech_list = ml; };
		QList<int> possibleHashNids();
		EVP_PKEY *load_pubkey(pkcs11 &p11, CK_OBJECT_HANDLE object) const;
		void generate(const keyjob &task);
		void deleteFromToken();
		void deleteFromToken(const slotid &slot);
		void store_token(const slotid &slot, EVP_PKEY *pkey);
		int renameOnToken(const slotid &slot, const QString &name);
		QString getMsg(msg_type msg) const;
		bool visible() const;
		QSqlError insertSqlData();
		QSqlError deleteSqlData();
		void restoreSql(const QSqlRecord &rec);
};
#endif
