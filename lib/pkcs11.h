/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2009 - 2011 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __XCA_PKCS11_H
#define __XCA_PKCS11_H

#include "pkcs11_lib.h"
#include "opensc-pkcs11.h"
#include <QStringList>
#include <QString>
#include <QList>

#include "pk11_attribute.h"
#include "func.h"

void waitcursor(int start, int line);
#define WAITCURSOR_START waitcursor(1, __LINE__);
#define WAITCURSOR_END waitcursor(0, __LINE__);

extern char segv_data[1024];
#define CALL_P11_C(l, func, ...) do { \
	snprintf(segv_data, sizeof segv_data, "Crashed in %s in %s from %s:%d\n" \
		"This looks like a bug in the PKC#11 library and not in XCA\n", \
		#func, CCHAR((l)->filename()), __func__, __LINE__); \
	if (IS_GUI_APP) \
		QApplication::setOverrideCursor(QCursor(Qt::WaitCursor)); \
	rv = l->ptr()->func(__VA_ARGS__); \
	segv_data[0] = 0; \
	if (IS_GUI_APP) \
		QApplication::restoreOverrideCursor(); \
	ign_openssl_error(); \
} while(0);


class tkInfo
{
private:
	CK_TOKEN_INFO token_info{};
public:
	tkInfo() { }
	tkInfo(const CK_TOKEN_INFO *ti)
	{
		set(ti);
	}
	tkInfo(const tkInfo &tk)
	{
		set(&tk.token_info);
	}
	void set(const CK_TOKEN_INFO *ti)
	{
		memcpy(&token_info, ti, sizeof(token_info));
		// sanitize strings
		for (int i=0; i<32; i++) {
			if (token_info.label[i] == 0)
				token_info.label[i] = ' ';
			if (token_info.manufacturerID[i] == 0)
				token_info.manufacturerID[i] = ' ';
		}
		for (int i=0; i<16; i++) {
			if (token_info.model[i] == 0)
				token_info.model[i] = ' ';
			if (token_info.serialNumber[i] == 0)
				token_info.serialNumber[i] = ' ';
		}
	}
	QString label() const
	{
		return UTF8QSTRING(token_info.label, 32);
	}
	QString manufacturerID() const
	{
		return UTF8QSTRING(token_info.manufacturerID, 32);
	}
	QString model() const
	{
		return UTF8QSTRING(token_info.model, 16);
	}
	QString serial() const
	{
		return ASCIIQSTRING(token_info.serialNumber, 16);
	}
	bool protAuthPath() const
	{
		return !!(token_info.flags & CKF_PROTECTED_AUTHENTICATION_PATH);
	}
	bool tokenInitialized() const
	{
		return !!(token_info.flags & CKF_TOKEN_INITIALIZED);
	}
	QString pinInfo() const
	{
		return QObject::tr("Required PIN size: %1 - %2").
			arg(token_info.ulMinPinLen).
			arg(token_info.ulMaxPinLen);
	}
	bool force_keygen_named_curve() const
	{
		// Workaround for "www.CardContact.de" bug
		return manufacturerID() == "www.CardContact.de";
	}
	bool need_SO_for_object_mod() const
	{
		// Yubikey Need SO Pin to modify objects
		return manufacturerID() == "Yubico (www.yubico.com)";
	}
	bool set_token_attr_false_dsa_param() const
	{
		// nCipher Attributes
		// as on 10/26/2015 - Thales' PKCS11 provider has
		// issue to generate Domain Parameters
		return manufacturerID() == "nCipher Corp. Ltd";
	}
	QList<QStringList> fixed_ids() const
	{
		// Yubi keys have fixed set of IDs
		// Use QStringList to not invent a new type: (QString + unsigned)
		static const QList<QStringList> ids {
			{ "9a: PIV Authentication", "1" },
			{ "9c: Digital Signature", "2" },
			{ "9d: Key Management", "3" },
			{ "9e: Card Authentication", "4" }
		};
		if (manufacturerID() == "Yubico (www.yubico.com)") {
			if (model() == "YubiKey NEO")
				return ids;
			if (model() == "YubiKey YK4" || model() == "YubiKey YK5") {
				QList<QStringList> retired(ids);
				for (int i=0; i< 20; i++)
					retired.append(QStringList {
						QString("%1: Retired Key %2")
								.arg(i+0x82, 0, 16).arg(i+1),
						QString::number(i + 5)
					});
				return retired;
			}
		}
		return QList<QStringList>();
	}
};

class pkcs11
{
	friend class pk11_attribute;
	friend class pk11_attr_ulong;
	friend class pk11_attr_data;

	private:
		slotid p11slot;
		CK_SESSION_HANDLE session;
		CK_OBJECT_HANDLE p11obj;
		static int pctr;

	public:
		static pkcs11_lib_list libraries;
		pkcs11();
		~pkcs11();

		CK_RV tokenInfo(const slotid &slot, tkInfo *tkinfo) const;
		tkInfo tokenInfo(const slotid &slot) const;
		tkInfo tokenInfo() const
		{
			return tokenInfo(p11slot);
		}
		QString driverInfo(const slotid &slot) const
		{
			return slot.lib->driverInfo();
		}
		static slotidList getSlotList()
		{
			return libraries.getSlotList();
		}

		void closeSession(const slotid &slot);
		bool selectToken(slotid *slot, QWidget *w);
		void changePin(const slotid &slot, bool so);
		void initPin(const slotid &slot);
		void initToken(const slotid &slot, unsigned char *pin,
			int pinlen, QString label);
		QList<CK_MECHANISM_TYPE> mechanismList(const slotid &slot);
		void mechanismInfo(const slotid &slot, CK_MECHANISM_TYPE m,
			CK_MECHANISM_INFO *info);
		void startSession(const slotid &slot, bool rw = false);

		/* Session based functions */
		void loadAttribute(pk11_attribute &attribute,
				   CK_OBJECT_HANDLE object);
		void storeAttribute(pk11_attribute &attribute,
				   CK_OBJECT_HANDLE object);
		QList<CK_OBJECT_HANDLE> objectList(pk11_attlist &atts) const;
		QString tokenLogin(const QString &name, bool so, bool force=false);
		bool tokenLoginForModification();
		void getRandom();
		void logout();
		bool needsLogin(bool so);
		void login(unsigned char *pin, unsigned long pinlen, bool so);

		void setPin(unsigned char *oldPin, unsigned long oldPinLen,
			unsigned char *pin, unsigned long pinLen);
		CK_OBJECT_HANDLE createObject(pk11_attlist &attrs);
		pk11_attr_data findUniqueID(unsigned long oclass) const;
		pk11_attr_data generateKey(QString name,
			unsigned long ec_rsa_mech, unsigned long bits, int nid,
			const pk11_attr_data &id);
		int deleteObjects(QList<CK_OBJECT_HANDLE> objects);
		EVP_PKEY *getPrivateKey(EVP_PKEY *pub, CK_OBJECT_HANDLE obj);
		int encrypt(int flen, const unsigned char *from,
				unsigned char *to, int tolen, unsigned long m);
		int decrypt(int flen, const unsigned char *from,
				unsigned char *to, int tolen, unsigned long m);

};

#endif
