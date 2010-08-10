/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2009 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __XCA_PKCS11_H
#define __XCA_PKCS11_H

#include "opensc-pkcs11.h"
#include <QtCore/QString>
#include <QtCore/QList>

#include <ltdl.h>

#include "pk11_attribute.h"

#define WAITCURSOR_START QApplication::setOverrideCursor(QCursor(Qt::WaitCursor))
#define WAITCURSOR_END QApplication::restoreOverrideCursor()

class tkInfo
{
private:
	CK_TOKEN_INFO token_info;
public:
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
};

class pkcs11
{
	friend class pk11_attribute;
	friend class pk11_attr_ulong;
	friend class pk11_attr_data;

	private:
		static lt_dlhandle dl_handle;
		static CK_FUNCTION_LIST *p11;

		CK_SESSION_HANDLE session;
		CK_SLOT_ID slot_id;
		CK_OBJECT_HANDLE p11obj;
	public:
		static void pk11error(QString fmt, int r);
		static bool loaded()
		{
			return !!p11;
		};

		pkcs11();
		~pkcs11();
		static bool load_lib(QString file, bool silent);
		static bool load_default_lib(QString file, bool silent);
		static void initialize();
		static void finalize();

		tkInfo tokenInfo(CK_SLOT_ID slot);
		tkInfo tokenInfo();

		void startSession(unsigned long slot, bool rw = false);
		QList<unsigned long> getSlotList();
		void loadAttribute(pk11_attribute &attribute,
				   CK_OBJECT_HANDLE object);
		void storeAttribute(pk11_attribute &attribute,
				   CK_OBJECT_HANDLE object);
		QList<CK_OBJECT_HANDLE> objectList(pk11_attlist &atts);
		QString tokenLogin(QString name, bool so, bool force=false);
		void logout() const;
		bool needsLogin(bool so);
		void login(unsigned char *pin, unsigned long pinlen, bool so);

		void setPin(unsigned char *oldPin, unsigned long oldPinLen,
			unsigned char *pin, unsigned long pinLen);
		QList<CK_MECHANISM_TYPE> mechanismList(unsigned long slot);
		void mechanismInfo(unsigned long slot, CK_MECHANISM_TYPE m,
			CK_MECHANISM_INFO *info);
		CK_OBJECT_HANDLE createObject(pk11_attlist &attrs);
		pk11_attr_data findUniqueID(unsigned long oclass);
		pk11_attr_data generateRSAKey(QString name, unsigned long bits);
		int deleteObjects(QList<CK_OBJECT_HANDLE> objects);
		void initToken(unsigned long slot, unsigned char *pin,
			int pinlen, QString label);
		bool selectToken(unsigned long *slot, QWidget *w);
		QString driverInfo();
		void changePin(unsigned long slot, bool so);
		void initPin(unsigned long slot);
		EVP_PKEY *getPrivateKey(EVP_PKEY *pub, CK_OBJECT_HANDLE obj);
		int encrypt(int flen, const unsigned char *from,
					unsigned char *to, int tolen);
		int decrypt(int flen, const unsigned char *from,
					unsigned char *to, int tolen);

};

#endif
