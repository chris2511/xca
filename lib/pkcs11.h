
#ifndef _XCA_PKCS11_H_
#define _XCA_PKCS11_H_

#include "opensc-pkcs11.h"
#include <qstring.h>
#include <qlist.h>
#include <ltdl.h>

#include "pk11_attribute.h"

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
		CK_OBJECT_HANDLE object;
	public:
		static void pk11error(QString fmt, int r);
		static bool loaded()
		{
			return !!p11;
		};

		pkcs11();
		~pkcs11();
		static bool load_lib(QString file, bool silent);

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
		void initPin(unsigned char *pin, unsigned long pinLen);
		QList<CK_MECHANISM_TYPE> mechanismList(unsigned long slot);
		void mechanismInfo(unsigned long slot, CK_MECHANISM_TYPE m,
			CK_MECHANISM_INFO *info);
		CK_OBJECT_HANDLE createObject(pk11_attlist &attrs);
		pk11_attr_data findUniqueID(unsigned long oclass);
		pk11_attr_data generateRSAKey(QString name, unsigned long bits);
		int deleteObjects(pk11_attlist &atts);
		void initToken(unsigned long slot, unsigned char *pin,
			int pinlen, QString label);
		bool selectToken(unsigned long *slot, QWidget *w);
		QString driverInfo();
};

#endif
