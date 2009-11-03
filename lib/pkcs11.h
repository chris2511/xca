
#ifndef _XCA_PKCS11_H_
#define _XCA_PKCS11_H_

#include <opensc/pkcs11.h>
#include <qstring.h>
#include <ltdl.h>

#include "pk11_attribute.h"

class pkcs11
{
	private:
		static lt_dlhandle dl_handle;

		CK_SESSION_HANDLE session;
		CK_SLOT_ID slot_id;
		CK_OBJECT_HANDLE object;
	public:
		static CK_FUNCTION_LIST *p11;
		void init_pkcs11();
		static void pk11error(QString fmt, int r);

		pkcs11();
		~pkcs11();
		static void load_lib(QString file, bool silent);

		QStringList tokenInfo(CK_SLOT_ID slot);
		QStringList tokenInfo();
		void startSession(unsigned long slot, bool rw = false);
		CK_SLOT_ID *getSlotList(unsigned long *num_slots);
		void loadAttribute(pk11_attribute &attribute,
				   CK_OBJECT_HANDLE object);
		void storeAttribute(pk11_attribute &attribute,
				   CK_OBJECT_HANDLE object);
		QList<CK_OBJECT_HANDLE> objectList(const pk11_attribute *att);
		void login(unsigned char *pin, unsigned long pinlen, bool so);
		void logout();
		bool needsLogin(bool so);
		void setPin(unsigned char *oldPin, unsigned long oldPinLen,
			unsigned char *pin, unsigned long pinLen);
		void initPin(unsigned char *pin, unsigned long pinLen);



};

#endif
