/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PKI_BASE_H
#define __PKI_BASE_H

#include <openssl/err.h>
#include <QString>
#include <QListView>
#include "pkcs11_lib.h"
#include "db.h"
#include "base.h"
#include "headerlist.h"

#define __ME QString("(%1:%2)").arg(class_name).arg(getIntName())
#define pki_openssl_error() _openssl_error(__ME, C_FILE, __LINE__)
#define pki_ign_openssl_error() _ign_openssl_error(__ME, C_FILE, __LINE__)

class pki_base : public QObject
{
		Q_OBJECT
	private:
		static int pki_counter;
	protected:
		const char *class_name;
		QString desc;
		int dataVersion;
		enum pki_type pkiType;
		/* model data */
		pki_base *parent;
		void my_error(const QString myerr) const;
		void fopen_error(const QString fname);

	public:
		enum msg_type {
			msg_import,
			msg_delete,
			msg_delete_multi,
			msg_create,
		};
		static int suppress_messages;
		static QRegExp limitPattern;
		QList<pki_base*> childItems;
		pki_base(const QString d = "", pki_base *p = NULL);
		virtual void fload(const QString) {};
		virtual void writeDefault(const QString) {};
		static int get_pki_counter(void);
		virtual void fromData(const unsigned char *, db_header_t *) {};
		virtual void oldFromData(unsigned char *, int ) {};
		virtual QByteArray toData()
		{
			return QByteArray();
		}
		virtual bool compare(pki_base *);
		virtual bool visible();
		virtual ~pki_base();
		QString getIntName() const;
		QString getUnderlinedName() const;
		void setIntName(const QString &d);
		QString getClassName();
		static QString rmslashdot(const QString &fname);
		virtual QString getMsg(msg_type msg)
		{
			return tr("Internal error: Unexpected message: %1 %2").
				arg(class_name).arg(msg);
		};
		int getVersion();
		enum pki_type getType();
		void setParent(pki_base *p);
		virtual pki_base *getParent();
		pki_base *child(int row);
		void append(pki_base *item);
		void insert(int row, pki_base *item);
		int childCount();
		int row() const;
		pki_base *iterate(pki_base *pki = NULL);
		void takeChild(pki_base *pki);
		pki_base *takeFirst();
		virtual QVariant column_data(dbheader *hd);
		virtual QVariant getIcon(dbheader *hd);
		const char *className()
		{
			return class_name;
		};
		uint32_t intFromData(QByteArray &ba);
		virtual void fromPEM_BIO(BIO *, QString) {};
		virtual void deleteFromToken() { };
		virtual void deleteFromToken(slotid) { };
		virtual int renameOnToken(slotid, QString)
		{
			return 0;
		};
		virtual QByteArray i2d()
		{
			return QByteArray();
		}
		virtual BIO *pem(BIO *, int format=0)
		{
			(void)format;
			return NULL;
		}
		void fwrite_ba(FILE *fp, QByteArray ba, QString fname);
		virtual QVariant bg_color(dbheader *hd)
		{
			(void)hd;
			return QVariant();
		}
};

#endif
