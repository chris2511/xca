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
#include "asn1time.h"
#include "pkcs11_lib.h"
#include "db.h"
#include "base.h"
#include "headerlist.h"
#include "settings.h"
#include "sql.h"

#define __ME QString("(%1[%2]:%3)") \
		.arg(getClassName()) \
		.arg(getSqlItemId().toString()) \
		.arg(getIntName())
#define pki_openssl_error() _openssl_error(__ME, C_FILE, __LINE__)
#define pki_ign_openssl_error() _ign_openssl_error(__ME, C_FILE, __LINE__)

enum pki_source {
	unknown,
	imported,
	generated,
	transformed,
	token,
	legacy_db
};

#define VIEW_item_id 0
#define VIEW_item_name 1
#define VIEW_item_type 2
#define VIEW_item_date 3
#define VIEW_item_source 4
#define VIEW_item_comment 5

class pki_base : public QObject
{
		Q_OBJECT

	public: /* static */
		static QRegExp limitPattern;
		static QString rmslashdot(const QString &fname);
		static unsigned hash(QByteArray ba);

	protected:
		QVariant sqlItemId;
		QString desc, comment;
		a1time insertion_date;
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
		enum pki_source pkiSource;
		QList<pki_base*> childItems;

		pki_base(const QString d = "", pki_base *p = NULL);
		virtual ~pki_base();

		QString getIntName() const
		{
			return desc;
		}
		virtual QString comboText() const;
		QString getUnderlinedName() const
		{
			return getIntName().replace(
				QRegExp("[ &;`/\\\\]+"), "_");
		}
		void setIntName(const QString &d)
		{
			desc = d;
		}
		virtual void autoIntName();
		QString getComment() const
		{
			return comment;
		}
		void setComment(QString c)
		{
			comment = c;
		}
		QVariant getSqlItemId() const
		{
			return sqlItemId;
		}
		enum pki_type getType() const
		{
			return pkiType;
		}
		QString i2d_b64() const
		{
			return QString::fromLatin1(i2d().toBase64());
		}
		a1time getInsertionDate() const
		{
			return insertion_date;
		}
		virtual QByteArray i2d() const;
		virtual bool compare(const pki_base *) const;
		virtual QString getMsg(msg_type msg) const;
		virtual const char *getClassName() const;

		/* Tree View management */
		void setParent(pki_base *p);
		virtual pki_base *getParent();
		pki_base *child(int row);
		void append(pki_base *item);
		void insert(int row, pki_base *item);
		int childCount() const;
		pki_base *iterate(pki_base *pki = NULL);
		void takeChild(pki_base *pki);
		pki_base *takeFirst();

		/* Token handling */
		virtual void deleteFromToken();
		virtual void deleteFromToken(slotid);
		virtual int renameOnToken(slotid, QString);

		/* Import / Export management */
		virtual BIO *pem(BIO *, int format=0);
		virtual void fromPEM_BIO(BIO *, QString);
		virtual void fromPEMbyteArray(QByteArray &, QString);
		void fwrite_ba(FILE *fp, QByteArray ba, QString fname);
		virtual void fload(const QString);
		virtual void writeDefault(const QString);

		/* Old database management methods */
		virtual void fromData(const unsigned char *, db_header_t *) {};
		/* Qt Model-View methods */
		virtual QVariant bg_color(const dbheader *hd) const
		{
			(void)hd;
			return QVariant();
		}
		int row() const;
		virtual QVariant column_data(const dbheader *hd) const;
		virtual QVariant getIcon(const dbheader *hd) const;
		virtual QVariant column_tooltip(const dbheader *hd) const;
		virtual a1time column_a1time(const dbheader *hd) const;
		virtual bool visible() const;
		int isVisible();
		bool childVisible() const;

		/* SQL management methods */
		QSqlError insertSql();
		virtual QSqlError insertSqlData()
		{
			return QSqlError();
		}
		QSqlError deleteSql();
		virtual QSqlError deleteSqlData()
		{
			return QSqlError();
		}
		virtual void restoreSql(const QSqlRecord &rec);
		QSqlError sqlItemNotFound(QVariant sqlId) const;
		unsigned hash() const;
		QString pki_source_name() const;
		QString get_dump_filename(const QString &dir, QString ext);
		void selfComment(QString msg);
		QStringList icsVEVENT(const a1time &expires,
		    const QString &summary, const QString &description) const;
};

Q_DECLARE_METATYPE(pki_base *);
#endif
