/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PKI_TEMP_H
#define __PKI_TEMP_H

#include "pki_base.h"
#include "x509name.h"
#include "asn1time.h"
#include "pki_x509super.h"

#define D5 "-----"
#define PEM_STRING_XCA_TEMPLATE "XCA TEMPLATE"
#define TMPL_VERSION 10

#define CHECK_TMPL_KEY if (!tmpl_keys.contains(key)) { qFatal("Unknown template key: %s(%s)",  __func__, CCHAR(key)); }

#define VIEW_temp_version 6
#define VIEW_temp_template 7

class pki_temp: public pki_x509name
{
		Q_OBJECT
	protected:
		static const QList<QString> tmpl_keys;
		int dataSize();
		void try_fload(XFile &file);
		bool pre_defined;
		x509name xname;
		QMap<QString, QString> settings;
		QString adv_ext;
		void fromExtList(extList *el, int nid, const char *item);

	public:
		pki_temp(const pki_temp *pk);
		pki_temp(const QString &d = QString());
		~pki_temp();

		QString getSetting(QString key)
		{
			CHECK_TMPL_KEY
			return settings[key];
		}
		int getSettingInt(QString key)
		{
			CHECK_TMPL_KEY
			return settings[key].toInt();
		}
		void setSetting(QString key, QString value)
		{
			CHECK_TMPL_KEY
			settings[key] = value;
		}
		void setSetting(QString key, int value)
		{
			CHECK_TMPL_KEY
			settings[key] = QString::number(value);
		}
		void fload(const QString &fname);
		void writeDefault(const QString &dirname) const ;
		void fromData(const unsigned char *p, int size, int version);
		void old_fromData(const unsigned char *p, int size, int version);
		void fromData(const unsigned char *p, db_header_t *head );
		void fromData(QByteArray &ba, int version);
		void setAsPreDefined()
		{
			pre_defined = true;
		}
		QString comboText() const;
		QByteArray toData() const;
		QString toB64Data()
		{
			return QString::fromLatin1(toData().toBase64());
		}
		bool compare(const pki_base *ref) const;
		void writeTemp(XFile &file) const;
		QVariant getIcon(const dbheader *hd) const;
		QString getMsg(msg_type msg) const;
		x509name getSubject() const;
		void setSubject(x509name n)
		{
			xname = n;
		}
		bool pem(BioByteArray &, int);
		QByteArray toExportData() const;
		void fromPEM_BIO(BIO *, const QString &);
		void fromExportData(QByteArray data);
		extList fromCert(pki_x509super *cert_or_req);
		QSqlError insertSqlData();
		QSqlError deleteSqlData();
		void restoreSql(const QSqlRecord &rec);
};

Q_DECLARE_METATYPE(pki_temp *);
#endif
