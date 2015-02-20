/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2005 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __V3EXT_H
#define __V3EXT_H

#include "ui_v3ext.h"
#include "lib/pki_base.h"
#include <QLineEdit>
#include <QStringList>
#include <openssl/x509v3.h>
#include "widgets/kvView.h"

class pki_x509;
class pki_key;

class v3ext: public QDialog, public Ui::v3ext
{
	Q_OBJECT
	private:
		QLineEdit *le;
		int nid;
		X509V3_CTX *ext_ctx;
		bool __validate(bool showSuccess);
		QStringList keys;
		QString prefix;
	public:
		v3ext( QWidget *parent);
		void addItem(QString list);
		void addEntry(QString list);
		QString toString();
		void addInfo(QLineEdit *myle, const QStringList &sl, int n,
				X509V3_CTX *ctx);
		void setPrefix(QString p) {
			prefix = p;
		}

	public slots:
		void on_apply_clicked();
		void on_validate_clicked();
		void setupLineEdit(const QString &s, QLineEdit *l);
};

#endif
