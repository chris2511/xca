/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef IMPORTMULTI_H
#define IMPORTMULTI_H

#include "ui_v3ext.h"
#include "lib/pki_base.h"
#include <qlineedit.h>
#include <qstringlist.h>
#include <openssl/x509v3.h>

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
	public:
		v3ext( QWidget *parent);
		~v3ext();
		void addItem(QString list);
		void addEntry(QString list);
		QString toString();
		void addInfo(QLineEdit *myle, const QStringList &sl, int n,
				X509V3_CTX *ctx);

	public slots:
		void on_delEntry_clicked();
		void on_addEntry_clicked();
		void on_apply_clicked();
		void on_validate_clicked();
};

#endif
