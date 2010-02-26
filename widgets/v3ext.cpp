/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2009 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "v3ext.h"
#include <qlabel.h>
#include <qlistwidget.h>
#include <qcombobox.h>
#include <qlineedit.h>
#include <qstringlist.h>
#include <qmessagebox.h>
#include "MainWindow.h"
#include "lib/exception.h"

v3ext::v3ext(QWidget *parent)
	:QDialog(parent)
{
	setupUi(this);
	setWindowTitle(XCA_TITLE);
}

void v3ext::addInfo(QLineEdit *myle, const QStringList &sl, int n,
		X509V3_CTX *ctx)
{
	nid = n;
	le = myle;
	if (le)
		addItem(le->text());
	ext_ctx = ctx;
	tab->setKeys(sl);
}

void v3ext::addItem(QString list)
{
	int i;
	QStringList sl;
	sl = list.split(',');
	for (i=0; i< sl.count(); i++)
		addEntry(sl[i]);
}

/* for one TYPE:Content String */
void v3ext::addEntry(QString line)
{
	QStringList s = line.split(':');
	if (s.count() > 1)
		tab->addRow(s[0], s[1]);
}

QString v3ext::toString()
{
	QStringList str;
	int i, row = tab->rowCount();

	for (i=0; i<row; i++) {
		QStringList s = tab->getRow(i);
		str += s[0] + ":" +s[1];
	}
	return str.join(",");
}

void v3ext::on_apply_clicked()
{
	if (le)
		le->setText(toString());
	__validate(false);
	accept();
}

bool v3ext::__validate(bool showSuccess)
{
	x509v3ext ext;
	QString str, error;

	if (nid==NID_info_access) {
		str = "OCSP;";
	}
	str += toString();

	ext.create(nid, str, ext_ctx);
	while (int i = ERR_get_error() ) {
		error += ERR_error_string(i ,NULL);
		error += "\n";
	}
	if (! error.isEmpty()) {
		QMessageBox::warning(this, XCA_TITLE,
			tr("Validation failed:\n'%1'").arg(str));
		return false;
	}
	if (showSuccess) {
		QMessageBox::information(this, XCA_TITLE,
			tr("Validation successfull:\n'%1'").
			arg(ext.getValue()));
	}
	return true;
}

void v3ext::on_validate_clicked()
{
	__validate(true);
}
