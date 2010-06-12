/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "v3ext.h"
#include <QtGui/QLabel>
#include <QtGui/QListWidget>
#include <QtGui/QComboBox>
#include <QtGui/QLineEdit>
#include <QtCore/QStringList>
#include <QtGui/QMessageBox>
#include "MainWindow.h"
#include "lib/exception.h"

v3ext::v3ext(QWidget *parent)
	:QDialog(parent)
{
	setupUi(this);
	setWindowTitle(XCA_TITLE);
	tab->horizontalHeader()->setDefaultSectionSize(80);
}

void v3ext::addInfo(QLineEdit *myle, const QStringList &sl, int n,
		X509V3_CTX *ctx)
{
	nid = n;
	le = myle;
	ext_ctx = ctx;
	tab->setKeys(sl);
	tab->setInfoLabel(infoLabel);
	connect(tab->itemDelegateForColumn(1),
		SIGNAL(setupLineEdit(const QString &, QLineEdit *)),
		this, SLOT(setupLineEdit(const QString &, QLineEdit *)));
	if (le && !le->text().trimmed().isEmpty())
		addItem(le->text());
}

void v3ext::addItem(QString list)
{
	int i;
	QStringList sl;
	sl = list.split(',');
	if (sl[0] == "critical") {
		sl.takeFirst();
		critical->setChecked(true);
	}
	for (i=0; i< sl.count(); i++)
		addEntry(sl[i]);
}

void v3ext::setupLineEdit(const QString &s, QLineEdit *l)
{
	QString tt;
	QValidator *v = NULL;

	if (s == "email") {
		if (nid == NID_subject_alt_name)
			tt = tr("An email address or 'copy'");
		else
			tt = tr("An email address");
	} else if (s == "RID") {
		tt = tr("a registered ID: OBJECT IDENTIFIER");
		QRegExp rx("[a-zA-Z0-9.]+");
		v = new QRegExpValidator(rx, this);
	} else if (s == "URI") {
		tt = tr("a uniform resource indicator");
		QRegExp rx("[a-z]+://.*");
                v = new QRegExpValidator(rx, this);
	} else if (s == "DNS") {
		tt = tr("a DNS domain name");
	} else if (s == "IP") {
		tt = tr("an IP address");
		QRegExp rx("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}");
		v = new QRegExpValidator(rx, this);
	} else if (s == "otherName") {
		tt = tr("Syntax: <OID>;TYPE:text like '1.2.3.4:UTF8:name'");
		QRegExp rx("[a-zA-Z0-9.]+;.*");
		v = new QRegExpValidator(rx, this);
	} else if (s == "issuer") {
		tt = tr("No editing. Only 'copy' allowed here");
		l->setText(QString("copy"));
		l->setReadOnly(true);
		QRegExp rx("copy");
                v = new QRegExpValidator(rx, this);
	}
	l->setToolTip(tt);
	l->setValidator(v);
}

/* for one TYPE:Content String */
void v3ext::addEntry(QString line)
{
	int idx = line.indexOf(':');
	QString type, value;
	if (idx == -1) {
		type = line;
		value = "";
	} else {
		type = line.left(idx);
		value = line.mid(idx+1);
	}
	tab->addRow(type, value);
}

QString v3ext::toString()
{
	QStringList str;
	int i, row = tab->rowCount();

	if (critical->isChecked())
		str << "critical";

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
	if (!error.isEmpty()) {
		QMessageBox::warning(this, XCA_TITLE,
			tr("Validation failed:\n'%1'\n%2").
				arg(str).arg(error));
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
