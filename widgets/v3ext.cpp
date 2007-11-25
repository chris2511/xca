/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
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
	QStringList sl;
	sl << "Type" << "Content";
	tableWidget->setColumnCount(2);
	tableWidget->setHorizontalHeaderLabels(sl);
	setWindowTitle(tr(XCA_TITLE));
}

v3ext::~v3ext()
{
}

void v3ext::addInfo(QLineEdit *myle, const QStringList &sl, int n,
		X509V3_CTX *ctx)
{
	type->addItems(sl);
	nid = n;
	le = myle;
	if (le)
		addItem(le->text());

	ext_ctx = ctx;
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
	int i, row;
	QTableWidgetItem *tw;

	i = line.indexOf(':');
	if (i<0 || line.isEmpty())
		return;

	row = tableWidget->rowCount();
	tableWidget->setRowCount(row+1);

	tw = new QTableWidgetItem(line.left(i));
	tableWidget->setItem(row, 0, tw);

	tw = new QTableWidgetItem(line.right(line.length()-(i+1)));
	tableWidget->setItem(row, 1, tw);
}

QString v3ext::toString()
{
	QStringList str;
	int i, row = tableWidget->rowCount();

	for (i=0; i<row; i++) {
		QString s;
		s = tableWidget->item(i,0)->text().trimmed();
		if (!s.contains(':'))
			s += ":" + tableWidget->item(i,1)->text().trimmed();
		str += s;
	}
	return str.join(",");
}


void v3ext::on_delEntry_clicked()
{
	tableWidget->removeRow(tableWidget->currentRow());
}

void v3ext::on_addEntry_clicked()
{
	QString line;

	line = type->currentText();
	if ( ! line.contains(':') )
		line += ":" + value->text();
	addEntry(line);
}

void v3ext::on_apply_clicked()
{
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
		QMessageBox::warning(this, XCA_TITLE, tr("Validation failed:")
			+ "\n'" + str + "'\n" + error, tr("&OK"));
		return false;
	}
	if (showSuccess) {
		QMessageBox::information(this, XCA_TITLE,
			tr("Validation successfull:\n'") + ext.getValue() + "'", tr("&OK"));
	}
	return true;
}

void v3ext::on_validate_clicked()
{
	__validate(true);
}
