/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2009 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "ExportDer.h"
#include "lib/base.h"
#include "lib/func.h"

#include <qcombobox.h>
#include <qlineedit.h>
#include <qfiledialog.h>
#include <qmessagebox.h>
#include <qstringlist.h>

ExportDer::ExportDer(QWidget *parent, QString fname, QString _filter)
	:QDialog(parent)
{
	setupUi(this);
	filename->setText(fname);
	setWindowTitle(tr(XCA_TITLE));
	QStringList sl;
	sl << "PEM" << "DER";

	exportFormat->addItems(sl);
	filter = _filter;
}

void ExportDer::on_fileBut_clicked()
{
	QString s = QFileDialog::getSaveFileName(this, QString(),
		filename->text(), filter + ";;All files ( * )", NULL,
		QFileDialog::DontConfirmOverwrite);

	if (!s.isEmpty()) {
		QDir::convertSeparators(s);
		filename->setText(s);
	}
	on_exportFormat_activated(0);
}

void ExportDer::on_exportFormat_activated(int c)
{
	QStringList suffix;
	suffix << "pem" << "der";

	filename->setText(changeFilenameSuffix(filename->text(), suffix, c));
}

void ExportDer::on_okButton_clicked()
{
	if (mayWriteFile(filename->text()))
		accept();
}

