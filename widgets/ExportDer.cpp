/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "ExportDer.h"
#include "lib/base.h"

#include <qcombobox.h>
#include <qlineedit.h>
#include <qfiledialog.h>

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
	filename->text(), filter + ";;All files ( * )" );
	if (! s.isEmpty()) {
		QDir::convertSeparators(s);
		filename->setText(s);
	}
	on_exportFormat_activated(0);
}

void ExportDer::on_exportFormat_activated(int)
{
	const char *suffix[] = { "pem", "der" };
	int selected = exportFormat->currentIndex();
	QString fn = filename->text();
	QString nfn = fn.left(fn.lastIndexOf('.')+1) + suffix[selected];
	filename->setText(nfn);
}

