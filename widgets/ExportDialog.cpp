/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "ExportDialog.h"
#include "MainWindow.h"
#include "Help.h"
#include "XcaWarning.h"
#include "lib/base.h"

#include <QComboBox>
#include <QLineEdit>
#include <QFileDialog>
#include <QPushButton>
#include <QMessageBox>
#include <QStringList>

ExportDialog::ExportDialog(QWidget *w, const QString &title,
			const QString &filt, const QModelIndexList &indexes,
			const QPixmap &img, QList<const pki_export*> types,
			const QString &help_ctx)
	: QDialog(w ? w : mainwin), filter(filt), savedFile(), alltypes(types)
{
	QString fname = "selected_items";
	setupUi(this);
	setWindowTitle(XCA_TITLE);
	if (indexes.size() == 1) {
		pki_base *pki = db_base::fromIndex(indexes[0]);
		if (pki) {
			description->setText(pki->getIntName());
			fname = pki->getUnderlinedName();
		}
		separateFiles->hide();
		setupExportFormat(F_MULTI);
	} else {
		// Plural form not required for < 2 items
		// Will only be called for 2 or more items
		description->setText(tr("%n selected item(s)", "", indexes.size()));
		setupExportFormat(F_SINGLE);
	}
	description->setReadOnly(true);
	image->setPixmap(img);
	label->setText(title);
	mainwin->helpdlg->register_ctxhelp_button(this, help_ctx);

	fname = Settings["workingdir"] + fname + "." + types[0]->extension;
	filename->setText(nativeSeparator(fname));
	filter = tr("All files ( * )") + ";;" + filter;
	filenameLabelOrig = filenameLabel->text();
}

void ExportDialog::setupExportFormat(int disable_flag)
{
	QList<const pki_export*> usual, normal;
	for (const pki_export *t : alltypes) {
		if (t->flags & disable_flag)
			continue;
		if (t->flags & F_USUAL)
			usual << t;
		else
			normal << t;
	}
	exportFormat->clear();
	foreach(const pki_export *t, usual + normal) {
		exportFormat->addItem(QString("%1 (*.%2)").
			arg(t->desc).arg(t->extension), QVariant(t->id));
	}
	if (usual.size() > 0 && normal.size() > 0)
		exportFormat->insertSeparator(usual.size());

	exportFormat->setCurrentIndex(0);
	on_exportFormat_highlighted(0);
}

ExportDialog::~ExportDialog()
{
	pki_base::pem_comment = 0;
}

void ExportDialog::on_fileBut_clicked()
{
	QString s;
	if (separateFiles->isChecked()) {
		s = QFileDialog::getExistingDirectory(this, QString(), filename->text(),
			QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
	} else {
		s = QFileDialog::getSaveFileName(this, QString(),
			filename->text(), filter, NULL,
			QFileDialog::DontConfirmOverwrite);
	}
	if (!s.isEmpty())
		filename->setText(nativeSeparator(s));
}

void ExportDialog::on_exportFormat_activated(int selected)
{
	QString fn = filename->text();
	const pki_export *t_sel = export_type(selected);

	for (int i=0; i< exportFormat->count(); i++) {
		const pki_export *t = export_type(i);
		if (t && fn.endsWith(QString(".") + t->extension)) {
			fn = fn.left(fn.length() - t->extension.length()) +
				t_sel->extension;
			break;
		}
	}
	if (filename->isEnabled())
		filename->setText(fn);
	on_exportFormat_highlighted(selected);
}

bool ExportDialog::mayWriteFile(const QString &fname)
{
	QFileInfo fi(fname);
	if (fi.exists() && !fi.isDir()) {
		xcaWarningBox msg(NULL,
			tr("The file: '%1' already exists!").arg(fname));
		msg.addButton(QMessageBox::Ok, tr("Overwrite"));
		msg.addButton(QMessageBox::Cancel, tr("Do not overwrite"));
		if (msg.exec() != QMessageBox::Ok)
			return false;
	}
	return true;
}

void ExportDialog::accept()
{
	QString fn = filename->text();
	pki_base::pem_comment = pemComment->isChecked();

	if (!filename->isEnabled()) {
		QDialog::accept();
		return;
	}
	if (fn.isEmpty()) {
		reject();
		return;
	}
	if (mayWriteFile(fn)) {
		update_workingdir(fn);
		QDialog::accept();
	}
}

const pki_export *ExportDialog::export_type(int idx) const
{
	if (idx == -1)
		idx = exportFormat->currentIndex();
	idx = exportFormat->itemData(idx).toInt();
	return idx ? pki_export::by_id(idx) : NULL;
}

void ExportDialog::on_exportFormat_highlighted(int index)
{
	const pki_export *x = export_type(index);
	if (!x)
		return;
	infoBox->setText(x->help);
	pemComment->setEnabled(x->flags & F_PEM);
}

void ExportDialog::on_separateFiles_clicked(bool checked)
{
	if (checked) {
		filenameLabel->setText(tr("Directory"));
		QFileInfo fi(filename->text());
		savedFile =	fi.fileName();
		filename->setText(nativeSeparator(fi.path()));
		setupExportFormat(F_MULTI);
	} else {
		filenameLabel->setText(filenameLabelOrig);
		if (!savedFile.isEmpty()) {
			QString completefile = filename->text() + "/" + savedFile;
			filename->setText(nativeSeparator(completefile));
		}
		setupExportFormat(F_SINGLE);
	}
}