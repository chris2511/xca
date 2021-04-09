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
			const QString &filt, pki_base *pki, const QPixmap &img,
			QList<exportType> types, const QString &help_ctx)
	: QDialog(w ?: mainwin)
{
	setupUi(this);
	setWindowTitle(XCA_TITLE);
	if (pki)
		descr->setText(pki->getIntName());
	descr->setReadOnly(true);
	image->setPixmap(img);
	label->setText(title);
	mainwin->helpdlg->register_ctxhelp_button(this, help_ctx);

	if (pki) {
		QString fn = Settings["workingdir"] +
			pki->getUnderlinedName() + "." + types[0].extension;
		filename->setText(nativeSeparator(fn));
	}
	filter = filt + ";;" + tr("All files ( * )");

	foreach(exportType t, types) {
		QVariant q;
		q.setValue(t);
		if (t.type == exportType::Separator)
			exportFormat->insertSeparator(exportFormat->count());
		else
			exportFormat->addItem(QString("%1 (*.%2)").
					arg(t.desc).arg(t.extension), q);
	}

	for (int i=0; i < exportType::ETYPE_max; i++)
		help.append(QString());
	help[exportType::Separator] = "What the heck!?";
	help[exportType::PEM] = tr("PEM Text format with headers");
	help[exportType::PEM_selected] =
		tr("Concatenated list of all selected items in one PEM text file");
	help[exportType::PEM_chain] = tr("Concatenated text format of the complete certificate chain in one PEM file");
	help[exportType::PEM_unrevoked] =
		tr("Concatenated text format of all unrevoked certificates in one PEM file");
	help[exportType::PEM_all] =
		tr("Concatenated text format of all certificates in one PEM file");
	help[exportType::DER] = tr("Binary DER encoded file");
	help[exportType::PKCS7] = tr("PKCS#7 encoded single certificate");
	help[exportType::PKCS7_chain] =
		tr("PKCS#7 encoded complete certificate chain");
	help[exportType::PKCS7_unrevoked] =
		tr("All unrevoked certificates encoded in one PKCS#7 file");
	help[exportType::PKCS7_selected] =
		tr("All selected certificates encoded in one PKCS#7 file");
	help[exportType::PKCS7_all] =
		tr("All certificates encoded in one PKCS#7 file");
	help[exportType::PKCS12] =
		tr("The certificate and the private key as encrypted PKCS#12 file");
	help[exportType::PKCS12_chain] = tr("The complete certificate chain and the private key as encrypted PKCS#12 file");
	help[exportType::PEM_cert_key] = tr("Concatenation of the certificate and the unencrypted private key in one PEM file");
	help[exportType::PEM_cert_pk8] = tr("Concatenation of the certificate and the encrypted private key in PKCS#8 format in one file");
	help[exportType::PEM_key] = tr("Text format of the public key in one PEM file");
	help[exportType::DER_key] = tr("Binary DER format of the public key");
	help[exportType::PEM_private] =
		tr("Unencrypted private key in text format");
	help[exportType::PEM_private_encrypt] =
		tr("OpenSSL specific encrypted private key in text format");
	help[exportType::DER_private] =
		tr("Unencrypted private key in binary DER format");
	help[exportType::PKCS8] =
		tr("Unencrypted private key in PKCS#8 text format");
	help[exportType::PKCS8_encrypt] =
		tr("Encrypted private key in PKCS#8 text format");
	help[exportType::SSH2_public] = tr("The public key encoded in SSH2 format");
	help[exportType::Index] = tr("OpenSSL specific Certificate Index file as created by the 'ca' command and required by the OCSP tool");
	help[exportType::vcalendar] = tr("vCalendar expiry reminder for the selected items");
	help[exportType::vcalendar_ca] = tr("vCalendar expiry reminder containing all issued, valid certificates, the CA itself and the latest CRL");
	help[exportType::PVK_private] = tr("Private key in Microsoft PVK format not encrypted");
	help[exportType::PVK_encrypt] = tr("Encrypted private key in Microsoft PVK format");

	on_exportFormat_highlighted(0);
}

void ExportDialog::on_fileBut_clicked()
{
	QString s = QFileDialog::getSaveFileName(this, QString(),
		filename->text(), filter, NULL,
		QFileDialog::DontConfirmOverwrite);

	if (!s.isEmpty())
		filename->setText(nativeSeparator(s));
}

void ExportDialog::on_exportFormat_activated(int selected)
{
	QString fn = filename->text();
	exportType form = exportFormat->itemData(selected).value<exportType>();

	for (int i=0; i< exportFormat->count(); i++) {
		exportType t = exportFormat->itemData(i).value<exportType>();
		if (fn.endsWith(QString(".") + t.extension)) {
			fn = fn.left(fn.length() - t.extension.length()) +
				form.extension;
			break;
		}
	}
	if (filename->isEnabled())
		filename->setText(fn);
	on_exportFormat_highlighted(selected);
}

bool ExportDialog::mayWriteFile(const QString &fname)
{
        if (QFile::exists(fname)) {
		xcaWarning msg(NULL,
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

enum exportType::etype ExportDialog::type()
{
	int selected = exportFormat->currentIndex();
	exportType form = exportFormat->itemData(selected).value<exportType>();
	return form.type;
}

void ExportDialog::on_exportFormat_highlighted(int index)
{
	exportType form = exportFormat->itemData(index).value<exportType>();
	infoBox->setText(help[form.type]);
}
