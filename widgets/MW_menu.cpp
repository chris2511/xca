/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2009 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "MainWindow.h"
#include "Options.h"
#include "lib/load_obj.h"
#include "lib/pass_info.h"
#include "lib/pkcs11.h"
#include "lib/pki_evp.h"
#include "lib/pki_scard.h"
#include "lib/func.h"
#include "ui_Options.h"
#include "widgets/hashBox.h"
#include <qapplication.h>
#include <qmenubar.h>
#include <qmessagebox.h>

void MainWindow::init_menu()
{
	QMenu *file, *help, *import;

	file = menuBar()->addMenu(tr("&File"));
	file->addAction(tr("&New DataBase"),  this, SLOT(new_database()));
	file->addAction(tr("&Open DataBase"),  this, SLOT(load_database()));
	acList += file->addAction(tr("&Close DataBase"), this,
			SLOT(close_database()));
	acList += file->addAction(tr("&Dump DataBase"), this,
				SLOT(dump_database()));
	scardMenuActions << file->addAction(tr("&Init Security token"),  this,
				SLOT(initToken()));
	acList += file->addAction(tr("C&hange DataBase password"), this,
				SLOT(changeDbPass()));
	acList += file->addAction(tr("&Import old db_dump"), this,
				SLOT(import_dbdump()));
	acList += file->addAction(tr("&Undelete items"), this,
				SLOT(undelete()));
	file->addSeparator();
	acList += file->addAction(tr("Options"), this, SLOT(setOptions()));
	file->addSeparator();
	file->addAction(tr("Exit"), qApp, SLOT(quit()), Qt::ALT+Qt::Key_F4);

	import = menuBar()->addMenu(tr("I&mport"));
	import->addAction(tr("Keys"), this,
				SLOT(on_BNimportKey_clicked()) );
	import->addAction(tr("Requests"), this,
				SLOT(on_BNimportReq_clicked()) );
	import->addAction(tr("Certificates"), this,
				SLOT(on_BNimportCert_clicked()) );
	import->addAction(tr("PKCS#12"), this,
				SLOT(on_BNimportPKCS12_clicked()) );
	import->addAction(tr("PKCS#7"), this,
				SLOT(on_BNimportPKCS7_clicked()) );
	import->addAction(tr("Template"), this,
				SLOT(on_BNimportTemp_clicked()) );
	import->addAction(tr("Revocation list"), this,
				SLOT(on_BNimportCrl_clicked()) );
	scardMenuActions << import->addAction(tr("Read Security token"), this,
				SLOT(importScard()));
	import->addAction(tr("PEM file"), this,
				SLOT(loadPem()) );
	import->addAction(tr("paste PEM file"), this,
				SLOT(pastePem()) );

	help = menuBar()->addMenu(tr("&Help") );
	help->addAction(tr("&Content"), this, SLOT(help()), Qt::Key_F1 );
	help->addAction(tr("&About"), this, SLOT(about()) );
	help->addAction(tr("Donations"), this, SLOT(donations()) );
	wdList += import;
}

void MainWindow::new_database()
{
	load_db l;
	QString selectedFilter;
	QString fname = QFileDialog::getSaveFileName(this, l.caption, homedir,
			l.filter, &selectedFilter, QFileDialog::DontConfirmOverwrite);

	if (fname.isEmpty())
		return;

	close_database();
	homedir = fname.mid(0, fname.lastIndexOf(QDir::separator()) );
	// make sure that, if the 3 letter extension was left selected
	// in Qt's OS X file open dialog,
	// the filename actually ends with that extension.
	// Otherwise usability breaks in jarring ways.
	dbfile = getFullFilename(fname, selectedFilter);
	init_database();
}

void MainWindow::load_database()
{
	load_db l;
	QString fname = QFileDialog::getOpenFileName(this, l.caption, homedir,
			l.filter);

	if (fname.isEmpty())
		return;

	close_database();
	homedir = fname.mid(0, fname.lastIndexOf(QDir::separator()) );
	dbfile = fname;
	init_database();
}

void MainWindow::import_dbdump()
{
	extern int read_dump(const char *, db_base **, char *, int);
	char buf[50];

	db_base *dbl[] = { keys, reqs, certs, temps, crls };
	if (!keys)
		return;
	QString pass;
	QString file = QFileDialog::getOpenFileName(this, tr(XCA_TITLE), homedir,
			tr("Database dump ( *.dump );;All files ( * )"));

	if (file.isEmpty())
		return;

	pass_info p(tr("Import password"),
		tr("Please enter the password of the old database"), this);
	if (passRead(buf, 50, 0, &p) <0)
		return;
	pass = buf;
	try {
		read_dump(CCHAR(file), dbl, buf, 50);
		if (pki_evp::md5passwd(CCHAR(pass)) != buf) {
			int ret = QMessageBox::warning(this, tr(XCA_TITLE),
				tr("Password verification error. Ignore keys ?"),
				tr("Import anyway"), tr("Cancel"));
			if (ret)
				return;
		}
		pki_evp::setOldPasswd(CCHAR(pass));
		read_dump(CCHAR(file), dbl, NULL, 0);
		pki_evp::eraseOldPasswd();
	} catch (errorEx &err) {
		Error(err);
	}
}

void MainWindow::setOptions()
{
	Options *opt = new Options(this);

	opt->setStringOpt(string_opt);
	opt->pkcs11path->setText(pkcs11path);
	if (!opt->exec())
		return;

	QString alg = opt->hashAlgo->currentHashName();
	db mydb(dbfile);
	mydb.set((const unsigned char *)CCHAR(alg), alg.length()+1, 1,
			setting, "default_hash");
	hashBox::setDefault(alg);

	mandatory_dn = opt->getDnString();
	mydb.set((const unsigned char *)CCHAR(mandatory_dn),
			mandatory_dn.length()+1, 1, setting, "mandatory_dn");

	if (opt->getStringOpt() != string_opt) {
		string_opt = opt->getStringOpt();
		ASN1_STRING_set_default_mask_asc((char *)CCHAR(string_opt));
		mydb.set((const unsigned char *)CCHAR(string_opt),
				string_opt.length()+1, 1, setting,"string_opt");
	}
	QString newpath = opt->pkcs11path->text();
	if (newpath != pkcs11path) {
		pkcs11path = newpath;
		mydb.set((const unsigned char *) CCHAR(pkcs11path),
			pkcs11path.length()+1, 1,setting, "pkcs11path");
		try {
			pki_scard::init_p11engine(pkcs11path, true);
		} catch (errorEx &err) {
			Error(err);
		}
#ifdef WIN32
		QMessageBox::information(this, XCA_TITLE,
			tr("You need to restart XCA to load the new library"));
#endif
	}
	enableTokenMenu(pkcs11::loaded());
}
