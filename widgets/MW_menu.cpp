/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "MainWindow.h"
#include "PwDialog.h"
#include "Options.h"
#include "lib/load_obj.h"
#include "lib/pass_info.h"
#include "lib/pkcs11.h"
#include "lib/pki_evp.h"
#include "lib/pki_scard.h"
#include "lib/func.h"
#include "ui_Options.h"
#include "widgets/hashBox.h"
#include <QtGui/QApplication>
#include <QtGui/QClipboard>
#include <QtGui/QMenuBar>
#include <QtGui/QMessageBox>

void MainWindow::init_menu()
{
	QMenu *file, *help, *import, *token;

	file = menuBar()->addMenu(tr("&File"));
	file->addAction(tr("&New DataBase"), this, SLOT(new_database()),
		QKeySequence::New);
	file->addAction(tr("&Open DataBase"), this, SLOT(load_database()),
		QKeySequence::Open);
	file->addAction(tr("Generate DH parameter"), this,
				 SLOT(generateDHparam()));
	acList += file->addAction(tr("Set as default DataBase"), this,
				SLOT(default_database()));
	acList += file->addAction(tr("&Close DataBase"), this,
		SLOT(close_database()), QKeySequence(QKeySequence::Close));
	acList += file->addAction(tr("&Dump DataBase"), this,
				SLOT(dump_database()));
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
	import->addAction(tr("PEM file"), this,
				SLOT(loadPem()) );
	import->addAction(tr("paste PEM file"), this,
				SLOT(pastePem()) );

	token = menuBar()->addMenu(tr("&Token"));
	token->addAction(tr("&Manage Security token"), this,
				SLOT(manageToken()));
	token->addAction(tr("&Init Security token"),  this,
				SLOT(initToken()));
	token->addAction(tr("&Change PIN"), this,
				SLOT(changePin()) );
	token->addAction(tr("Change &SO PIN"), this,
				SLOT(changeSoPin()) );
	token->addAction(tr("Init PIN"), this,
				SLOT(initPin()) );

	help = menuBar()->addMenu(tr("&Help") );
	help->addAction(tr("&Content"), this, SLOT(help()),
			QKeySequence::HelpContents);
	help->addAction(tr("&About"), this, SLOT(about()) );
	help->addAction(tr("Donations"), this, SLOT(donations()) );
	wdList += import;
	scardList += token;
}

int MainWindow::changeDB(QString fname)
{
	if (fname.isEmpty())
		return 1;
	close_database();
	homedir = fname.mid(0, fname.lastIndexOf(QDir::separator()));
	dbfile = fname;
	return init_database();
}

void MainWindow::new_database()
{
	load_db l;
	QString selectedFilter;
	QString fname = QFileDialog::getSaveFileName(this, l.caption, homedir,
			l.filter, &selectedFilter, QFileDialog::DontConfirmOverwrite);
	// make sure that, if the 3 letter extension was left selected
	// in Qt's OS X file open dialog,
	// the filename actually ends with that extension.
	// Otherwise usability breaks in jarring ways.
	changeDB(getFullFilename(fname, selectedFilter));
}

void MainWindow::load_database()
{
	load_db l;
	QString fname = QFileDialog::getOpenFileName(this, l.caption, homedir,
			l.filter);
	changeDB(fname);
}

void MainWindow::import_dbdump()
{
	extern int read_dump(const char *, db_base **, char *, int);
	Passwd pass;
	char buf[50];

	db_base *dbl[] = { keys, reqs, certs, temps, crls };
	if (!keys)
		return;
	QString file = QFileDialog::getOpenFileName(this, tr(XCA_TITLE), homedir,
			tr("Database dump ( *.dump );;All files ( * )"));

	if (file.isEmpty())
		return;

	pass_info p(tr("Import password"),
		tr("Please enter the password of the old database"), this);
	if (PwDialog::execute(&p, &pass) != 1)
		return;
	try {
		read_dump(CCHAR(file), dbl, buf, sizeof(buf));
		if (pki_evp::md5passwd(pass) != buf) {
			int ret = QMessageBox::warning(this, tr(XCA_TITLE),
				tr("Password verification error. Ignore keys ?"),
				tr("Import anyway"), tr("Cancel"));
			if (ret)
				return;
		}
		pki_evp::oldpasswd = pass;
		read_dump(CCHAR(file), dbl, NULL, 0);
		pki_evp::oldpasswd.cleanse();
	} catch (errorEx &err) {
		Error(err);
	}
}

void MainWindow::setOptions()
{
	Options *opt = new Options(this);

	opt->setDnString(mandatory_dn);
	opt->setStringOpt(string_opt);
	opt->setupPkcs11Provider(pkcs11path);
	opt->suppress->setCheckState(
		pki_base::suppress_messages ? Qt::Checked : Qt::Unchecked);
	opt->noColorize->setCheckState(
		pki_x509::dont_colorize_expiries ? Qt::Checked : Qt::Unchecked);

	if (!opt->exec()) {
		delete opt;
		enableTokenMenu(pkcs11::loaded());
		return;
	}
	QString alg = opt->hashAlgo->currentHashName();
	db mydb(dbfile);
	mydb.set((const unsigned char *)CCHAR(alg), alg.length()+1, 1,
			setting, "default_hash");
	hashBox::setDefault(alg);

	mandatory_dn = opt->getDnString();
	mydb.set((const unsigned char *)CCHAR(mandatory_dn),
			mandatory_dn.length()+1, 1, setting, "mandatory_dn");

	QString flags = getOptFlags();
	pki_base::suppress_messages = opt->suppress->checkState();
	pki_x509::dont_colorize_expiries = opt->noColorize->checkState();

	if (flags != getOptFlags()) {
		flags = getOptFlags();
		mydb.set((const unsigned char *)(CCHAR(flags)),
				flags.length()+1, 1, setting, "optionflags");
		mydb.first();
		if (!mydb.find(setting, "suppress"))
			mydb.erase();
	}

	if (opt->getStringOpt() != string_opt) {
		string_opt = opt->getStringOpt();
		ASN1_STRING_set_default_mask_asc((char *)CCHAR(string_opt));
		mydb.set((const unsigned char *)CCHAR(string_opt),
				string_opt.length()+1, 1, setting,"string_opt");
	}
	QString newpath = opt->getPkcs11Provider();
	if (newpath != pkcs11path) {
		pkcs11path = newpath;
		mydb.set((const unsigned char *) CCHAR(pkcs11path),
			pkcs11path.length()+1, 1,setting, "pkcs11path");
	}
	enableTokenMenu(pkcs11::loaded());
	delete opt;
}

/* Documentation of the flags field:
 * S: Suppress success messages
 * C: Don't colorize success messages
 */
void MainWindow::setOptFlags(QString flags)
{
	int s = flags.size(), i;
	QByteArray b = flags.toAscii();

	pki_base::suppress_messages = false;
	pki_x509::dont_colorize_expiries = false;

	for (i=0; i<s; i++) {
		switch (b[i]) {
		case 'S':
			pki_base::suppress_messages = true;
			break;
		case 'C':
			pki_x509::dont_colorize_expiries = true;
			break;
		default:
			abort();
		}
	}
}

QString MainWindow::getOptFlags()
{
	QString flags;

	if (pki_base::suppress_messages)
		flags += "S";
	if (pki_x509::dont_colorize_expiries)
		flags += "C";

	return flags;
}
