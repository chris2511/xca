/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
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
#include "lib/db_x509super.h"
#include "ui_Options.h"
#include "hashBox.h"
#include "OidResolver.h"
#include <QApplication>
#include <QClipboard>
#include <QMenuBar>
#include <QMessageBox>

class myLang
{
public:
	QString english, native;
	QLocale locale;
	myLang(QString e, QString n, QLocale l) {
		english = e; native = n, locale = l;
	}
};

void MainWindow::init_menu()
{
	static QMenu *file = NULL, *help = NULL, *import = NULL,
			*token = NULL, *languageMenu = NULL, *extra = NULL;
	static QActionGroup * langGroup = NULL;
	QAction *a;

	QList<myLang> languages;
	if (file) delete file;
	if (help) delete help;
	if (import) delete import;
	if (token) delete token;
	if (extra) delete extra;
	if (languageMenu) delete languageMenu;
	if (historyMenu) delete historyMenu;
	if (langGroup) delete langGroup;

	wdMenuList.clear();
	scardList.clear();
	acList.clear();

	langGroup = new QActionGroup(this);

	historyMenu = new tipMenu(tr("Recent DataBases") + " ...", this);
	connect(historyMenu, SIGNAL(triggered(QAction*)),
                this, SLOT(open_database(QAction*)));

	languages <<
		myLang("System", tr("System"), QLocale::system()) <<
		myLang("Croatian", tr("Croatian"), QLocale("hr")) <<
		myLang("English", tr("English"), QLocale("en")) <<
		myLang("French", tr("French"), QLocale("fr")) <<
		myLang("German", tr("German"), QLocale("de")) <<
		myLang("Russian", tr("Russian"), QLocale("ru")) <<
		myLang("Spanish", tr("Spanish"), QLocale("es")) <<
		myLang("Turkish", tr("Turkish"), QLocale("tr"));

	languageMenu = new tipMenu(tr("Language"), this);
	connect(languageMenu, SIGNAL(triggered(QAction*)),
		qApp, SLOT(switchLanguage(QAction*)));

	foreach(myLang l, languages) {
		QAction *a = new QAction(l.english, langGroup);
		a->setToolTip(l.native);
		a->setData(QVariant(l.locale));
		a->setDisabled(!XCA_application::languageAvailable(l.locale));
		a->setCheckable(true);
		langGroup->addAction(a);
		languageMenu->addAction(a);
		if (l.locale == XCA_application::language())
			a->setChecked(true);
	}

	file = menuBar()->addMenu(tr("&File"));
	file->addAction(tr("&New DataBase"), this, SLOT(new_database()),
		QKeySequence::New);
	file->addAction(tr("&Open DataBase"), this, SLOT(load_database()),
		QKeySequence::Open);
	file->addMenu(historyMenu);
	file->addAction(tr("Set as default DataBase"), this,
				SLOT(default_database()));
	acList += file->addAction(tr("&Close DataBase"), this,
		SLOT(close_database()), QKeySequence(QKeySequence::Close));

	a = new QAction(tr("Options"), this);
	connect(a, SIGNAL(triggered()), this, SLOT(setOptions()));
	a->setMenuRole(QAction::PreferencesRole);
	file->addAction(a);
	acList += a;

	file->addMenu(languageMenu);
	file->addSeparator();
	a = new QAction(tr("Exit"), this);
	connect(a, SIGNAL(triggered()), qApp, SLOT(quit()));
	a->setMenuRole(QAction::QuitRole);
	file->addAction(a);

	import = menuBar()->addMenu(tr("I&mport"));
	import->addAction(tr("Keys"), keyView, SLOT(load()) );
	import->addAction(tr("Requests"), reqView, SLOT(load()) );
	import->addAction(tr("Certificates"), certView, SLOT(load()) );
	import->addAction(tr("PKCS#12"), certView, SLOT(loadPKCS12()) );
	import->addAction(tr("PKCS#7"), certView, SLOT(loadPKCS7()) );
	import->addAction(tr("Template"), tempView, SLOT(load()) );
	import->addAction(tr("Revocation list"), crlView, SLOT(load()));
	import->addAction(tr("PEM file"), this, SLOT(loadPem()) );
	import->addAction(tr("paste PEM file"), this, SLOT(pastePem()));

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

	extra = menuBar()->addMenu(tr("Extra"));
	acList += extra->addAction(tr("&Dump DataBase"), this,
				SLOT(dump_database()));
	acList += extra->addAction(tr("C&hange DataBase password"), this,
				SLOT(changeDbPass()));
	acList += extra->addAction(tr("&Import old db_dump"), this,
				SLOT(import_dbdump()));
	acList += extra->addAction(tr("&Undelete items"), this,
				SLOT(undelete()));
	extra->addAction(tr("Generate DH parameter"), this,
				 SLOT(generateDHparam()));
	extra->addAction(tr("OID Resolver"), resolver, SLOT(show()));

	help = menuBar()->addMenu(tr("&Help") );
	help->addAction(tr("&Content"), this, SLOT(help()),
			QKeySequence::HelpContents);
	a = new QAction(tr("About"), this);
	connect(a, SIGNAL(triggered()), this, SLOT(about()));
	a->setMenuRole(QAction::AboutRole);
	help->addAction(a);
	wdMenuList += import;
	scardList += token;

	setItemEnabled(!dbfile.isEmpty());
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

void MainWindow::update_history_menu()
{
	historyMenu->clear();
	for (int i = 0; i < history.size(); i++) {
		QAction *a;
		QString txt = history[i];
		txt = txt.remove(0, txt.lastIndexOf(QDir::separator()) +1);
		if (txt.size() > 20)
			txt = QString("...") + txt.mid(txt.size() - 20);
		a = historyMenu->addAction(QString("%1 %2").arg(i).arg(txt));
		a->setData(QVariant(history[i]));
		a->setToolTip(history[i]);
	}
}

void MainWindow::open_database(QAction* a)
{
	changeDB(a->data().toString());
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
			xcaWarning msg(this, tr("Password verification error. Ignore keys ?"));
			msg.addButton(QMessageBox::Cancel);
			msg.addButton(QMessageBox::Ok)->setText(
					tr("Import anyway"));

			if (msg.exec() == QMessageBox::Cancel)
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
	if (dbfile.isEmpty())
		return;

	Options *opt = new Options(this);

	opt->setExtDnString(mandatory_dn);
	opt->setExpDnString(explicit_dn);
	opt->setStringOpt(string_opt);
	opt->setupPkcs11Provider(pkcs11path);
	opt->suppress->setCheckState(
		pki_base::suppress_messages ? Qt::Checked : Qt::Unchecked);
	opt->noColorize->setCheckState(
		pki_x509::dont_colorize_expiries ? Qt::Checked : Qt::Unchecked);
	opt->transDnEntries->setCheckState(
		translate_dn ? Qt::Checked : Qt::Unchecked);
	opt->onlyTokenHashes->setCheckState(
		pki_scard::only_token_hashes ? Qt::Checked : Qt::Unchecked);
	opt->disableNetscape->setCheckState(
		pki_x509::disable_netscape ? Qt::Checked : Qt::Unchecked);

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

	mandatory_dn = opt->getExtDnString();
	explicit_dn = opt->getExpDnString();
	mydb.set((const unsigned char *)CCHAR(mandatory_dn),
			mandatory_dn.length()+1, 1, setting, "mandatory_dn");
	if (explicit_dn.isEmpty())
		explicit_dn = explicit_dn_default;
	if (explicit_dn != explicit_dn_default) {
		mydb.set((const unsigned char *)CCHAR(explicit_dn),
			explicit_dn.length()+1, 1, setting, "explicit_dn");
	} else {
		mydb.first();
		if (!mydb.find(setting, "explicit_dn")) {
			mydb.erase();
		}
	}
	QString flags = getOptFlags();
	pki_base::suppress_messages = opt->suppress->checkState();
	pki_x509::dont_colorize_expiries = opt->noColorize->checkState();
	translate_dn = opt->transDnEntries->checkState();
	pki_scard::only_token_hashes = opt->onlyTokenHashes->checkState();
	pki_x509::disable_netscape = opt->disableNetscape->checkState();

	if (flags != getOptFlags()) {
		flags = getOptFlags();
		mydb.set((const unsigned char *)(CCHAR(flags)),
				flags.length()+1, 1, setting, "optionflags1");
		mydb.first();
		if (!mydb.find(setting, "suppress"))
			mydb.erase();
		certView->showHideSections();
		reqView->showHideSections();
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
void MainWindow::setOptFlags_old(QString flags)
{
	int s = flags.size(), i;
	QByteArray b = flags.toLatin1();

	pki_base::suppress_messages = false;
	pki_x509::dont_colorize_expiries = false;
	translate_dn = false;

	for (i=0; i<s; i++) {
		switch (b[i]) {
		case 'S':
			pki_base::suppress_messages = true;
			break;
		case 'C':
			pki_x509::dont_colorize_expiries = true;
			break;
		case 'T':
			translate_dn = true;
			break;
		}
	}
}

void MainWindow::setOptFlags(QString flags)
{
	bool old_disable_netscape = pki_x509::disable_netscape;
	pki_base::suppress_messages = false;
	pki_x509::dont_colorize_expiries = false;
	translate_dn = false;
	pki_scard::only_token_hashes = false;
	pki_x509::disable_netscape = false;

	foreach(QString flag, flags.split(",")) {
		if (flag == "suppress_messages")
			pki_base::suppress_messages = true;
		else if (flag == "dont_colorize_expiries")
			pki_x509::dont_colorize_expiries = true;
		else if (flag == "translate_dn")
			translate_dn = true;
		else if (flag == "only_token_hashes")
			pki_scard::only_token_hashes = true;
		else if (flag == "disable_netscape")
			pki_x509::disable_netscape = true;
		else if (!flag.isEmpty())
			fprintf(stderr, "Unkown flag '%s'\n", CCHAR(flag));
	}
	if (old_disable_netscape != pki_x509::disable_netscape) {
		certView->showHideSections();
		reqView->showHideSections();
	}
}

QString MainWindow::getOptFlags()
{
	QStringList flags;

	if (pki_base::suppress_messages)
		flags << "suppress_messages";
	if (pki_x509::dont_colorize_expiries)
		flags << "dont_colorize_expiries";
	if (translate_dn)
		flags << "translate_dn";
	if (pki_scard::only_token_hashes)
		flags << "only_token_hashes";
	if (pki_x509::disable_netscape)
		flags << "disable_netscape";
	return flags.join(",");
}
