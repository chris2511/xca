/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


//#define MDEBUG
#include "MainWindow.h"
#include "ImportMulti.h"
#include "lib/Passwd.h"
#include "lib/entropy.h"

#include <openssl/rand.h>

#include <QApplication>
#include <QClipboard>
#include <QMessageBox>
#include <QLabel>
#include <QPushButton>
#include <QListView>
#include <QLineEdit>
#include <QTextBrowser>
#include <QStatusBar>
#include <QList>
#include <QTimer>
#include <QMimeData>
#include <QInputDialog>

#include "lib/exception.h"
#include "lib/pki_evp.h"
#include "lib/pki_scard.h"
#include "lib/pki_pkcs12.h"
#include "lib/pki_multi.h"
#include "lib/load_obj.h"
#include "lib/pass_info.h"
#include "lib/func.h"
#include "lib/pkcs11.h"
#include "lib/builtin_curves.h"
#include "ui_About.h"
#include "PwDialog.h"

QPixmap *MainWindow::keyImg = NULL, *MainWindow::csrImg = NULL,
	*MainWindow::certImg = NULL, *MainWindow::tempImg = NULL,
	*MainWindow::nsImg = NULL, *MainWindow::revImg = NULL,
	*MainWindow::appIco = NULL, *MainWindow::scardImg = NULL,
	*MainWindow::doneIco = NULL, *MainWindow::warnIco = NULL;

db_key *MainWindow::keys = NULL;
db_x509req *MainWindow::reqs = NULL;
db_x509	*MainWindow::certs = NULL;
db_temp	*MainWindow::temps = NULL;
db_crl	*MainWindow::crls = NULL;

NIDlist *MainWindow::eku_nid = NULL;
NIDlist *MainWindow::dn_nid = NULL;
NIDlist *MainWindow::aia_nid = NULL;

QString MainWindow::mandatory_dn;
QString MainWindow::explicit_dn;
QString MainWindow::explicit_dn_default = QString("C,ST,L,O,OU,CN,emailAddress");

OidResolver *MainWindow::resolver = NULL;

void MainWindow::enableTokenMenu(bool enable)
{
	foreach(QWidget *w, scardList) {
		w->setEnabled(enable);
	}
}

void MainWindow::load_engine()
{
	try {
		pkcs11::load_libs(pkcs11path, false);
	} catch (errorEx &err) {
		Error(err);
	}
	enableTokenMenu(pkcs11::loaded());
}

MainWindow::MainWindow(QWidget *parent)
	:QMainWindow(parent)
{
	dbindex = new QLabel();
	dbindex->setFrameStyle(QFrame::Plain | QFrame::NoFrame);
	dbindex->setMargin(6);

	dn_translations_setup();
	statusBar()->addWidget(dbindex, 1);

	setupUi(this);
	setWindowTitle(XCA_TITLE);

	resolver = new OidResolver(NULL);
	resolver->setWindowTitle(XCA_TITLE);

	wdList << keyButtons << reqButtons << certButtons <<
		tempButtons <<	crlButtons;

	historyMenu = NULL;
	init_menu();
	setItemEnabled(false);

	init_images();
	homedir = getHomeDir();

#ifdef MDEBUG
	CRYPTO_malloc_debug_init();
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
	fprintf(stderr, "malloc() debugging on.\n");
#endif

	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	EVP_add_digest_alias(SN_sha1,SN_ecdsa_with_SHA1);
	EVP_add_digest_alias(SN_sha224,SN_ecdsa_with_SHA224);
	EVP_add_digest_alias(SN_sha256,SN_ecdsa_with_SHA256);
	EVP_add_digest_alias(SN_sha256,SN_dsa_with_SHA256);
	EVP_add_digest_alias(SN_sha384,SN_ecdsa_with_SHA384);
	EVP_add_digest_alias(SN_sha512,SN_ecdsa_with_SHA512);
	/* read in all our own OIDs */
	initOIDs();

	eku_nid = read_nidlist("eku.txt");
	dn_nid = read_nidlist("dn.txt");
	aia_nid = read_nidlist("aia.txt");

	setAcceptDrops(true);

	searchEdit = new QLineEdit();

	keyView->setMainwin(this, searchEdit);
	reqView->setMainwin(this, searchEdit);
	certView->setMainwin(this, searchEdit);
	tempView->setMainwin(this, searchEdit);
	crlView->setMainwin(this, searchEdit);
}

void MainWindow::dropEvent(QDropEvent *event)
{
	QList<QUrl> urls = event->mimeData()->urls();
	QUrl u;
	QStringList files;

	foreach(u, urls) {
		QString s = u.toLocalFile();
		files << s;
	}
	openURLs(files);
	event->acceptProposedAction();
}

void MainWindow::openURLs(QStringList &files)
{
	urlsToOpen = files;
	QTimer::singleShot(100, this, SLOT(openURLs()));
}

void MainWindow::openURLs()
{
	QStringList failed;
	QString s;
	ImportMulti *dlgi = new ImportMulti(this);

	foreach(s, urlsToOpen) {
	        pki_multi *pki = probeAnything(s);
		if (pki && !pki->count())
			failed << s;
	        dlgi->addItem(pki);
	}
	urlsToOpen.clear();
	dlgi->execute(1, failed);
	delete dlgi;
}

void MainWindow::dragEnterEvent(QDragEnterEvent *event)
{
	if (event->mimeData()->hasUrls())
		event->acceptProposedAction();
}

void MainWindow::setItemEnabled(bool enable)
{
	foreach(QWidget *w, wdList) {
		w->setEnabled(enable);
	}
	foreach(QWidget *w, wdMenuList) {
		w->setEnabled(enable);
	}
	foreach(QAction *a, acList) {
		a->setEnabled(enable);
	}
	enableTokenMenu(pkcs11::loaded());
}

/* creates a new nid list from the given filename */
NIDlist *MainWindow::read_nidlist(QString name)
{
	NIDlist nl;
	name = QDir::separator() + name;

#ifndef WIN32
	/* first try $HOME/xca/ */
	nl = readNIDlist(getUserSettingsDir() + name);
#if !defined(Q_WS_MAC)
	if (nl.count() == 0){
		/* next is /etx/xca/... */
		nl = readNIDlist(QString(ETC) + name);
	}
#endif
#endif
	if (nl.count() == 0) {
		/* look at /usr/(local/)share/xca/ */
		nl = readNIDlist(getPrefix() + name);
	}
	return new NIDlist(nl);
}

void MainWindow::init_images()
{
	keyImg = loadImg("bigkey.png");
	csrImg = loadImg("bigcsr.png");
	certImg = loadImg("bigcert.png");
	tempImg = loadImg("bigtemp.png");
	nsImg = loadImg("netscape.png");
	revImg = loadImg("bigcrl.png");
	scardImg = loadImg("bigscard.png");
	appIco = loadImg("key.xpm");
	doneIco = loadImg("done.png");
	warnIco = loadImg("warn.png");
	bigKey->setPixmap(*keyImg);
	bigCsr->setPixmap(*csrImg);
	bigCert->setPixmap(*certImg);
	bigTemp->setPixmap(*tempImg);
	bigRev->setPixmap(*revImg);
	setWindowIcon(*appIco);
	pki_evp::icon[0] = loadImg("key.png");
	pki_evp::icon[1] = loadImg("halfkey.png");
	pki_scard::icon[0] = loadImg("scard.png");
	pki_x509req::icon[0] = loadImg("req.png");
	pki_x509req::icon[1] = loadImg("reqkey.png");
	pki_x509req::icon[2] = loadImg("spki.png");
	pki_x509req::icon[3] = doneIco;
	pki_x509::icon[0] = loadImg("validcert.png");
	pki_x509::icon[1] = loadImg("validcertkey.png");
	pki_x509::icon[2] = loadImg("invalidcert.png");
	pki_x509::icon[3] = loadImg("invalidcertkey.png");
	pki_x509::icon[4] = loadImg("revoked.png");
	pki_x509::icon[5] = doneIco;
	pki_temp::icon = loadImg("template.png");
	pki_crl::icon = loadImg("crl.png");
}

void MainWindow::read_cmdline(int argc, char *argv[])
{
	int cnt = 1, opt = 0, force_load = 0;
	char *arg = NULL;
	exitApp = 0;
	QStringList failed;
	ImportMulti *dlgi = new ImportMulti(this);
	while (cnt < argc) {
		arg = argv[cnt];
		if (arg[0] == '-') { // option
			opt = 1;
			switch (arg[1]) {
				case 'c':
				case 'r':
				case 'k':
				case 'p':
				case '7':
				case 'l':
				case 't':
				case 'P':
					break;
				case 'd':
					force_load=1;
					break;
				case 'v':
					cmd_version();
					opt=0;
					break;
				case 'x':
					exitApp = 1;
					opt=0;
					break;
				case 'h':
					cmd_help(NULL);
					opt=0;
					break;
				default:
					 cmd_help(CCHAR(tr("no such option: %1").arg(arg)));
			}
			if (arg[2] != '\0' && opt==1) {
				 arg+=2;
			} else {
				cnt++;
				continue;
			}
		}
		QString file = filename2QString(arg);
		if (force_load) {
			if (changeDB(file) == 2)
				exitApp = 1;
			force_load = 0;
		} else {
			int ret;
			pki_multi *pki = probeAnything(file, &ret);
			if (!pki && ret == 2)
				 exitApp = 1;
			if (pki && !pki->count())
				failed << file;
			dlgi->addItem(pki);
		}
		cnt++;
	}
	dlgi->execute(1, failed); /* force showing of import dialog */
	if (dlgi->result() == QDialog::Rejected)
		exitApp = 1;
	delete dlgi;
}

void MainWindow::loadPem()
{
	load_pem l;
	if (keys)
		keys->load_default(l);
}

bool MainWindow::pastePem(QString text)
{
	bool success = false;
	QByteArray pemdata = text.toLatin1();
	BIO *b = BIO_QBA_mem_buf(pemdata);
	check_oom(b);
	pki_multi *pem = NULL;
	ImportMulti *dlgi = NULL;
	try {
		pem = new pki_multi();
		dlgi = new ImportMulti(this);
		pem->fromPEM_BIO(b, QString("paste"));
		success = pem->count() != 0;
		dlgi->addItem(pem);
		pem = NULL;
		dlgi->execute(1);
	}
	catch (errorEx &err) {
		Error(err);
	}
	if (dlgi)
		delete dlgi;
	if (pem)
		delete pem;
	BIO_free(b);
	return success;
}

void MainWindow::pastePem()
{
	Ui::About ui;
	QClipboard *cb = QApplication::clipboard();
	QString text;

	text = cb->text(QClipboard::Selection);
	if (text.isEmpty())
		text = cb->text(QClipboard::Clipboard);

	if (!text.isEmpty())
		if (pastePem(text))
			return;

	QDialog *input = new QDialog(this, 0);

	ui.setupUi(input);
	delete ui.textbox;
	QTextEdit *textbox = new QTextEdit(input);
	ui.vboxLayout->addWidget(textbox);
	ui.button->setText(tr("Import PEM data"));
	input->setWindowTitle(XCA_TITLE);
	textbox->setPlainText(text);
	if (input->exec())
		text = textbox->toPlainText();
	delete input;

	if (!text.isEmpty())
		pastePem(text);
}

void MainWindow::initToken()
{
	bool ok;
	if (!pkcs11::loaded())
		return;
	try {
		pkcs11 p11;
		slotid slot;
		Passwd pin;
		int ret;

		if (!p11.selectToken(&slot, this))
			return;

		tkInfo ti = p11.tokenInfo(slot);
		QString slotname = QString("%1 (#%2)").
			arg(ti.label()).arg(ti.serial());

		pass_info p(XCA_TITLE,
			tr("Please enter the original SO PIN (PUK) of the token '%1'").
			arg(slotname) + "\n" + ti.pinInfo());
		p.setPin();
		if (ti.tokenInitialized()) {
			ret = PwDialog::execute(&p, &pin, false);
		} else {
			p.setDescription(tr("Please enter the new SO PIN (PUK) of the token '%1'").
			arg(slotname) + "\n" + ti.pinInfo());
			ret = PwDialog::execute(&p, &pin, true);
		}
		if (ret != 1)
			return;
		QString label = QInputDialog::getText(this, XCA_TITLE,
			tr("The new label of the token '%1'").
			arg(slotname), QLineEdit::Normal, QString(), &ok);
		if (!ok)
			return;
		p11.initToken(slot, pin.constUchar(), pin.size(), label);
	} catch (errorEx &err) {
		Error(err);
        }
}

void MainWindow::changePin(bool so)
{
	if (!pkcs11::loaded())
		return;
	try {
		pkcs11 p11;
		slotid slot;

		if (!p11.selectToken(&slot, this))
			return;
		p11.changePin(slot, so);
	} catch (errorEx &err) {
		Error(err);
        }
}

void MainWindow::changeSoPin()
{
	changePin(true);
}

void MainWindow::initPin()
{
	if (!pkcs11::loaded())
		return;
	try {
		pkcs11 p11;
		slotid slot;

		if (!p11.selectToken(&slot, this))
			return;
		p11.initPin(slot);
	} catch (errorEx &err) {
		Error(err);
        }
}


void MainWindow::manageToken()
{
	pkcs11 p11;
	slotid slot;
	pki_scard *card = NULL;
	pki_x509 *cert = NULL;
	ImportMulti *dlgi = NULL;

	if (!pkcs11::loaded())
		return;

	try {
		if (!p11.selectToken(&slot, this))
			return;

		ImportMulti *dlgi = new ImportMulti(this);

		dlgi->tokenInfo(slot);
		QList<CK_OBJECT_HANDLE> objects;

		QList<CK_MECHANISM_TYPE> ml = p11.mechanismList(slot);
		if (ml.count() == 0)
			ml << CKM_SHA1_RSA_PKCS;
		pk11_attlist atts(pk11_attr_ulong(CKA_CLASS,
				CKO_PUBLIC_KEY));

		p11.startSession(slot);
		p11.getRandom();
		objects = p11.objectList(atts);

		for (int j=0; j< objects.count(); j++) {
			card = new pki_scard("");
			try {
				card->load_token(p11, objects[j]);
				card->setMech_list(ml);
				dlgi->addItem(card);
			} catch (errorEx &err) {
				Error(err);
				delete card;
			}
			card = NULL;
		}
		atts.reset();
		atts << pk11_attr_ulong(CKA_CLASS, CKO_CERTIFICATE) <<
			pk11_attr_ulong(CKA_CERTIFICATE_TYPE,CKC_X_509);
		objects = p11.objectList(atts);

		for (int j=0; j< objects.count(); j++) {
			cert = new pki_x509("");
			try {
				cert->load_token(p11, objects[j]);
				cert->setTrust(2);
				dlgi->addItem(cert);
			} catch (errorEx &err) {
				Error(err);
				delete cert;
			}
			cert = NULL;
		}
		if (dlgi->entries() == 0) {
			tkInfo ti = p11.tokenInfo();
			XCA_INFO(tr("The token '%1' did not contain any keys or certificates").arg(ti.label()));
		} else {
			dlgi->execute(true);
		}
	} catch (errorEx &err) {
		Error(err);
        }
	if (card)
		delete card;
	if (cert)
		delete cert;
	if (dlgi)
		delete dlgi;
}

MainWindow::~MainWindow()
{
	close_database();
	ERR_free_strings();
	EVP_cleanup();
	OBJ_cleanup();
	if (eku_nid)
		delete eku_nid;
	if (dn_nid)
		delete dn_nid;
	if (aia_nid)
		delete aia_nid;
	delete dbindex;
#ifdef MDEBUG
	fprintf(stderr, "Memdebug:\n");
	CRYPTO_mem_leaks_fp(stderr);
#endif
}

void MainWindow::closeEvent(QCloseEvent *e)
{
	if (resolver) {
		delete resolver;
	}
	QMainWindow::closeEvent(e);
}

QString makeSalt(void)
{
	unsigned char rand[2];
	char saltbuf[10];

	Entropy::get(rand, 2);
	snprintf(saltbuf, 10, "S%02X%02X", rand[0], rand[1]);
	return QString(saltbuf);
}

int MainWindow::checkOldGetNewPass(Passwd &pass)
{
	QString passHash;
	db mydb(dbfile);

	if (!mydb.find(setting, "pwhash")) {
		char *cpass;
		pass_info p(tr("Current Password"),
			tr("Please enter the current database password"), this);

		if ((cpass = (char *)mydb.load(NULL))) {
			passHash = cpass;
			free(cpass);
		}
		/* Try empty password */
		if (pki_evp::sha512passwd(pass, passHash) != passHash) {
			/* Not the empty password, check it */
			if (PwDialog::execute(&p, &pass, false) != 1)
				return 0;
		}

		if (pki_evp::sha512passwd(pass, passHash) != passHash) {
			XCA_WARN(tr("The entered password is wrong"));
			return 0;
		}
	}

	pass_info p(tr("New Password"), tr("Please enter the new password "
			"to encrypt your private keys in the database-file"),
			this);

	return PwDialog::execute(&p, &pass, true) != 1 ? 0 : 1;
}

void MainWindow::changeDbPass()
{
	Passwd pass;
	QString tempn = dbfile + "{recrypt}";

	if (!checkOldGetNewPass(pass))
		return;

	try {
		if (!QFile::copy(dbfile, tempn))
			throw errorEx("Could not create temporary file: " +
				tempn);

		QString passhash = updateDbPassword(tempn, pass);
		QFile new_file(tempn);
		/* closing the database erases 'dbfile' */
		QString dbfile_bkup = dbfile;
		close_database();
		db mydb(dbfile_bkup);
		if (mydb.mv(new_file))
			throw errorEx(QString("Failed to rename %1 to %2").
						arg(tempn).arg(dbfile_bkup));
		dbfile = dbfile_bkup;
		pki_evp::passHash = passhash;
		pki_evp::passwd = pass;
		init_database();
	} catch (errorEx &ex) {
		QFile::remove(tempn);
		Error(ex);
	}
}

QString MainWindow::updateDbPassword(QString newdb, Passwd pass)
{
	db mydb(newdb);

	QString salt = makeSalt();
	QString passhash = pki_evp::sha512passwd(pass, salt);
	mydb.set((const unsigned char *)CCHAR(passhash),
		passhash.length()+1, 1, setting, "pwhash");

	QList<pki_evp*> klist;
	mydb.first();
	while (mydb.find(asym_key, QString()) == 0) {
		QString s;
		pki_evp *key;
		unsigned char *p;
		db_header_t head;

		p = mydb.load(&head);
		if (!p)
			throw errorEx("Failed to load item");
		key = new pki_evp();
		if (key->getVersion() < head.version) {
			int v = key->getVersion();
			free(p);
			delete key;
			throw errorEx(QString("Item[%1]: Version %2 "
				"> known version: %3 -> ignored")
				.arg(head.name).arg(head.version).arg(v)
			);
		}
		key->setIntName(QString::fromUtf8(head.name));

		try {
			key->fromData(p, &head);
		}
		catch (errorEx &err) {
			err.appendString(key->getIntName());
			free(p);
			delete key;
			throw err;
		}
		free(p);
		if (key && key->getOwnPass() == pki_key::ptCommon &&
			!key->isPubKey())
		{
			EVP_PKEY *evp = key->decryptKey();
			key->set_evp_key(evp);
			key->encryptKey(pass.constData());
			klist << key;
		} else if (key)
			delete key;

		if (mydb.next())
			break;
	}
	for (int i=0; i< klist.count(); i++) {
		pki_evp *key = klist[i];
		QByteArray ba = key->toData();
		mydb.set((const unsigned char*)ba.constData(), ba.count(),
			key->getVersion(), key->getType(), key->getIntName());
		delete key;
	}
	return passhash;
}

int MainWindow::initPass()
{
	db mydb(dbfile);
	char *pass;
	pki_evp::passHash = QString();
	QString salt;
	int ret;

	pass_info p(tr("New Password"), tr("Please enter a password, "
			"that will be used to encrypt your private keys "
			"in the database file:\n%1").
			arg(compressFilename(dbfile)), this);

	if (!mydb.find(setting, "pwhash")) {
		if ((pass = (char *)mydb.load(NULL))) {
			pki_evp::passHash = pass;
			free(pass);
		}
	}
	if (pki_evp::passHash.isEmpty()) {
		ret = PwDialog::execute(&p, &pki_evp::passwd, true, true);
		if (ret != 1)
			return ret;
		salt = makeSalt();
		pki_evp::passHash = pki_evp::sha512passwd(pki_evp::passwd,salt);
		mydb.set((const unsigned char *)CCHAR(pki_evp::passHash),
			pki_evp::passHash.length()+1, 1, setting, "pwhash");
	} else {
		ret = 0;
		while (pki_evp::sha512passwd(pki_evp::passwd, pki_evp::passHash)
				!= pki_evp::passHash)
		{
			if (ret)
				XCA_WARN(
				tr("Password verify error, please try again"));
			p.setTitle(tr("Password"));
			p.setDescription(tr("Please enter the password for unlocking the database:\n%1").arg(compressFilename(dbfile)));
			ret = PwDialog::execute(&p, &pki_evp::passwd,
						false, true);
			if (ret != 1) {
				pki_evp::passwd = QByteArray();
				return ret;
			}
			if (pki_evp::passHash.left(1) == "S")
				continue;
			/* Start automatic update from md5 to salted sha512
			 * if the password is correct. my md5 hash does not
			 * start with 'S', while my new hash does. */
			if (pki_evp::md5passwd(pki_evp::passwd) ==
						pki_evp::passHash )
			{
				salt = makeSalt();
				pki_evp::passHash = pki_evp::sha512passwd(
						pki_evp::passwd, salt);
				mydb.set((const unsigned char *)CCHAR(
					pki_evp::passHash),
					pki_evp::passHash.length() +1, 1,
					setting, "pwhash");
			}
		}
	}
	if (pki_evp::passwd.isNull())
		pki_evp::passwd = "";
	return 1;
}

void MainWindow::Error(errorEx &err)
{
	if (err.isEmpty())
		 return;
	QString msg =  tr("The following error occured:") + "\n" + err.getString();
	xcaWarning box(NULL, msg);
	box.addButton(QMessageBox::Apply)->setText(tr("Copy to Clipboard"));
	box.addButton(QMessageBox::Ok);
	if (box.exec() == QMessageBox::Apply) {
		QClipboard *cb = QApplication::clipboard();
		if (cb->supportsSelection())
			cb->setText(msg, QClipboard::Selection);
		else
			cb->setText(msg);
	}
}

QString MainWindow::getPath()
{
	return workingdir;
}

void MainWindow::setPath(QString str)
{
	db mydb(dbfile);
	workingdir = str;
	mydb.set((const unsigned char *)CCHAR(str), str.length()+1, 1, setting, "workingdir");
}

void MainWindow::setDefaultKey(QString str)
{
	db mydb(dbfile);
	mydb.set((const unsigned char *)CCHAR(str), str.length()+1, 1, setting, "defaultkey");
}

void MainWindow::connNewX509(NewX509 *nx)
{
	connect( nx, SIGNAL(genKey(QString)), keys, SLOT(newItem(QString)) );
	connect( keys, SIGNAL(keyDone(QString)), nx, SLOT(newKeyDone(QString)) );
	connect( nx, SIGNAL(showReq(QString)), reqs, SLOT(showItem(QString)));
}

void MainWindow::importAnything(QString file)
{
	ImportMulti *dlgi = new ImportMulti(this);
	QStringList failed;
	pki_multi *pki = probeAnything(file);
	if (pki && !pki->count())
		failed << file;
	dlgi->addItem(pki);
	dlgi->execute(1, failed);
	delete dlgi;
}

pki_multi *MainWindow::probeAnything(QString file, int *ret)
{
	pki_multi *pki = new pki_multi();

	try {
		if (file.endsWith(".xdb")) {
			try {
				int r;
				db *mydb = new db(file);
				mydb->verify_magic();
				delete mydb;
				r = changeDB(file);
				delete pki;
				if (ret)
					*ret = r;
				return NULL;
			} catch (errorEx &err) {
			}
		}
		pki->probeAnything(file);
	} catch (errorEx &err) {
		Error(err);
	}
	return pki;
}

void MainWindow::generateDHparam()
{
	DH *dh = NULL;
	FILE *fp = NULL;
	QProgressBar *bar = NULL;
	bool ok;
	int num = QInputDialog::getDouble(this, XCA_TITLE, tr("Diffie-Hellman parameters are needed for different applications, but not handled by XCA.\nPlease enter the DH parameter bits"),
		1024, 1024, 4096, 0, &ok);

	if (!ok)
		return;
	/*
	 * 1024:   6 sec
	 * 2048:  38 sec
	 * 4096: 864 sec
	 */

	Entropy::seed_rng();
	try {
		QStatusBar *status = statusBar();
		bar = new QProgressBar();
		check_oom(bar);
		bar->setMinimum(0);
		bar->setMaximum(100);
		status->addPermanentWidget(bar, 1);
		dh = DH_generate_parameters(num, 2, inc_progress_bar, bar);
		status->removeWidget(bar);
		openssl_error();

		QString fname = QString("%1/dh%2.pem").arg(homedir).arg(num);
		fname = QFileDialog::getSaveFileName(this, QString(),
			fname, "All files ( * )", NULL);
		if (fname == "")
			throw errorEx("");
		fp = fopen_write(fname);
		if (fp == NULL) {
			throw errorEx(tr("Error opening file: '%1': %2").
				arg(fname).arg(strerror(errno)));
		}
		PEM_write_DHparams(fp, dh);
		openssl_error();
	} catch (errorEx &err) {
		Error(err);
	}
	if (dh)
		DH_free(dh);
	if (fp)
		fclose(fp);
	if (bar)
		delete bar;
}

void MainWindow::changeEvent(QEvent *event)
{
	if (event->type() == QEvent::LanguageChange) {
		QList<db_base*> models;
		retranslateUi(this);
		dn_translations_setup();
		init_menu();
		update_history_menu();
		models << keys << reqs << certs << crls << temps;
		foreach(db_base *model, models) {
			if (model)
				model->updateHeaders();
		}
		if (!dbfile.isEmpty())
			dbindex->setText(tr("Database") + ": " + dbfile);
	}
	QMainWindow::changeEvent(event);
}

void MainWindow::keyPressEvent(QKeyEvent *e)
{
	if (e->modifiers() != Qt::ControlModifier) {
		QMainWindow::keyPressEvent(e);
		return;
	}
	int siz = XCA_application::tableFont.pointSize();
	QList<XcaTreeView*> views;

	switch (e->key()) {
	case Qt::Key_Plus:
		XCA_application::tableFont.setPointSize(siz +1);
		break;
	case Qt::Key_Minus:
		if (siz > 4) {
			XCA_application::tableFont.setPointSize(siz -1);
		}
		break;
	default:
		QMainWindow::keyPressEvent(e);
		return;
	}
	views << keyView << reqView << certView << crlView << tempView;
	foreach(XcaTreeView *v, views) {
		if (v) {
			v->header()->resizeSections(
					QHeaderView::ResizeToContents);
			v->reset();
		}
	}
	update();
}
