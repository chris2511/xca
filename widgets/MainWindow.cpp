/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


//#define MDEBUG
#include "MainWindow.h"
#include "ImportMulti.h"
#include "dhgen.h"
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
#include <QThread>
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
#include "XcaDialog.h"
#include "PwDialog.h"
#include "OpenDb.h"

db_key *MainWindow::keys = NULL;
db_x509req *MainWindow::reqs = NULL;
db_x509	*MainWindow::certs = NULL;
db_temp	*MainWindow::temps = NULL;
db_crl	*MainWindow::crls = NULL;

OidResolver *MainWindow::resolver = NULL;

void MainWindow::enableTokenMenu(bool enable)
{
	foreach(QWidget *w, scardList) {
		w->setEnabled(enable);
	}
}

void MainWindow::load_engine()
{
	pkcs11::libraries.load(Settings["pkcs11path"]);
	enableTokenMenu(pkcs11::libraries.loaded());
}

void MainWindow::initResolver()
{
	bool shown = false;
	QString search;

	if (resolver) {
		shown = resolver->isVisible();
		search = resolver->input->text();
		delete resolver;
	}
	resolver = new OidResolver(NULL);
	resolver->setWindowTitle(XCA_TITLE);
	if (shown)
		resolver->searchOid(search);
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

	initResolver();

	wdList << keyButtons << reqButtons << certButtons <<
		tempButtons <<	crlButtons;

	QStringList drivers = QSqlDatabase::drivers();
	foreach(QString driver, drivers) {
//		QSqlDatabase d = QSqlDatabase::addDatabase(driver, driver +"_C");
		qDebug() << "DB driver:" << driver;
	}

	historyMenu = NULL;
	init_menu();
	setItemEnabled(false);

	init_images();
	homedir = getHomeDir();

#ifdef MDEBUG
	CRYPTO_malloc_debug_init();
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
	qWarning() << "malloc() debugging on.";
#endif

	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	EVP_add_digest_alias(SN_sha1,SN_ecdsa_with_SHA1);
	EVP_add_digest_alias(SN_sha224,SN_ecdsa_with_SHA224);
	EVP_add_digest_alias(SN_sha256,SN_ecdsa_with_SHA256);
	EVP_add_digest_alias(SN_sha256,SN_dsa_with_SHA256);
	EVP_add_digest_alias(SN_sha384,SN_ecdsa_with_SHA384);
	EVP_add_digest_alias(SN_sha512,SN_ecdsa_with_SHA512);

	setAcceptDrops(true);

	searchEdit = new QLineEdit();
	searchEdit->setPlaceholderText(tr("Search"));

	keyView->setMainwin(this, searchEdit);
	reqView->setMainwin(this, searchEdit);
	certView->setMainwin(this, searchEdit);
	tempView->setMainwin(this, searchEdit);
	crlView->setMainwin(this, searchEdit);
	keys = NULL; reqs = NULL; certs = NULL; temps = NULL; crls = NULL;

	keyView->setIconSize(QPixmap(":keyIco").size());
	reqView->setIconSize(QPixmap(":reqIco").size());
	certView->setIconSize(QPixmap(":validcertIco").size());
	tempView->setIconSize(QPixmap(":templateIco").size());
	crlView->setIconSize(QPixmap(":crlIco").size());

	dhgen = NULL;
	dhgenBar = new QProgressBar();
	check_oom(dhgenBar);
	dhgenBar->setMinimum(0);
	dhgenBar->setMaximum(0);
}

void MainWindow::dropEvent(QDropEvent *event)
{
	if (event->mimeData()->hasUrls()) {
		QList<QUrl> urls = event->mimeData()->urls();
		QUrl u;
		QStringList files;

		foreach(u, urls) {
			QString s = u.toLocalFile();
			files << s;
		}
		openURLs(files);
		event->acceptProposedAction();
	} else if (event->mimeData()->hasText()) {
		event->acceptProposedAction();
		pastePem(event->mimeData()->text());
	}
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
		int ret;
		pki_multi *pki = probeAnything(s, &ret);
		if (ret)
			failed << s;
		else
			dlgi->addItem(pki);
	}
	urlsToOpen.clear();
	dlgi->execute(1, failed);
	delete dlgi;
}

void MainWindow::dragEnterEvent(QDragEnterEvent *event)
{
	if (event->mimeData()->hasFormat(X_XCA_DRAG_DATA))
		return;

	if (event->mimeData()->hasUrls() || event->mimeData()->hasText())
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
	enableTokenMenu(pkcs11::libraries.loaded());
}

void MainWindow::init_images()
{
	bigKey->setPixmap(QPixmap(":keyImg"));
	bigCsr->setPixmap(QPixmap(":csrImg"));
	bigCert->setPixmap(QPixmap(":certImg"));
	bigTemp->setPixmap(QPixmap(":tempImg"));
	bigRev->setPixmap(QPixmap(":revImg"));
	setWindowIcon(QPixmap(":appIco"));
}

void MainWindow::read_cmdline(int argc, char *argv[])
{
	int cnt = 1, opt = 0, force_load = 0, export_index = 0;
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
				case 'i':
					export_index=1;
					break;
				case 'I':
					export_index=2;
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
		} else if (export_index) {
			if (exportIndex(file, (export_index == 2)) == 2)
				exitApp = 1;
			export_index = 0;
		} else {
			int ret;
			pki_multi *pki = probeAnything(file, &ret);
			if (!pki) {
				if (ret == 2)
					exitApp = 1;
				else if (ret == 1)
					failed << file;
			}
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

bool MainWindow::pastePem(QString text, bool silent)
{
	bool success = false;
	QByteArray pemdata = text.toLatin1();
	if (pemdata.size() == 0)
		return false;

	pki_multi *pem = NULL;
	ImportMulti *dlgi = NULL;
	try {
		pem = new pki_multi();
		dlgi = new ImportMulti(this);
		pem->fromPEMbyteArray(pemdata, QString());
		success = pem->count() != 0;
		dlgi->addItem(pem);
		pem = NULL;
		dlgi->execute(1);
	}
	catch (errorEx &err) {
		if (!silent)
			Error(err);
	}
	if (dlgi)
		delete dlgi;
	if (pem)
		delete pem;
	return success;
}

void MainWindow::pastePem()
{
	QClipboard *cb = QApplication::clipboard();
	QString text;

	text = cb->text(QClipboard::Selection);
	if (text.isEmpty())
		text = cb->text(QClipboard::Clipboard);

	if (!text.isEmpty())
		if (pastePem(text, true))
			return;


	QTextEdit *textbox = new QTextEdit();
	textbox->setPlainText(text);
	XcaDialog *input = new XcaDialog(this, x509, textbox,
			tr("Import PEM data"), QString());
	input->noSpacer();
	if (input->exec()) {
		text = textbox->toPlainText();
		if (!text.isEmpty())
			pastePem(text);
	}
	delete input;
}

void MainWindow::initToken()
{
	bool ok;
	if (!pkcs11::libraries.loaded())
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
			p.setDescription(tr("Please enter the new SO PIN (PUK) for the token '%1'").
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
	if (!pkcs11::libraries.loaded())
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
	if (!pkcs11::libraries.loaded())
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

	if (!pkcs11::libraries.loaded())
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
	ERR_free_strings();
	EVP_cleanup();
	OBJ_cleanup();
	delete dbindex;
#ifdef MDEBUG
	fprintf(stderr, "Memdebug:\n");
	CRYPTO_mem_leaks_fp(stderr);
#endif
}

void MainWindow::closeEvent(QCloseEvent *e)
{
	if (dhgen) {
		if (!XCA_YESNO("Abort Diffie-Hellmann parameter generation?")){
			e->ignore();
			return;
		}
		dhgen->terminate();
	}
	if (resolver) {
		delete resolver;
	}
	close_database();
	QMainWindow::closeEvent(e);
}

QString makeSalt(void)
{
	QString s = "T";
	unsigned char rand[8];

	Entropy::get(rand, sizeof rand);
	for (unsigned i=0; i< sizeof rand; i++)
		s += QString("%1").arg(rand[i]);
	return s;
}

int MainWindow::checkOldGetNewPass(Passwd &pass)
{
	QString passHash = Settings["pwhash"];
	if (!passHash.isEmpty()) {
		pass_info p(tr("Current Password"),
			tr("Please enter the current database password"), this);

		/* Try empty password */
		if (pki_evp::sha512passwT(pass, passHash) != passHash) {
			/* Not the empty password, check it */
			if (PwDialog::execute(&p, &pass, false) != 1)
				return 0;
		}

		if (pki_evp::sha512passwT(pass, passHash) != passHash) {
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
	XSqlQuery q;
	QSqlDatabase db = QSqlDatabase::database();

	if (!checkOldGetNewPass(pass))
		return;

	QString salt = makeSalt();
	QString passhash = pki_evp::sha512passwT(pass, salt);
	QList<pki_evp*> key_list = keys->sqlSELECTpki<pki_evp>(
		"SELECT item FROM private_keys WHERE ownPass=0");

	try {
		Transaction;
		if (!TransBegin()) {
			errorEx e(tr("Transaction start failed"));
			Error(e);
			return;
		}
		foreach(pki_evp *key, key_list) {
			EVP_PKEY *evp = key->decryptKey();
			key->set_evp_key(evp);
			key->encryptKey(pass.constData());
			key->sqlUpdatePrivateKey();
		}
		Settings["pwhash"] = passhash;
		TransCommit();
		pki_evp::passHash = passhash;
		pki_evp::passwd = pass;
	} catch (errorEx &e) {
		Error(e);
	}
}

int MainWindow::initPass(QString dbName)
{
	QString passhash = Settings["pwhash"];
	return initPass(dbName, passhash);
}

static void pwhash_upgrade()
{
	/* Start automatic update from sha512 to sha512*8000
	 * if the password is correct. The old sha512 hash does
	 * start with 'S', while the new hash starts with T. */

	/* Start automatic update from md5 to salted sha512*8000
	 * if the password is correct. The md5 hash does not
	 * start with 'S' or 'T, but with a hex-digit */
	if (pki_evp::passHash.startsWith("T")) {
		/* Fine, current hash function used. */
		return;
	}
	if (pki_evp::sha512passwd(pki_evp::passwd,
				pki_evp::passHash) == pki_evp::passHash ||
	    pki_evp::md5passwd(pki_evp::passwd) == pki_evp::passHash)
	{
		QString salt = makeSalt();
		pki_evp::passHash = pki_evp::sha512passwT(
				pki_evp::passwd, salt);
	}
}

int MainWindow::initPass(QString dbName, QString passhash)
{
	pki_evp::passHash = QString();
	QString salt, pass;
	int ret;

	pass_info p(tr("New Password"), tr("Please enter a password, "
			"that will be used to encrypt your private keys "
			"in the database:\n%1").
			arg(compressFilename(dbName)), this);

	pki_evp::passHash = passhash;
	if (pki_evp::passHash.isEmpty()) {
		ret = PwDialog::execute(&p, &pki_evp::passwd, true, true);
		if (ret != 1)
			return ret;
		salt = makeSalt();
		pki_evp::passHash =pki_evp::sha512passwT(pki_evp::passwd,salt);
		Settings["pwhash"] = pki_evp::passHash;
	} else {
		pwhash_upgrade();
		ret = 0;
		while (pki_evp::sha512passwT(pki_evp::passwd, pki_evp::passHash)
				!= pki_evp::passHash)
		{
			if (ret)
				XCA_WARN(
				tr("Password verify error, please try again"));
			p.setTitle(tr("Password"));
			p.setDescription(tr("Please enter the password for unlocking the database:\n%1").arg(compressFilename(dbName)));
			ret = PwDialog::execute(&p, &pki_evp::passwd,
						false, true);
			if (ret != 1) {
				pki_evp::passwd = QByteArray();
				return ret;
			}
			pwhash_upgrade();
		}
	}
	if (pki_evp::passwd.isNull())
		pki_evp::passwd = "";
	return 1;
}

void MainWindow::Error(const errorEx &err)
{
	if (err.isEmpty())
		 return;
	QString msg =  tr("The following error occurred:") + "\n" + err.getString();
	xcaWarning box(NULL, msg);
	box.addButton(QMessageBox::Apply)->setText(tr("Copy to Clipboard"));
	box.addButton(QMessageBox::Ok);
	if (box.exec() == QMessageBox::Apply) {
		QClipboard *cb = QApplication::clipboard();
		cb->setText(msg);
		if (cb->supportsSelection())
			cb->setText(msg, QClipboard::Selection);
	}
}

void MainWindow::connNewX509(NewX509 *nx)
{
	connect(nx, SIGNAL(genKey(QString)),
		keys, SLOT(newItem(QString)));
	connect(keys, SIGNAL(keyDone(pki_key*)),
		nx, SLOT(newKeyDone(pki_key*)));
	connect(nx, SIGNAL(showReq(pki_base*)),
		reqs, SLOT(showPki(pki_base*)));
	connect(reqs, SIGNAL(pkiChanged(pki_base*)),
		nx, SLOT(itemChanged(pki_base*)));
}

void MainWindow::importAnything(QString file)
{
	int ret;
	ImportMulti *dlgi = new ImportMulti(this);
	QStringList failed;
	pki_multi *pki = probeAnything(file, &ret);
	if (ret)
		failed << file;
	else
		dlgi->addItem(pki);
	dlgi->execute(1, failed);
	delete dlgi;
}

pki_multi *MainWindow::probeAnything(QString file, int *ret)
{
	if (ret)
		*ret = 0;
	pki_multi *pki = NULL;

	try {
		if (file.endsWith(".xdb") ||
		    !OpenDb::splitRemoteDbName(file).isEmpty())
		{
			int r = init_database(file);
			if (ret)
				*ret = r;
			return pki;
		}
		pki = new pki_multi();
		pki->probeAnything(file);
	} catch (errorEx &err) {
		Error(err);
	}
	if (pki && !pki->count()) {
		delete pki;
		pki = NULL;
	}
	if (!pki && ret)
		*ret = 1;
	return pki;
}

void MainWindow::exportIndex()
{
	exportIndex(QFileDialog::getSaveFileName(this, XCA_TITLE,
				Settings["workingdir"],
				tr("Certificate Index ( index.txt )") + ";;" +
					tr("All files ( * )")),
			false);
}

void MainWindow::exportIndexHierarchy()
{
	exportIndex(QFileDialog::getExistingDirectory(
		this, XCA_TITLE, Settings["workingdir"]), true);
}

int MainWindow::exportIndex(QString fname, bool hierarchy)
{
	qDebug() << fname << hierarchy;
	if (fname.isEmpty())
		return 1;
	if (certs == NULL) {
		open_default_db();
		if (certs == NULL)
			return 2;
	}
	certs->writeIndex(fname, hierarchy);
	return 0;
}

void MainWindow::generateDHparamDone()
{
	statusBar()->removeWidget(dhgenBar);
	errorEx e(dhgen->error);
	if (e.isEmpty())
		XCA_INFO(tr("Diffie-Hellman parameters saved as: %1")
			.arg(dhgen->filename()));
	else
		Error(e);
	dhgen->deleteLater();
	dhgen = NULL;
}

void MainWindow::generateDHparam()
{
	bool ok;
	int bits;

	if (dhgen)
		return;

	bits = QInputDialog::getDouble(this, XCA_TITLE, tr("Diffie-Hellman parameters are needed for different applications, but not handled by XCA.\nPlease enter the DH parameter bits"),
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
		QString fname = QString("%1/dh%2.pem").arg(homedir).arg(bits);
		fname = QFileDialog::getSaveFileName(this, QString(),
			fname, tr("All files ( * )"), NULL);
		if (fname == "")
			throw errorEx("");
		dhgen = new DHgen(fname, bits);
		check_oom(dhgen);
		statusBar()->addPermanentWidget(dhgenBar, 1);
		dhgenBar->show();
		dhgen->start(QThread::LowestPriority);
		connect(dhgen, SIGNAL(finished()),
			this, SLOT(generateDHparamDone()));
	} catch (errorEx &err) {
		Error(err);
	}
}

void MainWindow::changeEvent(QEvent *event)
{
	if (event->type() == QEvent::LanguageChange) {
		retranslateUi(this);
		dn_translations_setup();
		init_menu();
		update_history_menu();
		foreach(db_base *model, models)
			model->updateHeaders();

		if (!currentDB.isEmpty())
			dbindex->setText(tr("Database") + ": " + currentDB);
		searchEdit->setPlaceholderText(tr("Search"));
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
	case Qt::Key_V:
		if (e->modifiers() == Qt::ControlModifier) {
			pastePem();
			break;
		}
        /* FALLTHROUGH */
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
