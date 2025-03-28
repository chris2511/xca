/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "MainWindow.h"
#include "XcaApplication.h"
#include "ImportMulti.h"
#include "hashBox.h"

#include <QApplication>
#include <QClipboard>
#include <QFileDialog>
#include <QLabel>
#include <QLineEdit>
#include <QTextBrowser>
#include <QStatusBar>
#include <QList>
#include <QTimer>
#include <QThread>
#include <QMimeData>
#include <QInputDialog>

#include <openssl/err.h>

#include "lib/entropy.h"
#include "lib/Passwd.h"
#include "lib/database_model.h"
#include "lib/exception.h"
#include "lib/pki_evp.h"
#include "lib/pki_multi.h"
#include "lib/pki_scard.h"
#include "lib/dhgen.h"
#include "lib/load_obj.h"
#include "lib/pki_pkcs12.h"

#include "XcaDialog.h"
#include "XcaWarning.h"
#include "XcaProgressGui.h"
#include "PwDialog.h"
#include "OpenDb.h"
#include "Help.h"
#include "OidResolver.h"

OidResolver *MainWindow::resolver;
MainWindow *mainwin;
bool MainWindow::legacy_loaded;

void MainWindow::enableTokenMenu(bool enable)
{
	foreach(QWidget *w, scardList) {
		w->setEnabled(enable);
	}
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

MainWindow::MainWindow() : QMainWindow()
{
	dbindex = new QLabel();
	dbindex->setFrameStyle(QFrame::Plain | QFrame::NoFrame);
	dbindex->setMargin(6);

	dn_translations_setup();
	pki_export::init_elements();

	statusBar()->addWidget(dbindex, 1);

	setupUi(this);
	setWindowTitle(XCA_TITLE);

	OpenDb::checkSqLite();
	initResolver();

	wdList << keyButtons << reqButtons << certButtons <<
		tempButtons <<	crlButtons;

	OpenDb::initDatabases();

	helpdlg = new Help();
	init_menu();
	setItemEnabled(false);

	init_images();
	homedir = getHomeDir();

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

	keyView->setIconSize(QPixmap(":keyIco").size());
	reqView->setIconSize(QPixmap(":reqIco").size());
	certView->setIconSize(QPixmap(":validcertIco").size());
	tempView->setIconSize(QPixmap(":templateIco").size());
	crlView->setIconSize(QPixmap(":crlIco").size());

	views << keyView << reqView << certView << crlView << tempView;

	pki_base::setupColors(palette());

	foreach(XcaTreeView *v, views)
		v->setMainwin(this, searchEdit);

	XcaProgress::setGui(new XcaProgressGui(this));
	xcaWarning::setGui(new xcaWarningGui());
	PwDialogCore::setGui(new PwDialogUI());
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
	foreach(QString file, urlsToOpen) {
		if (file.endsWith(".xdb") ||
		    !database_model::splitRemoteDbName(file).isEmpty())
		{
			init_database(file);
			if (Database.isOpen()) {
				urlsToOpen.removeAll(file);
				break;
			}
		}
	}
	importAnything(urlsToOpen);
	urlsToOpen.clear();
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

void MainWindow::loadPem()
{
	load_pem l;
	keyView->load_default(&l);
}

bool MainWindow::pastePem(const QString &text, bool silent)
{
	bool success = false;
	QByteArray pemdata = text.toLatin1();
	if (pemdata.size() == 0)
		return false;

	pki_multi *pem = NULL;
	try {
		pem = new pki_multi();
		pem->fromPEMbyteArray(pemdata, QString());
		success = pem->failed_files.count() == 0;
		importMulti(pem, 1);
	}
	catch (errorEx &err) {
		delete pem;
		if (!silent)
			XCA_ERROR(err);
	}
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
			ret = PwDialogCore::execute(&p, &pin, false);
		} else {
			p.setDescription(tr("Please enter the new SO PIN (PUK) for the token '%1'").
			arg(slotname) + "\n" + ti.pinInfo());
			ret = PwDialogCore::execute(&p, &pin, true);
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
		XCA_ERROR(err);
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
		XCA_ERROR(err);
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
		XCA_ERROR(err);
	}
}


void MainWindow::manageToken()
{
	pkcs11 p11;
	slotid slot;
	pki_scard *card = NULL;
	pki_x509 *cert = NULL;
	ImportMulti *dlgi = NULL;

	enum logintype { none, userlogin, sologin } login = none;

	if (!pkcs11::libraries.loaded())
		return;

	try {
		if (!p11.selectToken(&slot, this))
			return;

		tkInfo ti(p11.tokenInfo(slot));

		ImportMulti *dlgi = new ImportMulti(this);

		while (true) {
			dlgi->tokenInfo(slot);
			QList<CK_OBJECT_HANDLE> objects;

			QList<CK_MECHANISM_TYPE> ml = p11.mechanismList(slot);
			if (ml.count() == 0)
				ml << CKM_SHA1_RSA_PKCS;
			pk11_attlist atts(pk11_attr_ulong(CKA_CLASS,
					CKO_PUBLIC_KEY));

			p11.startSession(slot);
			p11.getRandom();
			if (login != none) {
				if (p11.tokenLogin(ti.label(), login == sologin).isNull())
					break;
			}
			objects = p11.objectList(atts);

			for (int j=0; j< objects.count(); j++) {
				card = new pki_scard("");
				try {
					card->load_token(p11, objects[j]);
					card->setMech_list(ml);
					dlgi->addItem(card);
				} catch (errorEx &err) {
					XCA_ERROR(err);
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
					XCA_ERROR(err);
					delete cert;
				}
				cert = NULL;
			}
			if (dlgi->entries() == 0) {
				p11.closeSession(slot);
				QString txt = tr("The token '%1' did not contain any keys or certificates")
								.arg(ti.label());
				xcaWarningBox msg(this, txt);
				msg.addButton(QMessageBox::Ok);
				msg.addButton(QMessageBox::Retry, tr("Retry with PIN"));
				msg.addButton(QMessageBox::Apply, tr("Retry with SO PIN"));
				switch (msg.exec())
				{
					case QMessageBox::Retry:
						login = userlogin;
						continue;
					case QMessageBox::Apply:
						login = sologin;
						continue;
					case QMessageBox::Ok:
						// fall
					default:
						break;
				}
			} else {
				p11.closeSession(slot);
				dlgi->execute(true);
			}
			break;
		}
	} catch (errorEx &err) {
		XCA_ERROR(err);
	}
	delete card;
	delete cert;
	delete dlgi;
}

MainWindow::~MainWindow()
{
	ERR_free_strings();
	EVP_cleanup();
	OBJ_cleanup();
	delete dbindex;
	delete searchEdit;
	delete helpdlg;

	XcaProgress::setGui(nullptr);
	xcaWarning::setGui(nullptr);
	PwDialogCore::setGui(nullptr);
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
	delete resolver;
	resolver = NULL;
	delete helpdlg;
	helpdlg = NULL;
	close_database();
	QMainWindow::closeEvent(e);
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
			if (PwDialogCore::execute(&p, &pass, false) != 1)
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

	return PwDialogCore::execute(&p, &pass, true) != 1 ? 0 : 1;
}

void MainWindow::changeDbPass()
{
	Passwd pass;
	XSqlQuery q;
	QSqlDatabase db = QSqlDatabase::database();

	if (!checkOldGetNewPass(pass))
		return;

	QString salt = Entropy::makeSalt();
	QString passhash = pki_evp::sha512passwT(pass, salt);
	QList<pki_evp*> key_list = Store.sqlSELECTpki<pki_evp>(
		"SELECT item FROM private_keys WHERE ownPass=0");

	try {
		Transaction;
		if (!TransBegin()) {
			errorEx e(tr("Transaction start failed"));
			XCA_ERROR(e);
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
		XCA_ERROR(e);
	}
}

void MainWindow::importAnything(QString file)
{
	importAnything(QStringList(file));
}

void MainWindow::importAnything(const QStringList &files)
{
	pki_multi *multi = new pki_multi();

	foreach(QString s, files)
		multi->probeAnything(s);

	importMulti(multi, 1);
}

void MainWindow::importMulti(pki_multi *multi, int force)
{
	if (!multi)
		return;

	QStringList failed_files = multi->failed_files;
	ImportMulti *dlgi = new ImportMulti(this);

	// dlgi->addItem() deletes "multi" if appropriate
	dlgi->addItem(multi);
	dlgi->execute(force, failed_files);
	delete dlgi;
}

void MainWindow::openRemoteSqlDB()
{
	OpenDb *opendb = new OpenDb(this, QString());
	QString descriptor;
	Passwd pass;
	DbMap params;

	if (opendb->exec()) {
		descriptor = opendb->getDescriptor();
		pass = opendb->dbPassword->text().toLatin1();
		params = database_model::splitRemoteDbName(descriptor);
	}
	delete opendb;

	if (descriptor.isEmpty())
		return;

	init_database(descriptor, pass);
}

enum open_result MainWindow::init_database(const QString &name,
					   const Passwd &pass)
{
	close_database();
	try {
		Database.open(name, pass);
		return setup_open_database();
	} catch (errorEx &err) {
		XCA_ERROR(err);
		return open_abort;
	} catch (enum open_result r) {
		return r;
	}
	return pw_ok;
}

void MainWindow::showDatabaseName()
{
	if (Database.isOpen())
		dbindex->setText(tr("Database: %1")
			.arg(compressFilename(Database.name())));
}

enum open_result MainWindow::setup_open_database()
{
	if (!Database.isOpen())
		return open_abort;

	if (!database_model::isRemoteDB(Database.name()))
		homedir = QFileInfo(Database.name()).canonicalPath();

	setItemEnabled(true);
	showDatabaseName();
	set_geometry(Settings["mw_geometry"]);

	if (pki_evp::passwd.isNull())
		XCA_INFO(tr("Using or exporting private keys will not be possible without providing the correct password"));

	enableTokenMenu(pkcs11::libraries.loaded());

	digest defdig(digest::getDefault());
	if (defdig.isInsecure()) {
		XCA_WARN(tr("The currently used default hash '%1' is insecure. Please select at least 'SHA 224' for security reasons.").arg(defdig.name()));
		setOptions();
	}
	encAlgo encalg = encAlgo::getDefault();
	if (encalg.legacy() && !Settings["pkcs12_keep_legacy"]) {
		QString text(tr("The currently used PFX / PKCS#12 algorithm '%1' is insecure.")
				.arg(encalg.name()));
		xcaWarningBox msg(this, text);
		msg.addButton(QMessageBox::Ok);
        msg.addButton(QMessageBox::Ignore);
        msg.addButton(QMessageBox::Apply, tr("Change"));
		switch (msg.exec())
		{
			case QMessageBox::Ok:
				break;
			case QMessageBox::Ignore:
				Settings["pkcs12_keep_legacy"] = true;
				break;
			case QMessageBox::Apply:
				setOptions();
				break;
		}
	}
	keyView->setModel(Database.model<db_key>());
	reqView->setModel(Database.model<db_x509req>());
	certView->setModel(Database.model<db_x509>());
	tempView->setModel(Database.model<db_temp>());
	crlView->setModel(Database.model<db_crl>());

	searchEdit->setText("");
	searchEdit->show();
	statusBar()->addWidget(searchEdit, 1);

	connect(tempView, SIGNAL(newCert(pki_temp *)),
		Database.model<db_x509>(), SLOT(newCert(pki_temp *)));
	connect(tempView, SIGNAL(newReq(pki_temp *)),
		Database.model<db_x509req>(), SLOT(newItem(pki_temp *)));

	return pw_ok;
}

void MainWindow::set_geometry(QString geo)
{
	QStringList sl = geo.split(",");
	if (sl.size() != 3)
		return;
	resize(sl[0].toInt(), sl[1].toInt());
	int i = sl[2].toInt();
	if (i != -1)
		tabView->setCurrentIndex(i);
}

void MainWindow::close_database()
{
	if (!Database.isOpen())
		return;

	Settings["mw_geometry"] = QString("%1,%2,%3")
			.arg(size().width())
			.arg(size().height())
			.arg(tabView->currentIndex());

	history.addEntry(Database.name());
	foreach(XcaTreeView *v, views)
		v->setModel(NULL);
	Database.close();

	setItemEnabled(false);
	dbindex->clear();
	update_history_menu();
	enableTokenMenu(pkcs11::libraries.loaded());
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

void MainWindow::exportIndex(const QString &fname, bool hierarchy) const
{
	qDebug() << fname << hierarchy;
	if (fname.isEmpty() || !Database.isOpen())
		return;
	db_x509 *certs = Database.model<db_x509>();
	certs->writeIndex(fname, hierarchy);
}

void MainWindow::generateDHparamDone()
{
	errorEx e(dhgen->error());
	if (e.isEmpty())
		XCA_INFO(tr("Diffie-Hellman parameters saved as: %1")
			.arg(dhgen->filename()));
	else
		XCA_ERROR(e);
	dhgen->deleteLater();
	dhgen = NULL;
	delete dhgenProgress;
	dhgenProgress = nullptr;
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
		dhgenProgress = new XcaProgress(QString("Diffie-Hellman"), 0);
		dhgen->start(QThread::LowestPriority);
		connect(dhgen, SIGNAL(finished()),
			this, SLOT(generateDHparamDone()));
	} catch (errorEx &err) {
		XCA_ERROR(err);
	}
}

void MainWindow::changeEvent(QEvent *event)
{
	if (event->type() == QEvent::LanguageChange) {
		retranslateUi(this);
		dn_translations_setup();
		pki_export::init_elements();
		init_menu();
		foreach(db_base *model, Database.getModels())
			model->updateHeaders();

		showDatabaseName();
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
	int size = XcaApplication::tableFont.pointSize();

	switch (e->key()) {
	case Qt::Key_Plus:
		XcaApplication::tableFont.setPointSize(size +1);
		break;
	case Qt::Key_Minus:
		if (size > 4) {
			XcaApplication::tableFont.setPointSize(size -1);
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
	foreach(XcaTreeView *v, views) {
		if (v) {
			v->header()->resizeSections(
					QHeaderView::ResizeToContents);
			v->reset();
		}
	}
	update();
}

void MainWindow::dump_database()
{
	QString dirname = QFileDialog::getExistingDirectory(
				NULL, XCA_TITLE, Settings["workingdir"]);
	try {
		Database.dump(dirname);
	} catch (errorEx &err) {
		XCA_ERROR(err);
	}
}

void MainWindow::default_database()
{
	Database.as_default();
}
