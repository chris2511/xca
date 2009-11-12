/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


//#define MDEBUG
#include "MainWindow.h"
#include "ImportMulti.h"
#include <qapplication.h>
#include <qclipboard.h>
#include <qmessagebox.h>
#include <qlabel.h>
#include <qpushbutton.h>
#include <qlistview.h>
#include <qlineedit.h>
#include <qtextbrowser.h>
#include <qstatusbar.h>
#include <qlist.h>
#include <qtemporaryfile.h>
#include <openssl/rand.h>

#include "lib/exception.h"
#include "lib/pki_evp.h"
#include "lib/pki_scard.h"
#include "lib/pki_pkcs12.h"
#include "lib/pki_multi.h"
#include "lib/load_obj.h"
#include "lib/pass_info.h"
#include "lib/func.h"
#include "lib/pkcs11.h"
#include "ui_PassRead.h"
#include "ui_PassWrite.h"
#include "ui_About.h"


QPixmap *MainWindow::keyImg = NULL, *MainWindow::csrImg = NULL,
	*MainWindow::certImg = NULL, *MainWindow::tempImg = NULL,
	*MainWindow::nsImg = NULL, *MainWindow::revImg = NULL,
	*MainWindow::appIco = NULL, *MainWindow::scardImg = NULL;

db_key *MainWindow::keys = NULL;
db_x509req *MainWindow::reqs = NULL;
db_x509	*MainWindow::certs = NULL;
db_temp	*MainWindow::temps = NULL;
db_crl	*MainWindow::crls = NULL;

NIDlist *MainWindow::eku_nid = NULL;
NIDlist *MainWindow::dn_nid = NULL;
NIDlist *MainWindow::aia_nid = NULL;

QString MainWindow::mandatory_dn;

static const int x962_curve_nids[] = {
	NID_X9_62_prime192v1,
	NID_X9_62_prime192v2,
	NID_X9_62_prime192v3,
	NID_X9_62_prime239v1,
	NID_X9_62_prime239v2,
	NID_X9_62_prime239v3,
	NID_X9_62_prime256v1,
	NID_X9_62_c2pnb163v1,
	NID_X9_62_c2pnb163v2,
	NID_X9_62_c2pnb163v3,
	NID_X9_62_c2pnb176v1,
	NID_X9_62_c2tnb191v1,
	NID_X9_62_c2tnb191v2,
	NID_X9_62_c2tnb191v3,
	NID_X9_62_c2pnb208w1,
	NID_X9_62_c2tnb239v1,
	NID_X9_62_c2tnb239v2,
	NID_X9_62_c2tnb239v3,
	NID_X9_62_c2pnb272w1,
	NID_X9_62_c2pnb304w1,
	NID_X9_62_c2tnb359v1,
	NID_X9_62_c2pnb368w1,
	NID_X9_62_c2tnb431r1
};

static const int other_curve_nids[] = {
	NID_sect163k1,
	NID_sect163r2,
	NID_sect233k1,
	NID_sect233r1,
	NID_sect283k1,
	NID_sect283r1,
	NID_sect409k1,
	NID_sect409r1,
	NID_sect571k1,
	NID_sect571r1,
	NID_secp224r1,
	NID_secp384r1,
	NID_secp521r1
};

static void init_curves()
{
	pki_evp::num_curves = EC_get_builtin_curves(NULL, 0);
	pki_evp::curves = (EC_builtin_curve*)OPENSSL_malloc(
			(int)(sizeof(EC_builtin_curve) *pki_evp::num_curves));
	if (!pki_evp::curves)
		return;
	EC_get_builtin_curves(pki_evp::curves, pki_evp::num_curves);
	pki_evp::curve_flags = (unsigned char *)OPENSSL_malloc(pki_evp::num_curves);
	if (!pki_evp::curve_flags)
		return;
	for (size_t i=0; i< pki_evp::num_curves; i++) {
		size_t j;

		pki_evp::curve_flags[i] = 0;
		for (j=0; j<ARRAY_SIZE(x962_curve_nids); j++) {
			if (x962_curve_nids[j] == pki_evp::curves[i].nid) {
				pki_evp::curve_flags[i] = CURVE_X962;
				break;
			}
		}
		if (pki_evp::curve_flags[i])
			continue;
		for (j=0; j<ARRAY_SIZE(other_curve_nids); j++) {
			if (other_curve_nids[j] == pki_evp::curves[i].nid) {
				pki_evp::curve_flags[i] = CURVE_OTHER;
				break;
			}
		}
	}
}

void MainWindow::load_engine()
{
	try {
		pki_scard::init_p11engine(pkcs11path, pkcs11path.isEmpty());
	} catch (errorEx &err) {
		Error(err);
	}
	scardMenuAction->setEnabled(pkcs11::loaded());
}

MainWindow::MainWindow(QWidget *parent )
	:QMainWindow(parent)
{
	dbindex = new QLabel();
	dbindex->setFrameStyle(QFrame::Plain | QFrame::NoFrame);
	dbindex->setMargin(6);

	statusBar()->addWidget(dbindex, 1);
	force_load = 0;
	mandatory_dn = "";
	string_opt = "default";

	setupUi(this);
	setWindowTitle(tr(XCA_TITLE));

	wdList << keyButtons << reqButtons << certButtons <<
		tempButtons <<	crlButtons;
	init_menu();
	setItemEnabled(false);

	init_images();
	homedir = getHomeDir();

	init_curves();

	// FIXME: Change pass isn't functional yet.
	BNchangePass->setDisabled(true);

#ifdef MDEBUG
	CRYPTO_malloc_debug_init();
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
	fprintf(stderr, "malloc() debugging on.\n");
#endif

	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	/* read in all our own OIDs */
	initOIDs();

	eku_nid = read_nidlist("eku.txt");
	dn_nid = read_nidlist("dn.txt");
	aia_nid = read_nidlist("aia.txt");
}

void MainWindow::setItemEnabled(bool enable)
{
	foreach(QWidget *w, wdList) {
		w->setEnabled(enable);
	}
	foreach(QAction *a, acList) {
		a->setEnabled(enable);
	}
	scardMenuAction->setEnabled(pkcs11::loaded());
}

/* creates a new nid list from the given filename */
NIDlist *MainWindow::read_nidlist(QString name)
{
	NIDlist nl;
	name = QDir::separator() + name;

#ifndef WIN32
	/* first try $HOME/xca/ */
	nl = readNIDlist(getUserSettingsDir() + QDir::separator() + name);
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
	pki_x509::icon[0] = loadImg("validcert.png");
	pki_x509::icon[1] = loadImg("validcertkey.png");
	pki_x509::icon[2] = loadImg("invalidcert.png");
	pki_x509::icon[3] = loadImg("invalidcertkey.png");
	pki_x509::icon[4] = loadImg("revoked.png");
	pki_temp::icon = loadImg("template.png");
	pki_crl::icon = loadImg("crl.png");
}

void MainWindow::read_cmdline()
{
	int cnt = 1, opt = 0;
	char *arg = NULL;
	pki_base *item = NULL;
	load_base *lb = NULL;
	exitApp = 0;
	ImportMulti *dlgi = new ImportMulti(this);
	while (cnt < qApp->argc()) {
		arg = qApp->argv()[cnt];
		if (arg[0] == '-') { // option
			if (lb)
				delete lb;
			opt = 1; lb = NULL;
			switch (arg[1]) {
				case 'c' : lb = new load_cert(); break;
				case 'r' : lb = new load_req(); break;
				case 'k' : lb = new load_key(); break;
				case 'p' : lb = new load_pkcs12(); break;
				case '7' : lb = new load_pkcs7(); break;
				case 'l' : lb = new load_crl(); break;
				case 't' : lb = new load_temp(); break;
				case 'P' : lb = new load_pem(); break;
				case 'd' : force_load=1; break;
				case 'v' : cmd_version(); opt=0; break;
				case 'x' : exitApp = 1; opt=0; break;
				case 'h' : cmd_help(NULL); opt=0; break;
				default  : cmd_help(CCHAR(tr("no such option: ") + arg));
			}
			if (arg[2] != '\0' && opt==1) {
				 arg+=2;
			}
			else {
				cnt++;
				continue;
			}
		}
		if (lb) {
			item = NULL;
			try {
				item = lb->loadItem(arg);
				dlgi->addItem(item);
			}
			catch (errorEx &err) {
				if (item) {
					delete item;
					item = NULL;
				}
			}
		} else {
			if (QFile::exists(arg)) {
				dbfile = arg;
				homedir = dbfile.left(dbfile.lastIndexOf(QDir::separator()));
				init_database();
			} else {
				cmd_help(CCHAR(tr("Database file does not exist: ") + arg));
			}
		}

		cnt++;
	}
	dlgi->execute(1); /* force showing of import dialog */
	delete dlgi;
}

void MainWindow::loadPem()
{
	load_pem l;
	if (keys)
		keys->load_default(l);
}

void MainWindow::pastePem()
{
	Ui::About ui;
	QDialog *input = new QDialog(this, 0);

	ui.setupUi(input);
	delete ui.textbox;
	QTextEdit *textbox = new QTextEdit(input);
	ui.vboxLayout->addWidget(textbox);
	ui.button->setText(tr("Import PEM data"));
	input->setWindowTitle(tr(XCA_TITLE));
	if (input->exec()) {
		QString txt = textbox->toPlainText();
		QTemporaryFile f;
		f.open();
		f.write(textbox->toPlainText().toAscii());
		f.flush();
		pki_multi *pem = NULL;
		ImportMulti *dlgi = NULL;
		try {
			pem = new pki_multi();
			dlgi = new ImportMulti(this);
			pem->fload(f.fileName());
			dlgi->addItem(pem);
			dlgi->execute(1);
		}
		catch (errorEx &err) {
			Error(err);
		}
		delete dlgi;
	}
	delete input;
}

void MainWindow::importScard()
{
	pkcs11 p11;
	QList<unsigned long> p11_slots;
	int i;
	pki_scard *card = NULL;
	pki_x509 *cert = NULL;

	if (!pkcs11::loaded())
		return;
	try {
		ImportMulti *dlgi = new ImportMulti(this);
		QList<CK_OBJECT_HANDLE> objects;
		pk11_attr_ulong class_att = pk11_attr_ulong(CKA_CLASS);
		p11_slots = p11.getSlotList();

		if (p11_slots.count() == 0)
			QMessageBox::warning(this, XCA_TITLE,
				tr("No Smart card found"));
		for (i=0; i<p11_slots.count(); i++) {
			p11.startSession(p11_slots[i]);
			QList<CK_MECHANISM_TYPE> ml = p11.mechanismList(i);

			class_att.setValue(CKO_PUBLIC_KEY);
			objects = p11.objectList(&class_att);

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
			class_att.setValue(CKO_CERTIFICATE);
			objects = p11.objectList(&class_att);

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
		}
		dlgi->execute();
	} catch (errorEx &err) {
		Error(err);
        }
	if (card)
		delete card;
	if (cert)
		delete cert;
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

QString makeSalt(void)
{
	unsigned char rand[2];
	char saltbuf[10];

	RAND_bytes(rand, 2);
	snprintf(saltbuf, 10, "S%02X%02X", rand[0], rand[1]);
	return QString(saltbuf);
}

int MainWindow::initPass()
{
	db mydb(dbfile);
	char *pass;
	pki_evp::passHash = QString();
	QString salt;

	pass_info p(tr("New Password"), tr("Please enter a password, "
			"that will be used to encrypt your private keys "
			"in the database-file"), this);
	if (!mydb.find(setting, "pwhash")) {
		if ((pass = (char *)mydb.load(NULL))) {
			pki_evp::passHash = pass;
			free(pass);
		}
	}
	if (pki_evp::passHash.isEmpty()) {
		int keylen = passWrite((char *)pki_evp::passwd,
				MAX_PASS_LENGTH-1, 0, &p);
		if (keylen < 0)
			return 0;
		pki_evp::passwd[keylen]='\0';
		salt = makeSalt();
		pki_evp::passHash = pki_evp::sha512passwd(pki_evp::passwd,salt);
		mydb.set((const unsigned char *)CCHAR(pki_evp::passHash),
			pki_evp::passHash.length()+1, 1, setting, "pwhash");
	} else {
		int keylen=0;
		while (pki_evp::sha512passwd(pki_evp::passwd, pki_evp::passHash)
				!= pki_evp::passHash)
		{
			if (keylen !=0) QMessageBox::warning(this,tr(XCA_TITLE),
				tr("Password verify error, please try again"));
			p.setTitle(tr("Password"));
			p.setDescription(tr("Please enter the password for unlocking the database"));
			keylen = passRead(pki_evp::passwd, MAX_PASS_LENGTH-1, 0, &p);
			if (keylen < 0)
				return 1;
			pki_evp::passwd[keylen]='\0';
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
	return 1;
}

static int hex2bin(QString &x, char *buf, int buflen)
{
	int len = x.length();
	bool ok = false;
	if (len % 2)
		return -1;
	len /= 2;
	if (len > buflen)
		return -1;

	for (int i=0; i<len; i++) {
		buf[i] = x.mid(i*2, 2).toInt(&ok, 16);
		if (!ok)
			return -1;
	}
	return len;
}

static const QString hexwarn = MainWindow::tr("Hex password must only contain the characters '0' - '9' and 'a' - 'f' and it must consist of an even number of characters");
// Static Password Callback functions
int MainWindow::passRead(char *buf, int size, int, void *userdata)
{
	int ret = -1;
	pass_info *p = (pass_info *)userdata;
	Ui::PassRead ui;
	QDialog *dlg = new QDialog(p->getWidget());
	ui.setupUi(dlg);
	if (p != NULL) {
		ui.image->setPixmap(p->getImage());
		ui.description->setText(p->getDescription());
		ui.title->setText(p->getType());
		ui.label->setText(p->getType());
		dlg->setWindowTitle(p->getTitle());
		if (p->getType() != "PIN")
			ui.takeHex->hide();
	}

	while (dlg->exec()) {
		QString x = ui.pass->text();
		if (ui.takeHex->isChecked()) {
			ret = hex2bin(x, buf, size);
			if (ret != -1)
				break;
		} else {
			strncpy(buf, x.toAscii(), size);
			ret = x.length();
			break;
		}
		QMessageBox::warning(p->getWidget(), XCA_TITLE, hexwarn);
	}
	delete dlg;
	return ret;
}

int MainWindow::passWrite(char *buf, int size, int, void *userdata)
{
	int ret = -1;
	pass_info *p = (pass_info *)userdata;
	Ui::PassWrite ui;
	QDialog *dlg = new QDialog(p->getWidget());
	ui.setupUi(dlg);
	if (p != NULL) {
		ui.image->setPixmap(p->getImage()) ;
		ui.description->setText(p->getDescription());
		ui.title->setText(p->getType());
		ui.label->setText(p->getType());
		ui.repeatLabel->setText(tr("Repeat ") + p->getType());
		dlg->setWindowTitle(p->getTitle());
		if (p->getType() != "PIN")
			ui.takeHex->hide();
	}
	dlg->show();
	dlg->activateWindow();
	ui.passA->setFocus();

	while (dlg->exec()) {
		QString A = ui.passA->text();
		QString B = ui.passB->text();
		if (A == B) {
			if (ui.takeHex->isChecked()) {
				ret = hex2bin(A, buf, size);
				if (ret != -1)
					break;
			} else {
				strncpy(buf, A.toAscii(), size);
				ret = A.length();
				break;
			}
			QMessageBox::warning(p->getWidget(), XCA_TITLE,
						hexwarn);
		} else {
			QMessageBox::warning(p->getWidget(), XCA_TITLE,
						p->getType() + tr(" missmatch"));
		}
	}
	delete dlg;
	return ret;
}

void MainWindow::Error(errorEx &err)
{
	if (err.isEmpty())
		 return;
	QString msg =  tr("The following error occured:") + "\n" + err.getString();
	int ret = QMessageBox::warning(qApp->activeWindow(), XCA_TITLE,
			msg, tr("&OK"), tr("Copy to Clipboard"));
	if (ret == 1) {
		QClipboard *cb = QApplication::clipboard();
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

void MainWindow::connNewX509(NewX509 *nx)
{
	connect( nx, SIGNAL(genKey(QString)), keys, SLOT(newItem(QString)) );
	connect( keys, SIGNAL(keyDone(QString)), nx, SLOT(newKeyDone(QString)) );
	connect( nx, SIGNAL(showReq(QString)), reqs, SLOT(showItem(QString)));
}

