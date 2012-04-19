/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "MainWindow.h"
#include "lib/exception.h"
#include "lib/pki_evp.h"
#include "lib/pki_scard.h"
#include <QtCore/QDir>
#include <QtGui/QStatusBar>
#include <QtGui/QMessageBox>
#include "lib/db_base.h"
#include "lib/func.h"
#include "widgets/ImportMulti.h"

int MainWindow::init_database()
{
	int ret = 2;
	fprintf(stderr, "Opening database: %s\n", QString2filename(dbfile));
	keys = NULL; reqs = NULL; certs = NULL; temps = NULL; crls = NULL;

	certView->setRootIsDecorated(db_x509::treeview);

	try {
		ret = initPass();
		if (ret == 2)
			return ret;
		keys = new db_key(dbfile, this);
		reqs = new db_x509req(dbfile, this);
		certs = new db_x509(dbfile, this);
		temps = new db_temp(dbfile, this);
		crls = new db_crl(dbfile, this);
	}
	catch (errorEx &err) {
		Error(err);
		dbfile = "";
		return ret;
	}

	mandatory_dn = "";
	string_opt = QString("MASK:0x2002");
	ASN1_STRING_set_default_mask_asc((char*)CCHAR(string_opt));
	hashBox::resetDefault();
	pkcs11path = getDefaultPkcs11Lib();
	workingdir = QDir::currentPath();
	setOptFlags((QString()));
	try {
		pkcs11_lib p(pkcs11path);
	} catch (errorEx &e) {
		pkcs11path = QString();
	}

	connect( keys, SIGNAL(newKey(pki_key *)),
		certs, SLOT(newKey(pki_key *)) );
	connect( keys, SIGNAL(delKey(pki_key *)),
		certs, SLOT(delKey(pki_key *)) );
	connect( keys, SIGNAL(newKey(pki_key *)),
		reqs, SLOT(newKey(pki_key *)) );
	connect( keys, SIGNAL(delKey(pki_key *)),
		reqs, SLOT(delKey(pki_key *)) );

	connect( certs, SIGNAL(connNewX509(NewX509 *)), this,
		SLOT(connNewX509(NewX509 *)) );
	connect( reqs, SIGNAL(connNewX509(NewX509 *)), this,
		SLOT(connNewX509(NewX509 *)) );

	connect( reqs, SIGNAL(newCert(pki_x509req *)),
		certs, SLOT(newCert(pki_x509req *)) );
	connect( temps, SIGNAL(newCert(pki_temp *)),
		certs, SLOT(newCert(pki_temp *)) );
	connect( temps, SIGNAL(newReq(pki_temp *)),
		reqs, SLOT(newItem(pki_temp *)) );

	keyView->setIconSize(pki_evp::icon[0]->size());
	reqView->setIconSize(pki_x509req::icon[0]->size());
	certView->setIconSize(pki_x509::icon[0]->size());
	tempView->setIconSize(pki_temp::icon->size());
	crlView->setIconSize(pki_crl::icon->size());

	keyView->setModel(keys);
	reqView->setModel(reqs);
	certView->setModel(certs);
	tempView->setModel(temps);
	crlView->setModel(crls);

	try {
		db mydb(dbfile);
		char *p;
		if (!mydb.find(setting, "workingdir")) {
			if ((p = (char *)mydb.load(NULL))) {
				workingdir = p;
				free(p);
			}
		}
		mydb.first();
		if (!mydb.find(setting, "pkcs11path")) {
			if ((p = (char *)mydb.load(NULL))) {
				pkcs11path = p;
				free(p);
			}
		}
		mydb.first();
		if (!mydb.find(setting, "default_hash")) {
			if ((p = (char *)mydb.load(NULL))) {
				hashBox::setDefault(p);
				free(p);
			}
		}
		mydb.first();
		if (!mydb.find(setting, "mandatory_dn")) {
			if ((p = (char *)mydb.load(NULL))) {
				mandatory_dn = p;
				free(p);
			}
		}
		// what a stupid idea....
		mydb.first();
		if (!mydb.find(setting, "multiple_key_use")) {
			mydb.erase();
		}
		mydb.first();
		if (!mydb.find(setting, "string_opt")) {
			if ((p = (char *)mydb.load(NULL))) {
				string_opt = p;
				free(p);
			}
		}
		mydb.first();
		if (!mydb.find(setting, "suppress")) {
			if ((p = (char *)mydb.load(NULL))) {
				QString x = p;
				free(p);
				if (x == "1")
					pki_base::suppress_messages = 1;
			}
		}
		mydb.first();
		if (!mydb.find(setting, "optionflags")) {
			if ((p = (char *)mydb.load(NULL))) {
				setOptFlags((QString(p)));
				free(p);
			}
		}
		ASN1_STRING_set_default_mask_asc((char*)CCHAR(string_opt));
		mydb.first();
		if (!mydb.find(setting, "mw_geometry")) {
			db_header_t h;
			if ((p = (char *)mydb.load(&h))) {
				if (h.version == 1) {
					QByteArray ba;
					ba = QByteArray::fromRawData(p, h.len);
					int w, h, i;
					w = db::intFromData(ba);
					h = db::intFromData(ba);
					i = db::intFromData(ba);
					resize(w,h);
					if (i != -1)
						tabView->setCurrentIndex(i);
					}
				free(p);
			}
		}
	} catch (errorEx &err) {
		Error(err);
		return ret;
	}
	setWindowTitle(tr(XCA_TITLE));
	setItemEnabled(true);
	if (pki_evp::passwd.isNull())
		QMessageBox::information(this, XCA_TITLE,
			tr("Using or exporting private keys will not be possible without providing the correct password"));

	dbindex->setText(tr("Database") + ":" + dbfile);
	load_engine();
	return ret;
}

void MainWindow::dump_database()
{
	QString dirname = QFileDialog::getExistingDirectory(this, tr(XCA_TITLE),
			getPath());

	if (dirname.isEmpty())
		return;

	QDir d(dirname);
	if ( ! d.exists() && !d.mkdir(dirname)) {
		errorEx err("Could not create '" + dirname + "'");
		MainWindow::Error(err);
		return;
	}

	printf("Dumping to %s\n", CCHAR(dirname));
	try {
		keys->dump(dirname);
		certs->dump(dirname);
		temps->dump(dirname);
		crls->dump(dirname);
		reqs->dump(dirname);
	}
	catch (errorEx &err) {
		MainWindow::Error(err);
	}
}

void MainWindow::undelete()
{
	ImportMulti *dlgi = new ImportMulti(this);
	db_header_t head;
	db mydb(dbfile);

	for (mydb.first(DBFLAG_OUTDATED); !mydb.eof(); mydb.next(DBFLAG_OUTDATED)) {
		mydb.get_header(&head);
		if (head.flags & DBFLAG_DELETED) {
			pki_base *item;
			unsigned char *p = NULL;
			QString name = QString::fromUtf8(head.name);
			switch (head.type) {
			case asym_key: item = new pki_evp(name); break;
			case x509_req: item = new pki_x509req(name); break;
			case x509: item = new pki_x509(name); break;
			case revokation: item = new pki_crl(name); break;
			case tmpl: item = new pki_temp(name); break;
			case smartCard: item = new pki_scard(name); break;
			default: continue;
			}
			try {
				p = mydb.load(&head);
				item->fromData(p, &head);
				dlgi->addItem(item);
			}
			catch (errorEx &err) {
				Error(err);
				delete item;
			}
			free(p);
		}
	}
	if (dlgi->entries() > 0) {
		dlgi->execute(1);
	} else {
		QMessageBox::information(this, XCA_TITLE,
			tr("No deleted items found"));
	}
	delete dlgi;
}

int MainWindow::open_default_db()
{
	if (!dbfile.isEmpty())
		return 0;
	FILE *fp = fopen(QString2filename(getUserSettingsDir() +
					QDir::separator() + "defaultdb"), "r");
	if (!fp)
		return 0;

	char buff[256];
	size_t len = fread(buff, 1, 255, fp);
	fclose(fp);
	buff[len] = 0;
	dbfile = filename2QString(buff).trimmed();
	if (QFile::exists(dbfile))
		return init_database();
	return 0;
}

void MainWindow::default_database()
{
	QFileInfo fi(dbfile);
	QString dir = getUserSettingsDir();
	FILE *fp;

	QDir d;
	d.mkpath(dir);

	fp = fopen(QString2filename(dir +QDir::separator() +"defaultdb"), "w");
	if (fp) {
		QByteArray ba;
		ba = filename2bytearray(fi.canonicalFilePath() + "\n");
		fwrite(ba.constData(), ba.size(), 1, fp);
		fclose(fp);
	}

}

void MainWindow::close_database()
{
	QByteArray ba;
	if (!dbfile.isEmpty()) {
		ba += db::intToData(size().width());
		ba += db::intToData(size().height());
		ba += db::intToData(tabView->currentIndex());
		db mydb(dbfile);
		mydb.set((const unsigned char *)ba.constData(), ba.size(), 1,
			setting, "mw_geometry");
	}
	setItemEnabled(false);
	dbindex->clear();

	keyView->setModel(NULL);
	reqView->setModel(NULL);
	certView->setModel(NULL);
	tempView->setModel(NULL);
	crlView->setModel(NULL);

	if (crls)
		delete(crls);
	if (reqs)
		delete(reqs);
	if (certs)
		delete(certs);
	if (temps)
		delete(temps);
	if (keys)
		delete(keys);

	reqs = NULL;
	certs = NULL;
	temps = NULL;
	keys = NULL;

	pki_evp::passwd.cleanse();
	pki_evp::passwd = QByteArray();

	if (!crls)
		return;
	crls = NULL;


	try {
		db mydb(dbfile);
		mydb.shrink( DBFLAG_OUTDATED | DBFLAG_DELETED );
	}
	catch (errorEx &err) {
		MainWindow::Error(err);
	}
	pkcs11::remove_libs();
	enableTokenMenu(pkcs11::loaded());
}

/* Asymetric Key buttons */
void MainWindow::on_BNnewKey_clicked(void)
{
	if (keys)
		keys->newItem();
}
void MainWindow::on_BNdeleteKey_clicked(void)
{
	if (keys)
		keys->deleteSelectedItems(keyView);
}
void MainWindow::on_BNdetailsKey_clicked(void)
{
	if (keys)
		keys->showSelectedItems(keyView);
}
void MainWindow::on_BNimportKey_clicked(void)
{
	if (keys)
		keys->load();
}
void MainWindow::on_BNexportKey_clicked(void)
{
	if (keys)
		keys->storeSelectedItems(keyView);
}

void MainWindow::on_keyView_doubleClicked(const QModelIndex &m)
{
	if (keys)
		keys->showItem(keyView->getIndex(m));
}

void MainWindow::on_reqView_doubleClicked(const QModelIndex &m)
{
	if (reqs)
		reqs->showItem(reqView->getIndex(m));
}

void MainWindow::on_certView_doubleClicked(const QModelIndex &m)
{
	if (certs)
		certs->showItem(certView->getIndex(m));
}

void MainWindow::on_tempView_doubleClicked(const QModelIndex &m)
{
	if (temps)
		temps->showItem(tempView->getIndex(m));
}

void MainWindow::on_crlView_doubleClicked(const QModelIndex &m)
{
	if (crls)
		crls->showItem(crlView->getIndex(m));
}

void MainWindow::on_BNimportPFX_clicked(void)
{
	if (certs)
		certs->loadPKCS12();
}

/* Certificate request buttons */
void MainWindow::on_BNnewReq_clicked(void)
{
	if (reqs)
		reqs->newItem();
}
void MainWindow::on_BNdeleteReq_clicked(void)
{
	if (reqs)
		reqs->deleteSelectedItems(reqView);
}
void MainWindow::on_BNdetailsReq_clicked(void)
{
	if (reqs)
		reqs->showSelectedItems(reqView);
}
void MainWindow::on_BNimportReq_clicked(void)
{
	if (reqs)
		reqs->load();
}
void MainWindow::on_BNexportReq_clicked(void)
{
	if(reqs)
		reqs->storeSelectedItems(reqView);
}

/* Certificate  buttons */
void MainWindow::on_BNnewCert_clicked(void)
{
	if (certs)
		certs->newItem();
}
void MainWindow::on_BNdeleteCert_clicked(void)
{
	if (certs)
		certs->deleteSelectedItems(certView);
}
void MainWindow::on_BNdetailsCert_clicked(void)
{
	if (certs)
		certs->showSelectedItems(certView);
}
void MainWindow::on_BNimportCert_clicked(void)
{
	if (certs)
		certs->load();
}
void MainWindow::on_BNexportCert_clicked(void)
{
	if(certs)
		certs->storeSelectedItems(certView);
}

void MainWindow::on_BNimportPKCS12_clicked(void)
{
	if(certs)
		certs->loadPKCS12();
}

void MainWindow::on_BNimportPKCS7_clicked(void)
{
	if(certs)
		certs->loadPKCS7();
}

void MainWindow::on_BNviewState_clicked(void)
{
	if(certs)
		certs->changeView();
	 certView->setRootIsDecorated(db_x509::treeview);
}

/* Template buttons */
void MainWindow::on_BNdeleteTemp_clicked(void)
{
	if (temps)
		temps->deleteSelectedItems(tempView);
}
void MainWindow::on_BNchangeTemp_clicked(void)
{
	if (temps)
		temps->showSelectedItems(tempView);
}
void MainWindow::on_BNimportTemp_clicked(void)
{
	if (temps)
		temps->load();
}
void MainWindow::on_BNexportTemp_clicked(void)
{
	if(temps)
		temps->storeSelectedItems(tempView);
}
void MainWindow::on_BNnewTemp_clicked(void)
{
	if (temps)
		temps->newItem();
}

/* CRL buttons */
void MainWindow::on_BNdeleteCrl_clicked(void)
{
	if (crls)
		crls->deleteSelectedItems(crlView);
}
void MainWindow::on_BNimportCrl_clicked(void)
{
	if (crls)
		crls->load();
}
void MainWindow::on_BNexportCrl_clicked(void)
{
	if (crls)
		crls->storeSelectedItems(crlView);
}
void MainWindow::on_BNdetailsCrl_clicked(void)
{
	if(crls)
		crls->showSelectedItems(crlView);
}
