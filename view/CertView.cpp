/* vi: set sw=4 ts=4: */
/*
 * Copyright (C) 2001 Christian Hohnstaedt.
 *
 *  All rights reserved.
 *
 *
 *  Redistribution and use in source and binary forms, with or without 
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  - Neither the name of the author nor the names of its contributors may be 
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * This program links to software with different licenses from:
 *
 *	http://www.openssl.org which includes cryptographic software
 * 	written by Eric Young (eay@cryptsoft.com)"
 *
 *	http://www.sleepycat.com
 *
 *	http://www.trolltech.com
 * 
 *
 *
 * http://www.hohnstaedt.de/xca
 * email: christian@hohnstaedt.de
 *
 * $Id$ 
 *
 */                           


#include "CertView.h"
#include "widgets/MainWindow.h"
#include <qcheckbox.h>
#include <qlabel.h>
#include <qcombobox.h>
#include <qradiobutton.h>
#include <qmessagebox.h>
#include <qpopupmenu.h>
#include <qtextview.h>
#include <qpushbutton.h>
#include <qinputdialog.h>
#include "ui/CertExtend.h"
#include "widgets/ExportCert.h"
#include "widgets/CertDetail.h"
#include "ui/TrustState.h"
#include "widgets/ExportTinyCA.h"
#include "widgets/validity.h"
#include "widgets/clicklabel.h"
#include "lib/pki_pkcs12.h"
#include "lib/pki_pkcs7.h"

#ifdef WIN32
#include <direct.h>     // to define mkdir function
#include <windows.h>    // to define mkdir function
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#endif

CertView::CertView(QWidget * parent, const char * name, WFlags f)
        :XcaListView(parent, name, f)
{
	addColumn(tr("Internal name"));
	addColumn(tr("Common name"));
	addColumn(tr("Serial"));
	addColumn(tr("not After"));
	addColumn(tr("Trust state"));
	addColumn(tr("Revokation"));
	viewState=1; // Tree View
}	


void CertView::newItem()
{
	NewX509 *dlg = new NewX509(this, NULL, true);
	emit connNewX509(dlg);
	dlg->setCert();
	if (dlg->exec()) {
		newCert(dlg);
	}
	delete dlg;
}

void CertView::newCert(pki_x509req *req)
{
	NewX509 *dlg = new NewX509(this, NULL, true);
	emit connNewX509(dlg);
	dlg->setCert();
	dlg->defineRequest(req);
	if (dlg->exec()) {
		newCert(dlg);
	}
	delete dlg;
}

void CertView::newCert(pki_temp *req)
{
	NewX509 *dlg = new NewX509(this, NULL, true);
	emit connNewX509(dlg);
	dlg->setCert();
	dlg->defineTemplate(req);
	if (dlg->exec()) {
		newCert(dlg);
	}
	delete dlg;
}

void CertView::newCert(NewX509 *dlg)
{
	pki_x509 *cert = NULL;
	pki_x509 *signcert = NULL;
	pki_x509req *req = NULL;
	pki_key *signkey = NULL, *clientkey = NULL, *tempkey = NULL;
	a1int serial;
	a1time notBefore, notAfter;
	x509name subject;
	QString intname;
	
	emit init_database();

	dlg->defineSigner((pki_x509*)getSelected());
	
    try {	
	
	// Step 1 - Subject and key
	if (!dlg->fromReqCB->isChecked()) {
	    clientkey = dlg->getSelectedKey();
	    subject = dlg->getX509name();
	    intname = dlg->description->text();
	}
	else {
	    // A PKCS#10 Request was selected 
	    req = dlg->getSelectedReq();
	    if (Error(req)) return;
	    clientkey = req->getRefKey();
	    if (clientkey == NULL) {
		    clientkey = req->getPubKey();
		    tempkey = clientkey;
	    }
	    subject = req->getSubject();
	    intname = req->getIntName();
	}
	
	// initially create cert 
	cert = new pki_x509();
	cert->setIntName(intname);
	cert->setSubject(subject);
	cert->setPubKey(clientkey);
	dlg->initCtx(cert);
	
	// Step 2 - select Signing
	if (dlg->foreignSignRB->isChecked()) {
		signcert = dlg->getSelectedSigner();
		if (Error(signcert)) return;
		serial = signcert->getIncCaSerial();
		signkey = signcert->getRefKey();
		cert->setTrust(1);
	}
	else {
		signcert = cert;	
		signkey = clientkey;	
		bool ok;
		serial = dlg->serialNr->text().toInt(&ok);
		if (!ok) serial = 0;
		cert->setTrust(2);
	}
	
	// if we can not sign
	if (! signkey || signkey->isPubKey()) {
		throw errorEx(tr("The key you selected for signing is not a private one."));
	}
	
	// set the issuers name
	cert->setIssuer(signcert->getSubject());
	cert->setSerial(serial);
	
	// Step 3 - Choose the Date
	// Date handling
	cert->setNotBefore( dlg->notBefore->getDate() );
	cert->setNotAfter( dlg->notAfter->getDate() );

	if (cert->resetTimes(signcert) > 0) {
		if (QMessageBox::information(this,tr(XCA_TITLE),
			tr("The validity times for the certificate need to get adjusted to not exceed those of the signer"),
			tr("Continue creation"), tr("Abort")
		)) {
			
			throw errorEx("");
		}
	}
			
	// STEP 4
	// handle extensions
	cert->addV3ext(dlg->getBasicConstraints());
	cert->addV3ext(dlg->getSubKeyIdent());
	cert->addV3ext(dlg->getAuthKeyIdent());
	cert->addV3ext(dlg->getKeyUsage());
	cert->addV3ext(dlg->getEkeyUsage());
	cert->addV3ext(dlg->getSubAltName());
	cert->addV3ext(dlg->getIssAltName());
	cert->addV3ext(dlg->getCrlDist());
	extList ne = dlg->getNetscapeExt();
	int m = ne.count();
	for (int i=0; i<m; i++)
		 cert->addV3ext(ne[i]);
	
	
	// and finally sign the request 
	cert->sign(signkey, dlg->getHashAlgo());
	insert(cert);
	db->updatePKI(signcert);
	if (tempkey != NULL) delete(tempkey);
	updateView();
	return;
    } // EOF try
	
    catch (errorEx &err) {
		Error(err);
		delete cert;
		if (tempkey != NULL) delete(tempkey);
    }
	
}

void CertView::extendCert()
{
	pki_x509 *oldcert = NULL, *signer = NULL, *newcert =NULL;
	pki_key *signkey = NULL;
	a1time time;
	a1int serial;
	emit init_database();
	try {
		CertExtend_UI *dlg = new CertExtend_UI(this, NULL, true);
		dlg->image->setPixmap(*MainWindow::certImg);
		dlg->notBefore->setDate(time.now());
		dlg->notAfter->setDate(time.now(60 * 60 * 24 * 356));
		
		if (!dlg->exec()) {
			delete dlg;
			return;
		}
		oldcert = (pki_x509 *)getSelected();
		if (!oldcert || !(signer = oldcert->getSigner()) || !(signkey = signer->getRefKey()) || signkey->isPubKey()) return;
		newcert = new pki_x509(oldcert);
		serial = signer->getIncCaSerial();
		
		// get signers own serial to avoid having the same
		if (serial == signer->getSerial()) {
			serial = signer->getIncCaSerial(); // just take the next one
		}
		db->updatePKI(signer);  // FIXME::not so pretty ....
		
		// change date and serial
		newcert->setSerial(serial);
		newcert->setNotBefore(dlg->notBefore->getDate());
		newcert->setNotAfter(dlg->notBefore->getDate());

		if (newcert->resetTimes(signer) > 0) {
			if (QMessageBox::information(this,tr(XCA_TITLE),
				tr("The validity times for the certificate need to get adjusted to not exceed those of the signer"),
				tr("Continue creation"), tr("Abort")
			))
				throw errorEx("");
		}
		
		
		// and finally sign the request 
		newcert->sign(signkey, oldcert->getDigest());
		insert(newcert);
		delete dlg;
	}
	catch (errorEx &err) {
		Error(err);
		if (newcert)
			delete newcert;
	}
}
		
void CertView::showItem(pki_base *item, bool import)
{
	if (!item) return; 
    try {
	CertDetail *dlg = new CertDetail(this,0,true);
	bool ret;
	dlg->setCert((pki_x509 *)item);
	connect( dlg->privKey, SIGNAL( doubleClicked(QString) ), 
		this, SLOT( dlg_showKey(QString) ));
	connect( dlg->signCert, SIGNAL( doubleClicked(QString) ), 
		this, SLOT( showItem(QString) ));
	if (import) {
		dlg->setImport();
	}

	// show it to the user...	
	QString odesc = item->getIntName();
	ret = dlg->exec();
	QString ndesc = dlg->descr->text();
	delete dlg;
	if (!ret && import) {
		delete item;
	}
	if (!ret) return;	
	
	emit init_database();
	
	if (import) {
		item = insert(item);
	}
	if (ndesc != odesc) {
		db->renamePKI(item, ndesc);
		return;
	}
    }
    catch (errorEx &err) {
	    Error(err);
    }
    return ;
}

void CertView::deleteItem()
{
    try {
	pki_x509 *cert = (pki_x509 *)getSelected();
	if (!cert) return;
	if (cert->getSigner() && cert->getSigner() != cert && cert->getSigner()->canSign()) {
		QMessageBox::information(this,tr(XCA_TITLE),
			tr("It is actually not a good idea to delete a cert that was signed by you") +":\n'" + 
			cert->getIntName() + "'\n" ,
			tr("Ok") );
	}
    	deleteItem_default(tr("The certificate"), tr("is going to be deleted"));
    }
    catch (errorEx &err) {
	    Error(err);
    }
}

void CertView::load()
{
	QStringList filter;
	filter.append(tr("Certificates ( *.pem *.der *.crt *.cer )")); 
	load_default(filter,tr("Certificate import"));
}

pki_base *CertView::loadItem(QString fname)
{
	pki_x509 *cert = new pki_x509(fname);
	return cert;
}

void CertView::loadPKCS12()
{
	pki_pkcs12 *pk12;
	QStringList filt;
	filt.append(tr("PKCS#12 Certificates ( *.p12 *.pfx )")); 
	filt.append(tr("All files ( *.* )"));
	QStringList slist;
	QString s="";
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption(tr("Certificate import"));
	dlg->setFilters(filt);
	dlg->setMode( QFileDialog::ExistingFiles );
        dlg->setDir(MainWindow::getPath());
	if (dlg->exec()) {
		slist = dlg->selectedFiles();
		MainWindow::setPath(dlg->dirPath());
	}
	delete dlg;
	for ( QStringList::Iterator it = slist.begin(); it != slist.end(); ++it ) {
		s = *it;
		s = QDir::convertSeparators(s);
		try {
			pk12 = new pki_pkcs12(s, &MainWindow::passRead);
			insertP12(pk12);
		}
		catch (errorEx &err) {
			Error(err);
		}
		delete pk12;
	}
	updateView();
}

			
void CertView::insertP12(pki_pkcs12 *pk12)
{
	pki_x509 *acert;
	pki_key *akey;

	try {
		akey = pk12->getKey();
		acert = pk12->getCert();
#ifdef INSERT_WO_ASK
		insertKey(akey);
		insertCert(acert);
		for (int i=0; i<pk12->numCa(); i++) {
			acert = pk12->getCa(i);
			insertCert(acert);
		}
#else
		emit importKey(akey);
		showItem(acert,true);
		for (int i=0; i<pk12->numCa(); i++) {
			acert = pk12->getCa(i);
			showItem(acert, true);
		}
#endif			
	}
	catch (errorEx &err) {
		Error(err);
	}
}	
	

void CertView::loadPKCS7()
{
	pki_pkcs7 *pk7 = NULL;
	pki_x509 *acert;
	QStringList filt;
	filt.append(tr("PKCS#7 data ( *.p7s *.p7m *.p7b )")); 
	filt.append(tr("All files ( *.* )"));
	QStringList slist;
	QString s="";
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption(tr("Certificate import"));
	dlg->setFilters(filt);
	dlg->setMode( QFileDialog::ExistingFiles );
        dlg->setDir(MainWindow::getPath());
	if (dlg->exec()) {
		slist = dlg->selectedFiles();
		MainWindow::setPath(dlg->dirPath());
	}
	delete dlg;
	for ( QStringList::Iterator it = slist.begin(); it != slist.end(); ++it ) {
		s = *it;
		s = QDir::convertSeparators(s);
		try {
			pk7 = new pki_pkcs7(s);
			pk7->readP7(s);
			for (int i=0; i<pk7->numCert(); i++) {
				acert = pk7->getCert(i);
				showItem(acert, true);
			}
			// keys->updateView();
		}
		catch (errorEx &err) {
			Error(err);
		}
		if (pk7) delete pk7;
	}
}


pki_base *CertView::insert(pki_base *item)
{
    pki_x509 *cert = (pki_x509 *)item;
    emit init_database();
    try {
	pki_x509 *oldcert = (pki_x509 *)db->getByReference(cert);
	if (oldcert) {
	   QMessageBox::information(this,tr(XCA_TITLE),
		tr("The certificate already exists in the database as") +":\n'" +
		oldcert->getIntName() + 
		"'\n" + tr("and so it was not imported"), "OK");
	   delete(cert);
	   return oldcert;
	}
	cert->setCaSerial((cert->getSerial()));
	XcaListView::insert(cert);
	db->insertPKI(cert);
    }
    catch (errorEx &err) {
	    Error(err);
    }
    a1int serial;
    // check the CA serial of the CA of this cert to avoid serial doubles
    if (cert->getSigner() != cert && cert->getSigner()) {
	serial = cert->getSerial();
    if (cert->getSigner()->getCaSerial() < serial ) {
		QMessageBox::information(this,tr(XCA_TITLE),
			tr("The certificate-serial is higher than the next serial of the signer it will be set to ") +
		(++serial).toHex(), "OK");
		cert->getSigner()->setCaSerial(serial);
    	db->updatePKI(cert->getSigner());
	}
    }
    // check CA serial of this cert
    MainWindow::certs->searchSerial(cert);
    if ( serial > cert->getCaSerial()) {
	QMessageBox::information(this,tr(XCA_TITLE),
		tr("The certificate CA serial is lower than the highest serial of one signed certificate it will be set to ") +
		serial.toHex(), "OK");
	cert->setCaSerial(serial);
    }
    db->updatePKI(cert);
    return cert;
}

#define P7_ONLY 0
#define P7_CHAIN 1
#define P7_TRUSTED 2

void CertView::store()
{
	QStringList filt;
	pki_x509 *crt = (pki_x509 *)getSelected();
	pki_x509 *oldcrt = NULL;
	emit init_database();
	if (!crt) return;
	pki_key *privkey = crt->getRefKey();
	ExportCert *dlg = new ExportCert((crt->getIntName() + ".crt"),
			  (privkey && privkey->isPrivKey()), MainWindow::getPath(), crt->tinyCAfname() );
	dlg->image->setPixmap(*MainWindow::certImg);
	int dlgret = dlg->exec();

	if (!dlgret) {
		delete dlg;
		return;
	}
	QString fname = dlg->filename->text();
        if (fname == "") {
                delete dlg;
                return;
        }
	try {
	    switch (dlg->exportFormat->currentItem()) {
		case 0: // PEM
			crt->writeCert(fname,true,false);
			break;
		case 1: // PEM with chain
			while(crt && crt != oldcrt) {
				crt->writeCert(fname,true,true);
				oldcrt = crt;
				crt = crt->getSigner();
			}
			break;
		case 2: // PEM all trusted Certificates
			MainWindow::certs->writeAllCerts(fname,true);
			break;
		case 3: // PEM all Certificates
			MainWindow::certs->writeAllCerts(fname,false);
			break;
		case 4: // DER	
			crt->writeCert(fname,false,false);
			break;
		case 5: // P7 lonely
			writePKCS7(fname, P7_ONLY);
			break;
		case 6: // P12
			writePKCS7(fname, P7_CHAIN);
			break;
		case 7: // P12
			writePKCS7(fname, P7_TRUSTED);
			break;
		case 8: // P12
			writePKCS12(fname,false);
			break;
		case 9: // P12 + cert chain
			writePKCS12(fname,true);
			break;

	    }
	}
	catch (errorEx &err) {
		Error(err);
	}
	delete dlg;
}


void CertView::writePKCS12(QString s, bool chain)
{
	QStringList filt;
    try {
	pki_x509 *cert = (pki_x509 *)getSelected();
	if (!cert) return;
	pki_key *privkey = cert->getRefKey();
	if (!privkey || privkey->isPubKey()) {
		QMessageBox::warning(this,tr(XCA_TITLE),
                	tr("There was no key found for the Certificate: ") +
			cert->getIntName() );
		return; 
	}
	if (s.isEmpty()) return;
	s = QDir::convertSeparators(s);
	pki_pkcs12 *p12 = new pki_pkcs12(cert->getIntName(), cert, privkey, &MainWindow::passWrite);
	pki_x509 *signer = cert->getSigner();
	while ((signer != NULL ) && (signer != cert) && chain) {
		p12->addCaCert(signer);
		cert=signer;
		signer=signer->getSigner();
	}
	p12->writePKCS12(s);
	delete p12;
    }
    catch (errorEx &err) {
	    Error(err);
    }
}

void CertView::writePKCS7(QString s, int type)
{
    pki_pkcs7 *p7 = NULL;
    QList<pki_base> list;
    pki_x509 *cert = (pki_x509 *)getSelected();
    pki_base *cer;
    emit init_database();
    try {	
	p7 =  new pki_pkcs7("");
	if ( type == P7_CHAIN ) {
		while (cert != NULL) {
			p7->addCert(cert);
			if (cert->getSigner() == cert) cert = NULL;
			else cert = cert->getSigner();
		}
	}
	if ( type == P7_ONLY ) {
		p7->addCert(cert);
	}	
	if (type == P7_TRUSTED) {
		list = db->getContainer();
		if (!list.isEmpty()) {
       			for ( cer = list.first(); cer != NULL; cer = list.next() ) {
				p7->addCert((pki_x509 *)cer);
			}
		}
	}
	p7->writeP7(s, false);
    }
    catch (errorEx &err) {
	    Error(err);
    }
    if (p7 != NULL ) delete p7;
	
}
		
void CertView::signP7()
{
	QStringList filt;
    try {
	pki_x509 *cert = (pki_x509 *)getSelected();
	if (!cert) return;
	pki_key *privkey = cert->getRefKey();
	if (!privkey || privkey->isPubKey()) {
		QMessageBox::warning(this,tr(XCA_TITLE),
                	tr("There was no key found for the Certificate: ") +
			cert->getIntName());
		return; 
	}
        filt.append("All Files ( *.* )");
	QString s="";
	QStringList slist;
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption(tr("Import Certificate signing request"));
	dlg->setFilters(filt);
	dlg->setMode( QFileDialog::ExistingFiles );
        dlg->setDir(MainWindow::getPath());
	if (dlg->exec()) {
		slist = dlg->selectedFiles();
		MainWindow::setPath(dlg->dirPath());
        }
	delete dlg;
	pki_pkcs7 * p7 = new pki_pkcs7("");
	for ( QStringList::Iterator it = slist.begin(); it != slist.end(); ++it ) {
		s = *it;
		s = QDir::convertSeparators(s);
		p7->signFile(cert, s);
		p7->writeP7((s + ".p7s"), true);
	}
	delete p7;
    }
    catch (errorEx &err) {
	Error(err);
    }
}	

void CertView::encryptP7()
{
	QStringList filt;
    try {
	pki_x509 *cert = (pki_x509 *)getSelected();
	if (!cert) return;
	pki_key *privkey = cert->getRefKey();
	if (!privkey || privkey->isPubKey()) {
		QMessageBox::warning(this,tr(XCA_TITLE),
                	tr("There was no key found for the Certificate: ") +
			cert->getIntName()) ;
		return; 
	}
        filt.append("All Files ( *.* )");
	QString s="";
	QStringList slist;
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption(tr("Import Certificate signing request"));
	dlg->setFilters(filt);
	dlg->setMode( QFileDialog::ExistingFiles );
        dlg->setDir(MainWindow::getPath());
	if (dlg->exec()) {
		slist = dlg->selectedFiles();
		MainWindow::setPath(dlg->dirPath());
        }
	delete dlg;
	pki_pkcs7 * p7 = new pki_pkcs7("");
	for ( QStringList::Iterator it = slist.begin(); it != slist.end(); ++it ) {
		s = *it;
		s = QDir::convertSeparators(s);
		p7->encryptFile(cert, s);
		p7->writeP7((s + ".p7m"), true);
	}
	delete p7;
    }
    catch (errorEx &err) {
	Error(err);
    }
}	

void CertView::popupMenu(QListViewItem *item, const QPoint &pt, int x) {
	QPopupMenu *menu = new QPopupMenu(this);
	QPopupMenu *subCa = new QPopupMenu(this);
	QPopupMenu *subP7 = new QPopupMenu(this);
	QPopupMenu *subExport = new QPopupMenu(this);
	int itemExtend, itemRevoke, itemTrust, itemCA, itemTemplate, itemReq, itemP7, itemtca;
	bool canSign, parentCanSign, hasTemplates, hasPrivkey;
	
	emit init_database();
	if (!item) {
		menu->insertItem(tr("New Certificate"), this, SLOT(newItem()));
		menu->insertItem(tr("Import"), this, SLOT(load()));
		menu->insertItem(tr("Import PKCS#12"), this, SLOT(loadPKCS12()));
		menu->insertItem(tr("Import from PKCS#7"), this, SLOT(loadPKCS7()));
	}
	else {
		pki_x509 *cert = (pki_x509 *)db->getByName(item->text(0));
		menu->insertItem(tr("Rename"), this, SLOT(startRename()));
		menu->insertItem(tr("Show Details"), this, SLOT(showItem()));
		menu->insertItem(tr("Export"), subExport);
		subExport->insertItem(tr("File"), this, SLOT(store()));
		itemReq = subExport->insertItem(tr("Request"), this, SLOT(toRequest()));
		itemtca = subExport->insertItem(tr("TinyCA"), this, SLOT(toTinyCA()));

		menu->insertItem(tr("Delete"), this, SLOT(deleteItem()));
		itemTrust = menu->insertItem(tr("Trust"), this, SLOT(setTrust()));
		menu->insertSeparator();
		itemCA = menu->insertItem(tr("CA"), subCa);
		subCa->insertItem(tr("Serial"), this, SLOT(setSerial()));
		subCa->insertItem(tr("CRL days"), this, SLOT(setCrlDays()));
		itemTemplate = subCa->insertItem(tr("Signing Template"), this, SLOT(setTemplate()));
		subCa->insertItem(tr("Generate CRL"), this, SLOT(genCrl()));
		
		itemP7 = menu->insertItem(tr("PKCS#7"), subP7);
		subP7->insertItem(tr("Sign"), this, SLOT(signP7()));
		subP7->insertItem(tr("Encrypt"), this, SLOT(encryptP7()));
		menu->insertSeparator();
		itemExtend = menu->insertItem(tr("Renewal"), this, SLOT(extendCert()));
		if (cert) {
			if (cert->isRevoked()) {
				itemRevoke = menu->insertItem(tr("Unrevoke"), this, SLOT(unRevoke()));
				menu->setItemEnabled(itemTrust, false);
			}
			else	
				itemRevoke = menu->insertItem(tr("Revoke"), this, SLOT(revoke()));
			parentCanSign = (cert->getSigner() && cert->getSigner()->canSign() && (cert->getSigner() != cert));
			canSign = cert->canSign();
			hasTemplates = MainWindow::temps->getDesc().count() > 0 ;
			hasPrivkey = cert->getRefKey();
		}
		menu->setItemEnabled(itemExtend, parentCanSign);
		menu->setItemEnabled(itemRevoke, parentCanSign);
		menu->setItemEnabled(itemCA, canSign);
		subExport->setItemEnabled(itemReq, hasPrivkey);
		subExport->setItemEnabled(itemtca, canSign);
		menu->setItemEnabled(itemP7, hasPrivkey);
		subCa->setItemEnabled(itemTemplate, hasTemplates);

	}
	menu->exec(pt);
	delete menu;
	delete subCa;
	delete subP7;
	delete subExport;
	
	return;
}

void CertView::setTrust()
{
	pki_x509 *cert = (pki_x509 *)getSelected();
	if (!cert) return;
	TrustState_UI *dlg = new TrustState_UI(this,0,true);
	int state, newstate;
	dlg->image->setPixmap(*MainWindow::certImg);
	state = cert->getTrust();
	if (cert->getSigner() == cert) {
		if (state == 1) state = 0;
		dlg->trust1->setDisabled(true);
	}
	if (state == 0 ) dlg->trust0->setChecked(true);
	if (state == 1 ) dlg->trust1->setChecked(true);
	if (state == 2 ) dlg->trust2->setChecked(true);
	dlg->certName->setText(cert->getIntName());
	if (dlg->exec()) {
		if (dlg->trust0->isChecked()) newstate = 0;
		if (dlg->trust1->isChecked()) newstate = 1;
		if (dlg->trust2->isChecked()) newstate = 2;
		if (newstate!=state) {
			cert->setTrust(newstate);
			db->updatePKI(cert);
			updateView();
		}
	}
	delete dlg;
}

void CertView::toRequest()
{
	pki_x509 *cert = (pki_x509 *)getSelected();
	if (!cert) return;
	try {
		pki_x509req *req = new pki_x509req();
		req->setIntName(cert->getIntName());
		req->createReq(cert->getRefKey(), cert->getSubject(), EVP_md5());
                emit insertReq(req);
	}
	catch (errorEx &err) {
		Error(err);
	}
	
}

void CertView::revoke()
{
	pki_x509 *cert = (pki_x509 *)getSelected();
	if (!cert) return;
	cert->setRevoked(true);
	db->updatePKI(cert);
	updateView();
}

void CertView::unRevoke()
{
	pki_x509 *cert = (pki_x509 *)getSelected();
	if (!cert) return;
	cert->setRevoked(false);
	db->updatePKI(cert);
	updateView();
}

void CertView::setSerial()
{
	pki_x509 *cert = (pki_x509 *)getSelected();
	if (!cert) return;
	a1int serial = cert->getCaSerial();
	bool ok;
	a1int nserial = QInputDialog::getInteger (tr(XCA_TITLE),
			tr("Please enter the new Serial for signing"),
			serial.getLong(), serial.getLong(), 2147483647, 1, &ok, this );
	if (ok && nserial > serial) {
		cert->setCaSerial(nserial);
		db->updatePKI(cert);
	}
}

void CertView::setCrlDays()
{
	pki_x509 *cert = (pki_x509 *)getSelected();
	if (!cert) return;
	int crlDays = cert->getCrlDays();
	bool ok;
	int nCrlDays = QInputDialog::getInteger (tr(XCA_TITLE),
			tr("Please enter the CRL renewal periode in days"),
			crlDays, 1, 2147483647, 1, &ok, this );
	if (ok && (crlDays != nCrlDays)) {
		cert->setCrlDays(nCrlDays);
		db->updatePKI(cert);
	}
}

void CertView::setTemplate()
{
	pki_x509 *cert = (pki_x509 *)getSelected();
	if (!cert) return;
	QString templ = cert->getTemplate();
	QStringList tempList = MainWindow::temps->getDesc();
	unsigned int i, sel=0;
	bool ok;
	for (i=0; i<tempList.count(); i++) {
		if (tempList[i] == templ) {
			sel = i;
		}
	}
	QString nTempl = QInputDialog::getItem (tr(XCA_TITLE),
			tr("Please select the default Template for signing"),
			tempList, sel, false, &ok, this );
	if (ok && (templ != nTempl)) {
		cert->setTemplate(nTempl);
		db->updatePKI(cert);
	}
}


void CertView::changeView(QPushButton *b)
{
	if (viewState == 0) { // Plain view
		viewState = 1;
		b->setText(tr("Plain View"));
	}
	else { // Tree View
		viewState = 0;
		b->setText(tr("Tree View"));
	}
	updateView();
}

#define fopenerror(file) \
	QMessageBox::warning(this,tr(XCA_TITLE), \
       		tr("The file '") + file + tr("' could not be opened"));

void CertView::toTinyCA()
{
#ifndef WIN32
	pki_x509 *crt = (pki_x509 *)getSelected();
	if (!crt) return;
	pki_key *key = crt->getRefKey();
	if (!key) return;
	FILE *fp, *fpr;
	char buf[200];
	QList<pki_x509> list;
	pki_x509 *issuedcert;
	QString dname = crt->getIntName();
	QString tcatempdir = MainWindow::settings->getString("TinyCAtempdir");
	QString tcadir = MainWindow::settings->getString("TinyCAdir");
	if (tcatempdir.isEmpty()) {
		tcatempdir = "templates";
	}
	if (tcadir.isEmpty()) {
		tcadir = QDir::homeDirPath();
		tcadir += QDir::separator();
		tcadir += ".TinyCA";
	}
	ExportTinyCA *dlg = new ExportTinyCA( tcatempdir, tcadir, this, NULL);
	if (!dlg->exec()) return;
	
	tcatempdir = dlg->tempdir->text();
	tcadir = dlg->tinycadir->text();
	dname = dlg->dname->text();
	
	MainWindow::settings->putString("TinyCAtempdir", tcatempdir);
	MainWindow::settings->putString("TinyCAdir", tcadir);
	
	if (dname.isEmpty()) return;
	const EVP_CIPHER *enc = EVP_des_ede3_cbc();
	
	
	// OK, we have all names now...
	tcadir += QDir::separator();
        tcadir += dname;
	
	//create directory tree
	if (! mkDir(tcadir)) return;
	chdir(tcadir);
	if (! mkDir("certs")) return;
	if (! mkDir("crl")) return;
	if (! mkDir("keys")) return;
	if (! mkDir("newcerts")) return;
	if (! mkDir("req")) return;
	
	// write the CA cert and key
	crt->writeCert("cacert.pem", true, false);
	key->writeKey("cacert.key", enc, &MainWindow::passWrite, true);
	// write the crl
	chdir("crl");
	pki_crl *crl; // FIXME:  = genCrl(crt);
	crl->writeCrl("crl.pem");
	delete crl;
	chdir("..");
	// write the serial
	fp = fopen("serial", "w");
	if (!fp) {
		fopenerror("serial");
		return;
	}
	fprintf(fp, "%08lx", crt->getCaSerial().getLong());
	fclose(fp);
	
	// copy openssl.cnf
	tcatempdir += QDir::separator();
	tcatempdir += "openssl.cnf";
	fpr = fopen(tcatempdir, "r");
	if (!fpr) {
		fopenerror("openssl.cnf" );
		return;
	}
	fp = fopen("openssl.cnf", "w");
	if (!fp) {
		fopenerror("openssl.cnf" );
		fclose(fpr);
		return;
	}
	while (fgets(buf ,200, fpr) != NULL) {
		char *x = strstr(buf,"%dir%");
		if (x != 0) {
			x[0]='\0';
			fputs(buf, fp);
			fputs(tcadir, fp);
			fputs(x+5, fp);
		}
		else {
			fputs(buf, fp);
		}
	}
	fclose(fp);
	fclose(fpr);
	
	// store the issued certificates
	fp = fopen("index.txt", "w");
        if (!fp) return;
	list = ((db_x509 *)db)->getIssuedCerts(crt);
	if (!list.isEmpty()) {
       		for ( issuedcert = list.first(); issuedcert != NULL; issuedcert = list.next() ) {
			QString fname = issuedcert->tinyCAfname();
			chdir("certs");
			crt->writeCert(fname, true, false);
			chdir("..");
			key = issuedcert->getRefKey();
			if (key) {
				chdir("keys");
				key->writeKey(fname, NULL, &MainWindow::passWrite, true);
				chdir("..");
			}
			fprintf(fp, "%c\t%s\t%s\t%s\tunknown\t%s\n", 
					issuedcert->isRevoked() ? 'R':'V', 
					issuedcert->getNotAfter().toPlain().latin1(),
					issuedcert->getRevoked().toPlain().latin1(),
					issuedcert->getSerial().toHex().latin1(), 
					issuedcert->getSubject().oneLine().latin1() );
			
		}
	}
	fclose(fp);
	
#endif	
}	

void CertView::updateView()
{
	clear();
	setRootIsDecorated(true);
	pki_x509 *pki, *signer;
	pki_base *pkib;
	QListViewItem *parentitem,  *current;
	QList<pki_base> container = db->getContainer();
	if ( container.isEmpty() ) return;
	QList<pki_base> mycont = container;
	for ( pkib = container.first(); pkib != NULL; pkib = container.next() ) pkib->delLvi();
	while (! mycont.isEmpty() ) {
		QListIterator<pki_base> it(mycont);
		for ( ; it.current(); ++it ) {
			pki = (pki_x509 *)it.current();
			parentitem = NULL;
			signer = pki->getSigner();
			// foreign signed
			if ((signer != pki) && (signer != NULL) && (viewState != 0)) 
				parentitem = signer->getLvi();
			if (((parentitem != NULL) || (signer == pki) || (signer == NULL)
				|| viewState == 0) && (pki->getLvi() == NULL )) {
				// create the listview item
				if (parentitem != NULL) {
					current = new QListViewItem(parentitem);
				}
				else {
					current = new QListViewItem(this);
				}
				pki->setLvi(current);
				mycont.remove(pki);
				pki->updateView();
				it.toFirst();
			}
		}
	}
	return;
}

bool CertView::mkDir(QString dir)
{
#ifdef WIN32
        int ret = mkdir(dir.latin1());
        // in direct.h declare _CRTIMP int __cdecl mkdir(const char *);
#else
        int ret = mkdir(dir.latin1(), S_IRUSR | S_IWUSR | S_IXUSR);
#endif
        if (ret) {
                QString desc = " (";
                desc += strerror(ret);
                desc += ")";
                QMessageBox::critical(this,tr(XCA_TITLE),
                        tr("Error creating: ") + dir + desc);
                return false;
        }
        return true;

}

void CertView::updateViewAll()
{
	emit init_database();
	QList<pki_base> c = db->getContainer();
	for (pki_x509 *pki = (pki_x509 *)c.first(); pki != 0; pki = (pki_x509 *)c.next() ) 
		pki->updateView();
	return;
}

void CertView::genCrl()
{
	emit genCrl((pki_x509 *)getSelected());
}

