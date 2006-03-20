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

#include "db_x509.h"
#include "pki_pkcs12.h"
#include "pki_pkcs7.h"
#include "widgets/CertDetail.h"
#include "widgets/ExportCert.h"
#include <Qt/qmessagebox.h>
#include <Qt/qevent.h>
#include <Qt/qaction.h>


db_x509::db_x509(QString DBfile, MainWindow *mw)
	:db_x509super(DBfile, mw)
{

	delete rootItem;
	rootItem = newPKI();
	headertext << tr("Internal name") << tr("Common name") << tr("Serial") <<
			tr("not After") << tr("Trust state") << tr("Revocation");

	delete_txt = tr("Delete the certificates(s)");
	loadContainer();
	// FIXME:
	// connect(keyl, SIGNAL(delKey(pki_key *)), this, SLOT(delKey(pki_key *)));
	// connect(keyl, SIGNAL(newKey(pki_key *)), this, SLOT(newKey(pki_key *)));
}

pki_base *db_x509::newPKI(){
	return new pki_x509();
}

pki_x509 *db_x509::findSigner(pki_x509 *client)
{
	pki_x509 *signer;
	if ((signer = client->getSigner()) != NULL) return signer;
	// first check for self-signed
	if (client->verify(client)) {
		return client;
	}
	FOR_ALL_pki(pki, pki_x509)
		if (client->verify(pki)) 
			return pki;
	return NULL;
}

QStringList db_x509::getPrivateDesc()
{
	QStringList x;
	FOR_ALL_pki(pki, pki_x509)
		if (pki->getRefKey())
			x.append(pki->getIntName());	
	return x;
}

QStringList db_x509::getSignerDesc()
{
	QStringList x;
	FOR_ALL_pki(pki, pki_x509)
		if (pki->canSign())
			x.append(pki->getIntName());	
	return x;
}


void db_x509::remFromCont(pki_base *ref)
{
	db_base::remFromCont(ref);
	FOR_ALL_pki(pki, pki_x509)
		pki->delSigner((pki_x509 *)ref);
	return;
}

void db_x509::preprocess()
{
	FOR_ALL_pki(pki, pki_x509) {
		findSigner(pki);
		findKey(pki);	
	}
	calcEffTrust();
	
}


void db_x509::calcEffTrust()
{
	FOR_ALL_pki(pki, pki_x509)
		pki->calcEffTrust();
}

	
void db_x509::insertPKI(pki_base *refpki)
{
	db_base::insertPKI(refpki);
	pki_x509 *x = (pki_x509 *)refpki;
	findSigner(x);
	findKey(x);
	FOR_ALL_pki(pki, pki_x509)
		pki->verify(x);
	calcEffTrust();
}				


QList<pki_x509*> db_x509::getIssuedCerts(const pki_x509 *issuer)
{
	QList<pki_x509*> c;
	c.clear();
	if (!issuer) return c;
	FOR_ALL_pki(pki, pki_x509)
		if (pki->getSigner() == issuer)
			c.append(pki);
	return c;
}

pki_x509 *db_x509::getBySubject(const x509name &xname, pki_x509 *last)
{
	bool lastfound = false;
	if (last == NULL) lastfound = true;
	
	FOR_ALL_pki(pki, pki_x509) {
		if ( pki->getSubject() ==  xname) {
			if (lastfound) {
				return pki;
			}
		}
		if (pki == last) {
			lastfound = true;
		}
	}
	return NULL;
}

void db_x509::revokeCert(const x509rev &revok, const pki_x509 *iss)
{
	pki_x509 *crt = getByIssSerial(iss, revok.getSerial());
	if (crt)
		crt->setRevoked(revok.getDate());
}
	
pki_x509 *db_x509::getByIssSerial(const pki_x509 *issuer, const a1int &a)
{
	if (!issuer ) return NULL;
	FOR_ALL_pki(pki, pki_x509) {
		if ((pki->getSigner() == issuer) && (a == pki->getSerial()))
			return pki;
	}
	return NULL;
}

void db_x509::writeAllCerts(const QString fname, bool onlyTrusted)
{
	FOR_ALL_pki(pki, pki_x509) {
		if (onlyTrusted && pki->getTrust() != 2) continue;
		pki->writeCert(fname.toAscii(),true,true);
	}
}

QList<pki_x509*> db_x509::getCerts(bool onlyTrusted)
{
	QList<pki_x509*> c;
	c.clear();
	FOR_ALL_pki(pki, pki_x509) {
		if (onlyTrusted && pki->getTrust() != 2) continue;
		c.append(pki);
	}
	return c;
}

a1int db_x509::searchSerial(pki_x509 *signer)
{
	// returns the highest certificate serial
	// of all certs with this signer (itself too)
	a1int sserial, myserial; 
	if (!signer) return sserial;
	sserial = signer->getCaSerial();
	FOR_ALL_pki(pki, pki_x509)
		if (pki->getSigner() == signer)  {
			myserial = pki->getSerial();
			if (sserial < myserial ) {
				sserial = myserial;
			}
		}
	return sserial;
}

pki_base *db_x509::insert(pki_base *item)
{
	pki_x509 *cert = (pki_x509 *)item;
	pki_x509 *oldcert = (pki_x509 *)getByReference(cert);
	if (oldcert) {
		QMessageBox::information(mainwin, XCA_TITLE,
		tr("The certificate already exists in the database as") +":\n'" +
		oldcert->getIntName() +
		"'\n" + tr("and so it was not imported"), "OK");
		delete(cert);
		return oldcert;
	}
	cert->setCaSerial((cert->getSerial()));
	insertPKI(cert);
	a1int serial;

	// check the CA serial of the CA of this cert to avoid serial doubles
	if (cert->getSigner() != cert && cert->getSigner()) {
		serial = cert->getSerial();
		if (cert->getSigner()->getCaSerial() < ++serial ) {
			cert->getSigner()->setCaSerial(serial);
			updatePKI(cert->getSigner());
		}
	}
	
	// check CA serial of this cert
	serial = searchSerial(cert);
	if ( ++serial > cert->getCaSerial()) {
		cert->setCaSerial(serial);
	}
	updatePKI(cert);
	return cert;
}

void db_x509::load(void)
{
	load_cert c;
	load_default(c);
}

void db_x509::newItem()
{
	NewX509 *dlg = new NewX509(mainwin);
	//emit connNewX509(dlg);
	dlg->setCert();
	//dlg->defineSigner((pki_x509*)getSelected());
	if (dlg->exec()) {
		newCert(dlg);
	}
	delete dlg;
}
#if 0
void db_x509::newCert(pki_x509req *req)
{
	NewX509 *dlg = new NewX509(this, NULL, true);
	emit connNewX509(dlg);
	dlg->setCert();
	dlg->defineRequest(req);
	dlg->defineSigner((pki_x509*)getSelected());
	if (dlg->exec()) {
		newCert(dlg);
	}
	delete dlg;
}

void db_x509::newCert(pki_temp *req)
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
#endif

void db_x509::newCert(NewX509 *dlg)
{
	pki_x509 *cert = NULL;
	pki_x509 *signcert = NULL;
	pki_x509req *req = NULL;
	pki_key *signkey = NULL, *clientkey = NULL, *tempkey = NULL;
	a1int serial;
	a1time notBefore, notAfter;
	x509name subject;
	QString intname;
	
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
	    if (!req)
			return;
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
	
	// Step 2 - select Signing
	if (dlg->foreignSignRB->isChecked()) {
		signcert = dlg->getSelectedSigner();
		if (!signcert)
			return;
		serial = signcert->getIncCaSerial();
		signkey = signcert->getRefKey();
		cert->setTrust(1);
	}
#if 0
	else if (dlg->selfQASignRB->isChecked()){
          
                PassWrite_UI *dlg1 = new PassWrite_UI(NULL, 0, true);
                dlg1->image->setPixmap( *MainWindow::keyImg );
                dlg1->title->setText(XCA_TITLE);
                dlg1->description->setText(tr("Please enter the new hexadecimal secret number for the QA process."));
                dlg1->passA->setFocus();
                dlg1->passA->setValidator(new QRegExpValidator(QRegExp("[0-9a-fA-F]*"),dlg1->passA));
                dlg1->passB->setValidator(new QRegExpValidator(QRegExp("[0-9a-fA-F]*"),dlg1->passB));
                dlg1->setCaption(XCA_TITLE);
                QString A = "x", B="";

                while (dlg1->exec())
                  {
                    A = dlg1->passA->text();
                    B = dlg1->passB->text();
                    if (A==B) break;
                    else
                      QMessageBox::warning(mainwin, XCA_TITLE, tr("The two secret numbers don't match."));
                    }
                delete dlg1;
                if (A!=B)
                  throw errorEx(tr("The QA process has been terminated by the user."));
		signcert = cert;	
		signkey = clientkey;	
                serial.setHex(A);
		cert->setTrust(2);
	}
#endif
	else {
		signcert = cert;	
		signkey = clientkey;	
		serial.setHex(dlg->serialNr->text());
		cert->setTrust(2);
	}

	dlg->initCtx(cert, signcert);
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
		if (QMessageBox::information(mainwin,tr(XCA_TITLE),
			tr("The validity times for the certificate need to get adjusted to not exceed those of the signer"),
			tr("Continue creation"), tr("Abort")
		))
			throw errorEx("");
	}
	 
			
	// STEP 4 handle extensions
	if (dlg->copyReqExtCB->isChecked() && dlg->fromReqCB->isChecked()) {
		extList el = req->getV3Ext();
		int m = el.count();
		for (int i=0; i<m; i++)
			cert->addV3ext(el[i]);
	}		
		
	cert->addV3ext(dlg->getBasicConstraints());
	cert->addV3ext(dlg->getSubKeyIdent());
	cert->addV3ext(dlg->getAuthKeyIdent());
	cert->addV3ext(dlg->getKeyUsage());
	cert->addV3ext(dlg->getEkeyUsage());
	cert->addV3ext(dlg->getSubAltName());
	cert->addV3ext(dlg->getIssAltName());
	cert->addV3ext(dlg->getCrlDist());
	cert->addV3ext(dlg->getAuthInfAcc());
	cert->addV3ext(dlg->getCertPol());
	extList ne = dlg->getNetscapeExt();
	int m = ne.count();
	for (int i=0; i<m; i++)
		 cert->addV3ext(ne[i]);
	
	const EVP_MD *hashAlgo = dlg->getHashAlgo();
	if (signkey->getType() == EVP_PKEY_DSA)
		hashAlgo = EVP_dss1();
#if 0	
	if (dlg->selfQASignRB->isChecked())
          {
            // sign the request intermediately in order to finally fill
            // up the cert_info substructure.
            cert->sign(signkey, hashAlgo);
            // now set the QA serial.
            cert->setSerial(cert->hashInfo(EVP_md5()));
          }
#endif
	// and finally sign the request 
	cert->sign(signkey, hashAlgo);
	insert(cert);
	updatePKI(signcert);
	if (tempkey != NULL)
		delete(tempkey);
    }
	
    catch (errorEx &err) {
		MainWindow::Error(err);
		delete cert;
		if (tempkey != NULL) delete(tempkey);
    }
	
}

void db_x509::showItem()
{
	if (!currentIdx.isValid())
		return;
	pki_x509 *crt = static_cast<pki_x509*>(currentIdx.internalPointer());
	CertDetail *dlg;
	printf("Show Item x509\n");	
	dlg = new CertDetail(mainwin);
	if (dlg) {
		dlg->setCert(crt);
		dlg->exec();
		delete dlg;
	}
}

void db_x509::showContextMenu(QContextMenuEvent *e, const QModelIndex &index)
{
	QMenu *menu = new QMenu(mainwin);
	QMenu *subExport, *subCa, *subP7;
	QAction *itemReq, *itemtca, *itemTemplate, *itemRevoke, *itemExtend,
			*itemTrust;
	bool parentCanSign, canSign, hasTemplates, hasPrivkey;	
	currentIdx = QModelIndex();
	
	pki_x509 *cert = static_cast<pki_x509*>(index.internalPointer());
	
	menu->addAction(tr("New Certificate"), this, SLOT(newItem()));
	menu->addAction(tr("Import"), this, SLOT(load()));
	menu->addAction(tr("Import PKCS#12"), this, SLOT(loadPKCS12()));
	menu->addAction(tr("Import from PKCS#7"), this, SLOT(loadPKCS7()));
	if (index != QModelIndex()) {
		menu->addAction(tr("Show Details"), this, SLOT(showItem()));
		subExport = menu->addMenu(tr("Export"));
		subExport->addAction(tr("File"), this, SLOT(store()));
		itemReq = subExport->addAction(tr("Request"),
				this, SLOT(toRequest()));
		itemtca = subExport->addAction(tr("TinyCA"),
				this, SLOT(toTinyCA()));

		menu->addAction(tr("Delete"), this, SLOT(deletePKI()));
		itemTrust = menu->addAction(tr("Trust"), this, SLOT(setTrust()));
		menu->addSeparator();
		subCa = menu->addMenu(tr("CA"));
		subCa->addAction(tr("Serial"), this, SLOT(setSerial()));
		subCa->addAction(tr("CRL days"), this, SLOT(setCrlDays()));
		itemTemplate = subCa->addAction(tr("Signing Template"),
				this, SLOT(setTemplate()));
		subCa->addAction(tr("Generate CRL"), this, SLOT(genCrl()));
		
		subP7 = menu->addMenu(tr("PKCS#7"));
		subP7->addAction(tr("Sign"), this, SLOT(signP7()));
		subP7->addAction(tr("Encrypt"), this, SLOT(encryptP7()));
		menu->addSeparator();
		itemExtend = menu->addAction(tr("Renewal"),
				this, SLOT(extendCert()));
		if (cert) {
			if (cert->isRevoked()) {
				itemRevoke = menu->addAction(tr("Unrevoke"),
						this, SLOT(unRevoke()));
				itemTrust->setEnabled(false);
			} else {
				itemRevoke = menu->addAction(tr("Revoke"),
						this, SLOT(revoke()));
			}
			parentCanSign = (cert->getSigner() && cert->getSigner()->canSign()
					&& (cert->getSigner() != cert));
			canSign = cert->canSign();
#warning templates
			hasTemplates = false; // MainWindow::temps->getDesc().count() > 0 ;
			hasPrivkey = cert->getRefKey();
		}
		itemExtend->setEnabled(parentCanSign);
		itemRevoke->setEnabled(parentCanSign);
		subCa->setEnabled(canSign);
		itemReq->setEnabled(hasPrivkey);
		itemtca->setEnabled(canSign);
		subP7->setEnabled(hasPrivkey);
		itemTemplate->setEnabled(hasTemplates);

	}
	menu->exec(e->globalPos());
	delete menu;
	currentIdx = QModelIndex();
	return;
}


#define P7_ONLY 0
#define P7_CHAIN 1
#define P7_TRUSTED 2
#define P7_ALL 3

void db_x509::store()
{
	QStringList filt;
	if (!currentIdx.isValid())
		return;
	
	pki_x509 *crt = static_cast<pki_x509*>(currentIdx.internalPointer());
	pki_x509 *oldcrt = NULL;
	if (!crt)
		return;
	pki_key *privkey = crt->getRefKey();
	ExportCert *dlg = new ExportCert((crt->getIntName() + ".crt"),
			  (privkey && privkey->isPrivKey()),
			  mainwin->getPath(), crt->tinyCAfname() );
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
	  switch (dlg->exportFormat->currentIndex()) {
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
			writeAllCerts(fname,true);
			break;
		case 3: // PEM all Certificates
			writeAllCerts(fname,false);
			break;
		case 4: // DER	
			crt->writeCert(fname,false,false);
			break;
		case 5: // P7 lonely
			writePKCS7(crt,fname, P7_ONLY);
			break;
		case 6: // P7
			writePKCS7(crt,fname, P7_CHAIN);
			break;
		case 7: // P7
			writePKCS7(crt,fname, P7_TRUSTED);
			break;
		case 8: // P7
			writePKCS7(crt,fname, P7_ALL);
			break;
		case 9: // P12
			writePKCS12(crt,fname,false);
			break;
		case 10: // P12 + cert chain
			writePKCS12(crt,fname,true);
			break;

	  }
	}
	catch (errorEx &err) {
		MainWindow::Error(err);
	}
	delete dlg;
}


void db_x509::writePKCS12(pki_x509 *cert, QString s, bool chain)
{
	QStringList filt;
    try {
		pki_key *privkey = cert->getRefKey();
		if (!privkey || privkey->isPubKey()) {
			QMessageBox::warning(mainwin, tr(XCA_TITLE),
				tr("There was no key found for the Certificate: ") +
				cert->getIntName() );
			return; 
		}
		if (s.isEmpty())
			return;
		s = QDir::convertSeparators(s);
		pki_pkcs12 *p12 = new pki_pkcs12(cert->getIntName(), cert, privkey,
				MainWindow::passWrite);
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
		MainWindow::Error(err);
    }
}

void db_x509::writePKCS7(pki_x509 *cert, QString s, int type)
{
    pki_pkcs7 *p7 = NULL;
    QList<pki_base> list;
    pki_base *cer;
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
#if 0
	if (type == P7_TRUSTED) {
		list = db->getContainer();
		if (!list.isEmpty()) {
       		for ( cer = list.first(); cer != NULL; cer = list.next() ) {
				if (((pki_x509*)cer)->getTrust() == 2)
					p7->addCert((pki_x509 *)cer);
			}
		}
	}
	if (type == P7_ALL) {
		list = db->getContainer();
		if (!list.isEmpty()) {
			for ( cer = list.first(); cer != NULL; cer = list.next() ) {
				p7->addCert((pki_x509 *)cer);
			}
		}
	}
#else 
#warning P7_TRUSTED P7_ALL
#endif
	p7->writeP7(s, false);
    }
    catch (errorEx &err) {
		MainWindow::Error(err);
    }
    if (p7 != NULL )
		delete p7;
	
}
# if 0		
void ::signP7()
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
	Q3FileDialog *dlg = new Q3FileDialog(this,0,true);
	dlg->setCaption(tr("Import Certificate signing request"));
	dlg->setFilters(filt);
	dlg->setMode( Q3FileDialog::ExistingFiles );
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
	Qt::SocketError(err);
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
	Q3FileDialog *dlg = new Q3FileDialog(this,0,true);
	dlg->setCaption(tr("Import Certificate signing request"));
	dlg->setFilters(filt);
	dlg->setMode( Q3FileDialog::ExistingFiles );
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
		Qt::SocketError(err);
    }
}	
#endif
