#include "MainWindow.h"

const int MainWindow::sizeList[] = {256, 512, 1024, 2048, 4096, 0 };


pki_key *MainWindow::getSelectedKey()
{
	CERR << "get Selected Key" << endl;
	pki_key *targetKey = (pki_key *)keys->getSelectedPKI();
	CERR << "got selected: "<< (int)targetKey << endl;
	if (targetKey) {
	   string errtxt = targetKey->getError();
	   if (errtxt != "")
		QMessageBox::warning(this,tr("Key error"),
			tr("The Key: ") + QString::fromLatin1(targetKey->getDescription().c_str()) +
			tr(" is not consistent:") + QString::fromLatin1(errtxt.c_str()) );
	}
	CERR << "targetKey = " << (int)targetKey << endl;
	return targetKey;
}


void MainWindow::newKey()
{
	NewKey_UI *dlg = new NewKey_UI(this,0,true,0);
	QString x;
	for (int i=0; sizeList[i] != 0; i++ ) 
	   dlg->keyLength->insertItem( x.number(sizeList[i]) +" bit");	
	dlg->keyLength->setCurrentItem(2);
	if (dlg->exec()) {
	   int sel = dlg->keyLength->currentItem();
	   QProgressDialog *progress = new QProgressDialog(
		tr("Please wait, Key generation is in progress"),
		tr("Cancel"),90, 0, 0, true);
	   progress->setMinimumDuration(0);
	   progress->setProgress(0);	
	   pki_key *nkey = new pki_key (dlg->keyDesc->text().latin1(), 
		       &MainWindow::incProgress,
		       progress,
		       sizeList[sel]);
           progress->cancel();
	   insertKey(nkey);
	}
}


void MainWindow::deleteKey()
{
	pki_key *delKey = getSelectedKey();
	if (!delKey) return;
	if (QMessageBox::information(this,"Delete key",
			tr("The key") + ": '" + 
			QString::fromLatin1(delKey->getDescription().c_str()) +
			"'\n" + tr("is going to be deleted"),
			"Delete", "Cancel")
	) return;
	keys->deletePKI(delKey);
}


void MainWindow::showDetailsKey(pki_key *key)
{
	if (key == NULL ) return;
	KeyDetail_UI *detDlg = new KeyDetail_UI(this, 0, true, 0 );
	
	detDlg->keyDesc->setText(
		key->getDescription().c_str() );
	detDlg->keyLength->setText(
		key->length().c_str() );
	detDlg->keyPubEx->setText(
		key->pubEx().c_str() );
	detDlg->keyModulus->setText(
		key->modulus().c_str() );
	detDlg->keyPrivEx->setText(
		key->privEx().c_str() );

	if ( !detDlg->exec()) return;
	string ndesc = detDlg->keyDesc->text().latin1();
	if (ndesc != key->getDescription()) {
		keys->updatePKI(key, ndesc);
	}
}


void MainWindow::showDetailsKey()
{
	pki_key *targetKey = getSelectedKey();
	if (targetKey) showDetailsKey(targetKey);
}


void MainWindow::showDetailsKey(QListViewItem *item)
{
	string key = item->text(0).latin1();
	showDetailsKey((pki_key *)keys->getSelectedPKI(key));
}


void MainWindow::loadKey()
{
	QStringList filt;
	filt.append( "PKI Keys ( *.pem *.der )"); 
	filt.append( "PKCS#8 Keys ( *.p8 *.pk8 )"); 
	filt.append( "All Files ( *.* )");
	string s;
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption("Import key");
	dlg->setFilters(filt);
	if (dlg->exec())
		s = dlg->selectedFile().latin1();
	if (s == "") return;
	string errtxt;
	pki_key *lkey = new pki_key(s, &MainWindow::passRead);
	if ((errtxt = lkey->getError()) != "") {
		QMessageBox::warning(this,"Key error",
			tr("The key") +": " + QString::fromLatin1(s.c_str()) +
			"\n"+ tr("could not be loaded") + QString::fromLatin1(errtxt.c_str()) );
		return;
	}
	insertKey(lkey);
}


void MainWindow::insertKey(pki_key *lkey)
{
	pki_key *oldkey;
	QString title=tr("Key storing");
	if ((oldkey = (pki_key *)keys->findPKI(lkey))!= 0) {
		if ((oldkey->isPrivKey() && lkey->isPrivKey()) ||
		    lkey->isPubKey()){
	   	    QMessageBox::information(this,title,
			tr("The key is already in the database as") +":\n'" +
			QString::fromLatin1(oldkey->getDescription().c_str()) + 
			"'\n" + tr("and is not going to be imported"), "OK");
		    delete(lkey);
		    return;
		}
		else {
	   	    QMessageBox::information(this,title,
			tr("The database already contains the public part of the imported key as") +":\n'" +
			QString::fromLatin1(oldkey->getDescription().c_str()) + 
			"'\n" + tr("and will be completed by the new, private part of the key"), "OK");
		    CERR << "before deleting pki...\n";
		    keys->deletePKI(oldkey);
		    lkey->setDescription(oldkey->getDescription());
		    delete(oldkey);
		}
	}
	CERR << "after findkey\n";
	if (keys->insertPKI(lkey))
	   QMessageBox::information(this,title,
		tr("The Key was successfully stored as:\n'") +
		QString::fromLatin1(lkey->getDescription().c_str()) + "'", "OK");
	else	
	   QMessageBox::warning(this,title,
		tr("The key could not be stored into the database"), "OK");
	
}


void MainWindow::writeKey()
{
	bool PEM=false;
	EVP_CIPHER *enc = NULL;
	pki_key *targetKey = NULL;
	targetKey = getSelectedKey();
	if (!targetKey) return;
	ExportKey *dlg = new ExportKey((targetKey->getDescription() + ".pem").c_str(),
			targetKey->isPubKey(), this);
	dlg->exportFormat->insertItem("PEM");
	dlg->exportFormat->insertItem("DER");
	if (targetKey->isPrivKey())
		dlg->exportFormat->insertItem("PKCS#8");
	if (!dlg->exec()) return;
	string fname = dlg->filename->text().latin1();
	if (fname == "") return;
	if (dlg->exportFormat->currentText() == "PEM") PEM = true;
	if (dlg->exportFormat->currentText() == "PKCS#8")
		 targetKey->writePKCS8(fname, &MainWindow::passWrite);
	else if (dlg->exportPrivate->isChecked()) {
	   if (dlg->encryptKey->isChecked())
   	   	enc = EVP_des_ede3_cbc();
	   targetKey->writeKey(fname, enc, &MainWindow::passWrite, PEM);
	}
	else {
		targetKey->writePublic(fname, PEM);
	}
	string errtxt;
	if ((errtxt = targetKey->getError()) != "") {
		QMessageBox::warning(this,tr("File error"),
			tr("Der Schlüssel") +": '" + QString::fromLatin1(fname.c_str()) +
			"'\n" + tr("could not be written") +":\n" + QString::fromLatin1(errtxt.c_str()));
		return;
	}
	QMessageBox::information(this,tr("Key export"),
		tr("The key was successfull exported into the file") + ":\n'" +
		QString::fromLatin1(fname.c_str()) , "OK");

}


