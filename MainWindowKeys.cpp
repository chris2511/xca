#include "MainWindow.h"

const int MainWindow::sizeList[] = {256, 512, 1024, 2048, 4096, 0 };


pki_key *MainWindow::getSelectedKey()
{
	cerr << "get Selected Key\n";
	pki_key *targetKey = (pki_key *)keys->getSelectedPKI();
	cerr << "got selected: "<< (int)targetKey << endl;
	if (targetKey) {
	   string errtxt = targetKey->getError();
	   if (errtxt != "")
		QMessageBox::warning(this,"Schlüssel Fehler",
			("Der Schlüssel: " + targetKey->getDescription() +
			"\nist nicht konsistent:\n" + errtxt).c_str());
	}
	cerr << "targetKey = " << (int)targetKey << endl;
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
		"Bitte warten Sie, der Schlüssel wird erstellt",
		"Abbrechen",90, 0, 0, true);
	   progress->setMinimumDuration(0);
	   progress->setProgress(0);	
	   pki_key *nkey = new pki_key (dlg->keyDesc->text().latin1(), 
		       &MainWindow::incProgress,
		       progress,
		       sizeList[sel]);
           progress->cancel();
	   keys->insertPKI(nkey);
	}
}


void MainWindow::deleteKey()
{
	pki_key *delKey = getSelectedKey();
	if (!delKey) return;
	if (QMessageBox::information(this,"Schlüssel löschen",
			("Möchten Sie den Schlüssel: '" + 
			delKey->getDescription() +
			"'\nwirklich löschen ?\n").c_str(),
			"Löschen", "Abbrechen")
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


void MainWindow::loadKey()
{
	pki_key *oldkey;
	QStringList filt;
	filt.append( "PKI Schlüssel ( *.pem *.der *.pk8 )"); 
	filt.append("Alle Dateien ( *.* )");
	string s;
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption("Schlüssel importieren");
	dlg->setFilters(filt);
	if (dlg->exec())
		s = dlg->selectedFile().latin1();
	if (s == "") return;
	string errtxt;
	pki_key *lkey = new pki_key(s, &MainWindow::passRead);
	if ((errtxt = lkey->getError()) != "") {
		QMessageBox::warning(this,"Datei Fehler",
			("Der Schlüssel: " + s +
			"\nkonnte nicht geladen werden:\n" + errtxt).c_str());
		return;
	}
	cerr << "before findkey\n";
	if ((oldkey = (pki_key *)keys->findPKI(lkey))!= 0) {
		if ((oldkey->isPrivKey() && lkey->isPrivKey()) ||
		    lkey->isPubKey()){
	   	    QMessageBox::information(this,"Schlüssel import",
			("Der Schlüssel ist bereits vorhanden als:\n'" +
			oldkey->getDescription() + 
			"'\nund wurde daher nicht importiert").c_str(), "OK");
		    delete(lkey);
		    return;
		}
		else {
	   	    QMessageBox::information(this,"Schlüssel import",
			("Der öffentliche Teil des Schlüssels ist bereits vorhanden als:\n'" +
			oldkey->getDescription() + 
			"'\nund wird durch den neuen, vollständigen Schlüssel ersetzt").c_str(), "OK");
		    cerr << "before deleting pki...\n";
		    keys->deletePKI(oldkey);
		    lkey->setDescription(oldkey->getDescription());
		    delete(oldkey);
		}
	}
	cerr << "after findkey\n";
	if (keys->insertPKI(lkey))
	   QMessageBox::information(this,"Schlüssel import",
		("Der Schlüssel wurde erfolgreich importiert als:\n'" +
		lkey->getDescription() + "'").c_str(), "OK");
	else	
	   QMessageBox::warning(this,"Schlüssel import",
		"Der Schlüssel konnte nicht in der Datenbank \
		gespeichert werden", "OK");
	
	cerr << "after insert\n";
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
		QMessageBox::warning(this,"Datei Fehler",
			("Der Schlüssel: '" + fname +
			"'\nkonnte nicht geschrieben werden:\n" + errtxt).c_str());
		return;
	}
	QMessageBox::information(this,"Schlüssel export",
		("Der Schlüssel wurde erfolgreich in die Datei:\n'" +
		fname + "' exportiert").c_str(), "OK");

}


