#include "MainWindow.h"

const int MainWindow::sizeList[] = {256, 512, 1024, 2048, 4096, 0 };


RSAkey *MainWindow::getSelectedKey()
{
	RSAkey *targetKey = keys->getSelectedKey();
	char *errtxt = targetKey->getError();
	if (errtxt)
		QMessageBox::warning(this,"Schlüssel Fehler",
			"Der Schlüssel: " + targetKey->description() +
			"\nist nicht konsistent:\n" + errtxt);
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
	   RSAkey *nkey = new RSAkey (dlg->keyDesc->text(), 
		       sizeList[sel],
		       &MainWindow::incProgress,
		       progress);
           progress->cancel();
	   keys->insertKey(nkey);
	}
}


void MainWindow::deleteKey()
{
	RSAkey *delKey = getSelectedKey();
	if (!delKey) return;
	if (QMessageBox::information(this,"Schlüssel löschen",
			"Möchten Sie den Schlüssel: '" + 
			delKey->description() +
			"' wirklich löschen ?\n",
			"Löschen", "Abbrechen")
	) return;
	keys->deleteKey(delKey);
}


void MainWindow::showDetailsKey(RSAkey *key)
{
	KeyDetail_UI *detDlg = new KeyDetail_UI(this, 0, true, 0 );
	
	detDlg->keyDesc->setText(
		key->description() );
	detDlg->keyLength->setText(
		key->length() );
	detDlg->keyPubEx->setText(
		key->pubEx() );
	detDlg->keyModulus->setText(
		key->modulus() );
	detDlg->keyPrivEx->setText(
		key->privEx() );

	if ( !detDlg->exec()) return;
	QString ndesc = detDlg->keyDesc->text();
	if (ndesc != key->description()) {
		keys->updateKey(key, ndesc);
	}
}


void MainWindow::showDetailsKey()
{
	RSAkey *targetKey = getSelectedKey();
	if (targetKey) showDetailsKey(targetKey);
}


void MainWindow::loadKey()
{
	QString s(QFileDialog::getOpenFileName( QString::null, "PEM Schlüssel (*.pem *.der)", this));
	if (s.isEmpty()) return;
	char *errtxt;
	RSAkey *lkey = new RSAkey(s, &MainWindow::passRead);
	if ((errtxt = lkey->getError()) != NULL) {
		QMessageBox::warning(this,"Datei Fehler",
			"Der Schlüssel: " + s +
			"\nkonnte nicht geladen werden:\n" + errtxt);
		return;
	}
	if (keys->insertKey(lkey))
	   QMessageBox::information(this,"Schlüssel import",
		"Der Schlüssel wurde erfolgreich importiert als: '" +
		lkey->description() + "' ", "OK");
	else	
	   QMessageBox::warning(this,"Schlüssel import",
		"Der Schlüssel konnte nicht in der Datenbank \
		gespeichert werden", "OK");
}


void MainWindow::writeKey()
{
	bool PEM=false;
	EVP_CIPHER *enc = NULL;
	RSAkey *targetKey = getSelectedKey();
	if (!targetKey) return;
	ExportKey *dlg = new ExportKey(targetKey->description() + ".pem",
			targetKey->onlyPubKey, this);
	dlg->exportFormat->insertItem("PEM");
	dlg->exportFormat->insertItem("DER");
	if (!targetKey->onlyPubKey)
		dlg->exportFormat->insertItem("PKCS#8");
	if (!dlg->exec()) return;
	QString fname = dlg->filename->text();
	if (fname.isEmpty()) return;
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
	char *errtxt;
	if ((errtxt = targetKey->getError()) != NULL) {
		QMessageBox::warning(this,"Datei Fehler",
			"Der Schlüssel: " + fname +
			"\nkonnte nicht geschrieben werden:\n" + errtxt);
		return;
	}
	QMessageBox::information(this,"Schlüssel export",
		"Der Schlüssel wurde erfolgreich in die Datei '" +
		fname + "' exportiert", "OK");

}


