#include "ExportKey.h"
#include <iostream.h>


ExportKey::ExportKey(QString fname, bool onlypub, 
	QWidget *parent = 0,const char *name = 0)
	:ExportKey_UI(parent,name,true,0)
{
	filename->setText(fname);
	onlyPub = onlypub;
	if (onlyPub) {
		exportPrivate->setDisabled(true);
		encryptKey->setDisabled(true);
	}		
}
	
void ExportKey::chooseFile()
{
	QStringList filt;
	filt.append( "PKI Schlüssel ( *.pem *.der *.pk8 )"); 
	filt.append("Alle Dateien ( *.* )");
	QString s;
	QFileDialog *dlg = new QFileDialog(this,0,true);
	//dlg->setSelection( filename->text() );
	dlg->setCaption("Schlüssel speichern unter");
	dlg->setFilters(filt);
	if (dlg->exec())
		s = dlg->selectedFile();
	if (! s.isEmpty()) filename->setText(s);
}

void ExportKey::canEncrypt() {
	if (exportFormat->currentText() == "PKCS#8") {
		//exportPrivate->setOn(true);
		exportPrivate->setDisabled(true);
		//encryptKey->setOn(true);
		encryptKey->setDisabled(true);
	}
	else if (exportFormat->currentText() == "PEM" && !onlyPub) {
		exportPrivate->setEnabled(true);
	    	if (exportPrivate->isOn())
			encryptKey->setEnabled(true);
	}
	else {
		encryptKey->setDisabled(true);
		//encryptKey->setOn(false);
	}

	if (onlyPub) {
		//exportPrivate->setOn(false);
		exportPrivate->setDisabled(true);
		//encryptKey->setOn(false);
		encryptKey->setDisabled(true);
	}
}
	
