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
	QString s(QFileDialog::getSaveFileName( filename->text(), "PEM Schlüssel (*.pem *.der)", this));
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
	
