#include "ExportKey_UI.h"
#include <qfiledialog.h>
#include <qcombobox.h>
#include <qcheckbox.h>

#ifndef EXPORTKEY_H
#define EXPORTKEY_H


class ExportKey: public ExportKey_UI
{
	Q_OBJECT
	bool onlyPub;
   public:	
	ExportKey(QString fname, bool onlypub,
		  QWidget *parent = 0, const char *name = 0);
   public slots:
	virtual void chooseFile();
	virtual void canEncrypt();
};
#endif
