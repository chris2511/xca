#include "NewX509_UI.h"
#include <qcombobox.h>
#include <qradiobutton.h>
#include "lib/db_key.h"
#include "lib/db_x509req.h"
#include <qframe.h>

#ifndef NEWX509_H
#define NEWX509_H

class MainWindow;
class NewX509: public NewX509_UI
{
	Q_OBJECT
   private:
	db_x509req *reqs;
	db_key *keys;
	MainWindow *par;
   public:	
	NewX509(QWidget *parent, const char *name, db_key *key, db_x509req *req);
	
   public slots:
	void setDisabled(int state);
   	void newKey();
   signals:
	void genKey();  
};

#endif
