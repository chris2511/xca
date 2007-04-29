/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#ifndef DB_TEMP_H
#define DB_TEMP_H

#include "db_base.h"
#include "pki_temp.h"
#include <qobject.h>
#include <qpixmap.h>

class Mainwin;

class db_temp: public db_base
{
	Q_OBJECT
    protected:
	QPixmap *keyicon;
	pki_base *predefs;
    public:
	db_temp(QString DBfile, MainWindow *mw);
	~db_temp();
	pki_base *newPKI();
	bool runTempDlg(pki_temp *temp);
	bool alterTemp(pki_temp *temp);
	void showContextMenu(QContextMenuEvent *e, const QModelIndex &index);

    public slots:
	void newItem();
	void changeTemp();
	void showPki(pki_base *pki);
	void load();
	void store();
	void certFromTemp();
	void reqFromTemp();
	void alterTemp();
	void duplicateTemp();
    signals:
	void newReq(pki_temp *);
	void newCert(pki_temp *);

};
#endif
