/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#ifndef __DB_TEMP_H
#define __DB_TEMP_H

#include "db_base.h"
#include "pki_temp.h"
#include "db_x509super.h"
#include <QObject>
#include <QPixmap>

class db_temp: public db_x509name
{
	Q_OBJECT
    protected:
	QPixmap *keyicon;
	pki_base *predefs;
	dbheaderList getHeaders();

    public:
	db_temp(QString DBfile, MainWindow *mw);
	~db_temp();
	pki_base *newPKI(db_header_t *head = NULL);
	bool runTempDlg(pki_temp *temp);
	bool alterTemp(pki_temp *temp);
	void fillContextMenu(QMenu *menu, const QModelIndex &index);
	pki_base *getByName(QString desc);
	QStringList getDescPredefs();
	void newItem();
	void showPki(pki_base *pki);
	void load();
	void store(QModelIndex index);
};
#endif
