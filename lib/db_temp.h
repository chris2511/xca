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
	QList<pki_temp*> predefs;

    public:
	db_temp(MainWindow *mw);
	~db_temp();
	pki_base *newPKI(enum pki_type type = none);
	bool runTempDlg(pki_temp *temp);
	bool alterTemp(pki_temp *temp);
	void fillContextMenu(QMenu *menu, const QModelIndex &index);
	QList<pki_temp*> getAllAndPredefs();
	void newItem();
	void showPki(pki_base *pki);
	void load();
	void store(QModelIndex index);
};
#endif
