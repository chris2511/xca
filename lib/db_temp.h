/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#ifndef __DB_TEMP_H
#define __DB_TEMP_H

#include "db_x509super.h"

class pki_temp;

class db_temp: public db_x509name
{
	Q_OBJECT
    protected:
	QList<pki_temp*> predefs;

    public:
	db_temp();
	~db_temp();
	pki_base *newPKI(enum pki_type type = none);
	void fillContextMenu(QMenu *menu, const QModelIndex &index);
	QList<pki_temp*> getPredefs() const;
	void load();
	void store(QModelIndex index);
	bool alterTemp(pki_temp *temp);
};
#endif
