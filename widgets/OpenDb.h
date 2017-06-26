/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2017 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __OPENDB_H
#define __OPENDB_H

#include "ui_OpenDb.h"
#include <QSqlDatabase>

class OpenDb: public QDialog, public Ui::OpenDb
{
	Q_OBJECT

    public:
	OpenDb(QWidget *parent, QString db);
	void openDatabase() const;
	bool _openDatabase(QString connName, QString pass) const;
	QString getDescriptor() const;

    public slots:
	int exec();
};

#endif
