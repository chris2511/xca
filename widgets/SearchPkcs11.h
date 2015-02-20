/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2011 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __SEARCHPKCS11DIALOG_H
#define __SEARCHPKCS11DIALOG_H

#include <QThread>
#include "ui_SearchPkcs11.h"

class SearchPkcs11;
class searchThread: public QThread
{
	Q_OBJECT

   protected:
	QString dirname;
	QStringList ext;
	bool recursive;
	bool keepOnRunning;

	bool checkLib(QString file);

   public:
	searchThread(QString _dir, QStringList _ext, bool _recursive);
	void search(QString mydir);
	void run()
	{
		search(dirname);
	}

   public slots:
	void cancelSearch();

   signals:
	void updateCurrFile(QString f);
	void updateLibs(QString f);
};

class SearchPkcs11: public QDialog, public Ui::SearchPkcs11
{
	Q_OBJECT

   protected:
	void searchDir(QString dirname, bool subdirs);
	searchThread *searching;

   public:
	SearchPkcs11(QWidget *parent, QString fname);
	~SearchPkcs11();

   public slots:
	void on_search_clicked();
	void on_fileBut_clicked();
	void buttonPress(QAbstractButton *but);
	void loadItem(QListWidgetItem *lib);
	void updateLibs(QString f);
	void updateCurrFile(QString f);
	void finishSearch();

   signals:
	void addLib(QString);
};

#endif
