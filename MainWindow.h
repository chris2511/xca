#include "MainWindow_UI.h"
#include "KeyDetailDlg_UI.h"
#include "PassRead_UI.h"
#include "PassWrite_UI.h"
#include "NewKeyDlg_UI.h"
#include "NewX509Req_UI.h"
#include "ExportKey.h"
#include "RSAkey.h"
#include "KeyDB.h"
#include <iostream.h>
#include <qapplication.h>
#include <qdir.h>
#include <qlineedit.h>
#include <qcombobox.h>
#include <qlistbox.h>
#include <qobjectlist.h>
#include <qobjcoll.h>
#include <qlabel.h>
#include <qfiledialog.h>
#include <qmessagebox.h>
#include <qcheckbox.h>
#include <qprogressdialog.h>

#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#define BASE_DIR "/xca"


class MainWindow: public MainWindow_UI
{
	Q_OBJECT
	KeyDB *keys;
   public:
	QString baseDir;
	static const int sizeList[];
	MainWindow(QWidget *parent, const char *name);
	~MainWindow(); 
	void showDetailsKey(RSAkey *key);
	void loadKey();
	void writeKey();
	static int passRead(char *buf, int size, int rwflag, void *userdata);
	static int passWrite(char *buf, int size, int rwflag, void *userdata);
	static void incProgress(int a, int b, void *progress);
	RSAkey* getSelectedKey();
   public slots:
	virtual void newKey();
	virtual void showDetailsKey();
	virtual void deleteKey();
	virtual void newX509Req();
};
#endif
