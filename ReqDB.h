#include <db_cxx.h>
#include "X509Req.h"
#include <qlistbox.h>
#include <stdio.h>

#ifndef REQDB_H
#define REQDB_H


class ReqDB: public QObject
{
    	Q_OBJECT
	Db *data;
	DbEnv *dbenv;
	QListBox *listView;
	unsigned char mem[100];
    public:
	ReqDB(DbEnv *dbe, QString DBfile, QListBox *list, 
	      QObject *parent, const char *name = 0);
	~ReqDB();
	bool updateView();
	bool insertReq(X509Req *req);
	bool deleteReq(X509Req *req);
	bool updateReq(X509Req *req, QString desc);
	X509Req *getSelectedReq(QString desc);
	X509Req *getSelectedReq();
	QStringList getPrivateDesc();
};

#endif
