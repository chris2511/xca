#include "ReqDB.h"


ReqDB::ReqDB(DbEnv *dbe, QString DBfile, QListBox *list, 
	QObject *parent , const char *name = 0)
	:QObject( parent, name)
{
	dbenv = dbe;
	listView = list;
	data = new Db(dbe, 0);
	int x;
	if ( x = data->open(DBfile,"reqdb",DB_BTREE, DB_CREATE,0600)) 
		data->err(x,"DB open");
	updateView();
}


ReqDB::~ReqDB()
{
	data->close(0);
}



bool ReqDB::updateView()
{
	listView->clear();
	Dbc *cursor;
	if (int x = data->cursor(NULL, &cursor, 0))
		data->err(x,"DB new Cursor");
	Dbt *key = new Dbt();
	Dbt *data = new Dbt();
	QString desc;
	while (!cursor->get(key, data, DB_NEXT)) {
		desc = (char *)key->get_data();
		listView->insertItem(desc);
	}
}


bool ReqDB::insertReq(X509Req *req) 
{
	QString desc = req->description();
	QString orig = desc;
	int size=0;
	unsigned char *p;
	p = req->getReq(&size);
	int cnt=0;
	int x = DB_KEYEXIST;
	while (x == DB_KEYEXIST) {
	   Dbt k((void *)desc.latin1(), desc.length()+1);
	   Dbt d((void *)p, size);
           cerr << "Size: " << d.get_size() << "\n";
	
	   if (x = data->put(NULL, &k, &d, DB_NOOVERWRITE)) {
		data->err(x,"DB Error put");
	   	desc = orig + "_" + QString::number(++cnt);
	   }
	}
	if (x != DB_KEYEXIST && x != 0) {
	   data->err(x,"DB Error put TINE");
	   //return false;
	}
	OPENSSL_free(p);
	updateView();
	req->setDescription(desc);
	return true;
}


bool ReqDB::deleteReq(X509Req *req) 
{
	QString desc = req->description();
	Dbt k((void *)desc.latin1(), desc.length()+1);
	int x = data->del(NULL, &k, 0);
	updateView();
	if (x){
	   data->err(x,"DB Error del");
	   return false;
	}
	return true;
}

bool ReqDB::updateReq(X509Req *req, QString desc) 
{
	if (deleteReq(req)){
	   req->setDescription(desc);
	   return insertReq(req);
	}
	return true;
}


X509Req *ReqDB::getSelectedReq(QString desc)
{
	if (desc.isEmpty()) return NULL;
	unsigned char *p;
	X509Req *req = NULL;
	Dbt k((void *)desc.latin1(), desc.length()+1);
	Dbt d((void *)p, 0);
	int x = data->get(NULL, &k, &d, 0);
	p = (unsigned char *)d.get_data();
	int size = d.get_size();
	if (x) data->err(x,"DB Error get");
	else req = new X509Req(p, size);
	req->setDescription(desc);
	return req;
}

X509Req *ReqDB::getSelectedReq()
{
	QString desc = listView->currentText();
	return getSelectedReq(desc);
}
	
