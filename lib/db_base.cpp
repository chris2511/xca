#include "db_base.h"


db_base::db_base(DbEnv *dbe, string DBfile, string DB) 
{
	dbenv = dbe;
	listView = NULL;
	data = new Db(dbe, 0);
	cerr << "DB:" << DBfile <<"\n";//
	int x;
	if (( x = data->open(DBfile.c_str(), DB.c_str(), DB_BTREE, DB_CREATE, 0600))) 
		data->err(x,"DB open");
}


db_base::~db_base()
{
	data->close(0);
}


Dbc *db_base::getCursor()
{
	Dbc *cursor;
	if (int x = data->cursor(NULL, &cursor, 0)) {
		data->err(x,"DB new Cursor");
		return NULL;	
	}
	return cursor;
}

bool db_base::freeCursor(Dbc *cursor)
{
	if (int x = cursor->close()) {
		data->err(x,"DB delete cursor");
		return false;
	}
	return true;
}

void *db_base::getData(void *key, int length, int *dsize)
{
	if ((key == NULL) || (length == 0) ) {
		*dsize = 0;
		return NULL;
	}
	void *p;
	Dbt k(key, length);
	Dbt d(NULL, 0);
	if (int x = data->get(NULL, &k, &d, 0)) {
		data->err(x,"DB Error get");
		*dsize = 0;
		return NULL;
	}
	p = d.get_data();
	*dsize = d.get_size();
	void *q = malloc(*dsize);
	memcpy(q,p,*dsize);

	return q;
}

void *db_base::getData(string key, int *dsize)
{
	return getData((void *)key.c_str(), key.length()+ 1, dsize);
}


string db_base::getString(string key)
{
	string x = "";
	int dsize;
	char *p = (char *)getData(key, &dsize);
	if (p == NULL) {
		cerr << "getString: p was NULL"<< endl;
		return x;
	}
	if ( p[dsize-1] != '\0' ) {
		int a =p[dsize-1];	
		cerr << "getString: stringerror "<< a <<" != 0  (returning empty string) size:" <<dsize<< endl;
		return x;
	}
	x = p;
	free(p);
	if ( (int)x.length() != (dsize-1) ) {
		cerr << "error with '"<<key<<"': "<< x.c_str() <<" "<<dsize<<endl;
	}
	return x;
}


string db_base::getString(char *key)
{
	string x = key;
	return getString(x);
}


int db_base::getInt(string key)
{
	string x = getString(key);
	return atoi(x.c_str());
}


void db_base::putData(void *key, int keylen, void *dat, int datalen)
{
	
	Dbt k(key, keylen);
	Dbt d(dat, datalen);
	if (int x = data->put(NULL, &k, &d, 0 )) {
		data->err(x,"DB Error put");
	}
}

void db_base::putString(string key, void *dat, int datalen)
{
	cerr << key << endl;
	putData((void *)key.c_str(), key.length()+1, dat, datalen);
}

void db_base::putString(string key, string dat)
{
	cerr << key<<endl;
	putString(key, (void *)dat.c_str(), dat.length() +1);
}

void db_base::putString(char *key, string dat)
{
	string x = key;
	cerr << key<<endl;
	putString(x,dat);
}

void db_base::putInt(string key, int dat)
{
	char buf[100];
	sprintf(buf,"%i",dat);
	string x = buf;
	putString(key, x);
}

void db_base::loadContainer()
{
	unsigned char *p;
	Dbc *cursor = getCursor();
	Dbt *k = new Dbt();
	Dbt *d = new Dbt();
	string desc;
	pki_base *pki;
	container.clear();
	while (!cursor->get(k, d, DB_NEXT)) {
		desc = (char *)k->get_data();
		p = (unsigned char *)d->get_data();
		int size = d->get_size();
		pki = newPKI();
		if (pki == NULL) continue;
		cerr << desc.c_str() << endl;
		if (pki->fromData(p, size)) {
			pki->setDescription(desc);
			container.append(pki);
		}
		else delete(pki);
	}
	delete (k);
	delete (d);
	freeCursor(cursor);
}	


bool db_base::updateView()
{
	if (listView == NULL) return false;
	listView->clear();
	pki_base *pki;
	if (container.isEmpty()) return false;
        QListIterator<pki_base> it(container);
        for ( ; it.current(); ++it ) {
                pki = it.current();
		QListViewItem * lvi = new QListViewItem(listView, pki->getDescription().c_str());
		lvi->setPixmap(0, *icon);
		listView->insertItem(lvi);
	}
	return true;
}


bool db_base::insertPKI(pki_base *pki) 
{
	string desc = pki->getDescription();
	string orig = desc;
	int size=0;
	char field[10];
	unsigned char *p;
	p = pki->toData(&size);
	int cnt=0;
	int x = DB_KEYEXIST;
	while (x == DB_KEYEXIST) {
	   Dbt k((void *)desc.c_str(), desc.length() + 1);
	   Dbt d((void *)p, size);
           cerr << "Size: " << d.get_size() << "\n";
	
	   if ((x = data->put(NULL, &k, &d, DB_NOOVERWRITE ))!=0) {
		data->err(x,"DB Error put");
		sprintf(field,"%02i", ++cnt);
		string z = field;
	   	desc = orig + "_" + z ;
	   }
	}
	if (x != DB_KEYEXIST && x != 0) {
	   data->err(x,"DB Error put");
	   //return false;
	}
	OPENSSL_free(p);
	pki->setDescription(desc);
	container.append(pki);
	updateView();
	return true;
}


bool db_base::deletePKI(pki_base *pki) 
{
	string desc = pki->getDescription();
	Dbt k((void *)desc.c_str(), desc.length() + 1);
	int x = data->del(NULL, &k, 0);
	if (x){
	   data->err(x,"DB Error del");
	   return false;
	}
	remFromCont(pki);
	updateView();
	return true;
}

void db_base::remFromCont(pki_base *pki)
{
	container.remove(pki);
}

bool db_base::updatePKI(pki_base *pki, string desc) 
{
	if (deletePKI(pki)){
	   pki->setDescription(desc);
	   return insertPKI(pki);
	}
	updateView();
	return true;
}


pki_base *db_base::getSelectedPKI(string desc)
{
	if (desc == "" ) return NULL;
	pki_base *pki;
        QListIterator<pki_base> it(container);
        for ( ; it.current(); ++it ) {
                pki = it.current();
		if (pki->getDescription() == desc) return pki;
	}
}

pki_base *db_base::getSelectedPKI()
{
	const char *tp;
	string desc = "";
	QListViewItem *lvi;
	if ((lvi = listView->selectedItem()) == NULL) return NULL;
	if ((tp = lvi->text(0).latin1())) desc = tp;
	cerr << "desc = '"<<desc <<"'\n";
	return getSelectedPKI(desc);
}
	

pki_base *db_base::findPKI(pki_base *refpki)
{
	pki_base *pki;
        QListIterator<pki_base> it(container);
        for ( ; it.current(); ++it ) {
                pki = it.current();
		if (refpki->compare(pki)) return pki;
	}
	return NULL;
}

QPixmap *db_base::loadImg(const char *name )
{
        QString path = PREFIX;
	path += "/";
        return new QPixmap(path + name);
}


