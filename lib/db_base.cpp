#include "db_base.h"


db_base::db_base(DbEnv *dbe, string DBfile, string DB, QListView *l) 
{
	listView = l;
	dbenv = dbe;
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

void db_base::loadContainer()
{
	unsigned char *p;
	Dbc *cursor;
	if (int x = data->cursor(NULL, &cursor, 0))
		data->err(x,"DB new Cursor");
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
}	


bool db_base::updateView()
{
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
		sprintf(field,"%i", ++cnt);
		string z = field;
	   	desc = orig + "_" + z ;
	   }
	}
	if (x != DB_KEYEXIST && x != 0) {
	   data->err(x,"DB Error put TINE");
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
