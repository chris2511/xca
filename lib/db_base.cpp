/*
 * Copyright (C) 2001 Christian Hohnstaedt.
 *
 *  All rights reserved.
 *
 *
 *  Redistribution and use in source and binary forms, with or without 
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  - Neither the name of the author nor the names of its contributors may be 
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * This program links to software with different licenses from:
 *
 *	http://www.openssl.org which includes cryptographic software
 * 	written by Eric Young (eay@cryptsoft.com)"
 *
 *	http://www.sleepycat.com
 *
 *	http://www.trolltech.com
 * 
 *
 *
 * http://www.hohnstaedt.de/xca
 * email: christian@hohnstaedt.de
 *
 * $Id$
 *
 */                           


#include "db_base.h"


db_base::db_base(DbEnv *dbe, string DBfile, string DB) 
{
	dbenv = dbe;
	listView = NULL;
	data = new Db(dbe, 0);
	CERR("DB:" << DBfile);
	int x;
#if DB_VERSION_MAJOR >= 4 && DB_VERSION_MINOR >=1	
	if (( x = data->open(NULL, DBfile.c_str(), DB.c_str(), DB_BTREE, DB_CREATE, 0600))) 
#else
	if (( x = data->open(DBfile.c_str(), DB.c_str(), DB_BTREE, DB_CREATE, 0600))) 
#endif
		data->err(x,"DB open");
}


db_base::~db_base()
{
	data->close(0);
}


Dbc *db_base::getCursor(DbTxn *tid)
{
	Dbc *cursor;
	if (int x = data->cursor(tid, &cursor, 0)) {
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
		CERR("getString: p was NULL");
		return x;
	}
	if ( p[dsize-1] != '\0' ) {
		int a =p[dsize-1];	
		CERR( "getString: stringerror "<< a <<" != 0  (returning empty string) size:" <<dsize);
		return x;
	}
	x = p;
	free(p);
	if ( (int)x.length() != (dsize-1) ) {
		CERR( "error with '"<<key<<"': "<< x.c_str() <<" "<<dsize);
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
	CERR( key );
	putData((void *)key.c_str(), key.length()+1, dat, datalen);
}

void db_base::putString(string key, string dat)
{
	CERR( key);
	putString(key, (void *)dat.c_str(), dat.length() +1);
}

void db_base::putString(char *key, string dat)
{
	string x = key;
	CERR(key);
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
	DbTxn *tid = NULL;
	dbenv->txn_begin(NULL, &tid, 0);
	unsigned char *p;
	Dbc *cursor = getCursor(tid);
	Dbt *k = new Dbt();
	Dbt *d = new Dbt();
	string desc;
	pki_base *pki;
	container.clear();
	CERR("Load Container");
	while (!cursor->get(k, d, DB_NEXT)) {
		desc = (char *)k->get_data();
		p = (unsigned char *)d->get_data();
		int size = d->get_size();
		try {	
			pki = newPKI();
			CERR("PKItest");
			CERR(desc.c_str());
			pki->fromData(p, size);
			pki->setDescription(desc);
			container.append(pki);
		}
		catch (errorEx &err) {
			QMessageBox::warning(NULL,tr(XCA_TITLE), tr("Error loading: '") + desc.c_str() + "'\n" +
			err.getCString());
		}
	}
	delete (k);
	delete (d);
	freeCursor(cursor);
	preprocess();
	tid->commit(0);
	
}	


bool db_base::updateView()
{
	if (listView == NULL) return false;
	listView->clear();
	pki_base *pki;
	if (container.isEmpty()) return false;
	for ( pki = container.first(); pki != NULL; pki = container.next() ) pki->delPointer();
        QListIterator<pki_base> it(container);
        for ( ; it.current(); ++it ) {
                pki = it.current();
		QListViewItem *lvi = new QListViewItem(listView, pki->getDescription().c_str());
		listView->insertItem(lvi);
		pki->setPointer(lvi);
		updateViewPKI(pki);
	}
	return true;
}

bool db_base::insertPKI(pki_base *pki)
{
	DbTxn *tid = NULL;
	dbenv->txn_begin(NULL, &tid, 0);
	bool s = _writePKI(pki, false, tid);
	if (s) {
		inToCont(pki);
		updateView();
		tid->commit(0);
	}
	else {
		tid->abort();
	}
	return s;
}
	
bool db_base::_writePKI(pki_base *pki, bool overwrite, DbTxn *tid) 
{
	int flags = 0;
	if (!overwrite) flags = DB_NOOVERWRITE;
	string desc = pki->getDescription();
	if (desc == "") {
		desc="unnamed";
	}
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
           CERR("Size: " << d.get_size());
	   if ((x = data->put(tid, &k, &d, flags ))!=0) {
		data->err(x,"DB Error put");
		sprintf(field,"%02i", ++cnt);
		string z = field;
	   	desc = orig + "_" + z ;
	   }
	}
	if (x != DB_KEYEXIST && x != 0) {
	   data->err(x,"DB Error put");
	   OPENSSL_free(p);
	   return false;
	}
	OPENSSL_free(p);
	pki->setDescription(desc);
	return true;
}


bool db_base::_removePKI(pki_base *pki, DbTxn *tid) 
{
	string desc = pki->getDescription();
	return removeItem(desc, tid);
}	

bool db_base::removeItem(string key, DbTxn *tid) 
{
	Dbt k((void *)key.c_str(), key.length() + 1);
	int x = data->del(tid, &k, 0);
	if (x){
	   data->err(x,"DB Error delete");
	   return false;
	}
	return true;
}


bool db_base::deletePKI(pki_base *pki)
{
	DbTxn *tid = NULL;
	dbenv->txn_begin(NULL, &tid, 0);
	bool s = _removePKI(pki, tid);
	if (s) {
		remFromCont(pki);
		updateView();
		tid->commit(0);
		delete(pki);
	}
	else {
		tid->abort();
	}
	return s;
}

bool db_base::renamePKI(pki_base *pki, string desc)
{
	string oldname = pki->getDescription();
	DbTxn *tid = NULL;
	dbenv->txn_begin(NULL, &tid, 0);
	if (! _removePKI(pki, tid)) {
		tid->abort();
		return false;
	}
	pki->setDescription(desc);
	if (! _writePKI(pki, false, tid)) {
		tid->abort();
		return false;
	}
	// rename the pki in the listView .....	
	QListViewItem * item = (QListViewItem *)pki->getPointer();
	if (!item) {
		tid->abort();
		return false;
	}
	item->setText(0, pki->getDescription().c_str());
	tid->commit(0);
	updateViewPKI(pki);
	return true;
}

void db_base::remFromCont(pki_base *pki)
{
	container.remove(pki);
}


void db_base::inToCont(pki_base *pki)
{
	container.append(pki);
}


bool db_base::updatePKI(pki_base *pki) 
{
	DbTxn *tid = NULL;
	dbenv->txn_begin(NULL, &tid, 0);
	bool s = _writePKI(pki, true, tid);
	if (s) {
		updateViewPKI(pki);
		tid->commit(0);
	}
	else {
		tid->abort();
	}
	return s;
}


pki_base *db_base::getSelectedPKI(string desc)
{
	if (desc == "" ) return NULL;
	CERR("desc = '"<<desc);
	pki_base *pki;
        QListIterator<pki_base> it(container);
        for ( ; it.current(); ++it ) {
                pki = it.current();
		if (pki->getDescription() == desc) return pki;
	}
	return NULL;
}


pki_base *db_base::getSelectedPKI(void *item)
{
	if (item  == NULL) return NULL;
	pki_base *pki;
        QListIterator<pki_base> it(container);
        for ( ; it.current(); ++it ) {
                pki = it.current();
		if (pki->getPointer() == item) return pki;
	}
	return NULL;
}


pki_base *db_base::getSelectedPKI()
{
	const char *tp;
	string desc = "";
	QListViewItem *lvi;
	if ((lvi = listView->selectedItem()) == NULL) return NULL;
	if ((tp = lvi->text(0).latin1())) desc = tp;
	CERR("desc = '"<<desc);
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
		QString path ="";
#ifdef WIN32
		path = "."; 
#else
		path = PREFIX ;
#endif
		path += QDir::separator();
        return new QPixmap(path + name);
}

void db_base::updateViewPKI(pki_base *pki)
{
        if (! pki) return;
        QListViewItem *current = (QListViewItem *)pki->getPointer();
        if (!current) return;
#ifdef qt3
	current->setRenameEnabled(0,true);
#endif
        current->setText(0, pki->getDescription().c_str());
}
							
QStringList db_base::getDesc()
{
	pki_base *pki;
	QStringList x;
	x.clear();
	for ( pki = container.first(); pki != 0; pki = container.next() )	{
		x.append(pki->getDescription().c_str());	
	}
	return x;
}

void db_base::setSelected(pki_base *item) 
{
	if (!item) return;
	QListViewItem * lvitem = (QListViewItem *)item->getPointer();
	if (lvitem) {
		listView->setSelected(lvitem, true);
	}
}

