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
#include "exception.h"
#include <qmessagebox.h>
#include <qdir.h>

db_base::db_base(DbEnv *dbe, string DBfile, string DB, DbTxn *global_tid) 
{
	dbenv = dbe;
	data = new Db(dbe, 0);
	CERR("DB:" << DBfile);
	try {
#if DB_VERSION_MAJOR >= 4 && DB_VERSION_MINOR >=1	
		data->open(NULL, DBfile.c_str(), DB.c_str(), DB_BTREE, DB_CREATE, 0600); 
#else
		data->open(DBfile.c_str(), DB.c_str(), DB_BTREE, DB_CREATE, 0600); 
#endif
	}
	catch (DbException &err) {
		DBEX(err);
		throw errorEx(err.what());
	}
}


db_base::~db_base()
{
	data->close(0);
	container.setAutoDelete(true);
	container.clear();
	CERR("Deleting db");
}

void *db_base::getData(void *key, int length, int *dsize)
{
	*dsize = 0;
	if ((key == NULL) || (length == 0) ) {
		return NULL;
	}
	try {
		void *p;
		Dbt k(key, length);
		Dbt d(NULL, 0);
		if (data->get(NULL, &k, &d, 0)) return NULL;
		p = d.get_data();
		*dsize = d.get_size();
		void *q = malloc(*dsize);
		memcpy(q,p,*dsize);
		return q;
	}
	catch (DbException &err) {
		DBEX(err);
		throw errorEx(err.what());
	}
	return NULL;
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
	try {
		data->put(NULL, &k, &d, 0 );
	}
	catch (DbException &err) {
		DBEX(err);
		throw errorEx(err.what());
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
	Dbc *cursor = NULL;
	unsigned char *p;
	try {
		dbenv->txn_begin(NULL, &tid, 0);
		data->cursor(tid, &cursor, 0);
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
		cursor->close();
		preprocess();
		tid->commit(0);
	}
	catch (DbException &err) {
		tid->abort();
		DBEX(err);
		throw errorEx(err.what());
	}
}	

void db_base::insertPKI(pki_base *pki)
{
	DbTxn *tid = NULL;
	dbenv->txn_begin(NULL, &tid, 0);
	try {
		_writePKI(pki, false, tid);
		inToCont(pki);
		tid->commit(0);
	}
	catch (DbException &err) {
		tid->abort();
		DBEX(err);
	}
}
	
void db_base::_writePKI(pki_base *pki, bool overwrite, DbTxn *tid) 
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
	unsigned char *p = pki->toData(&size);
	int cnt=0;
	int x = DB_KEYEXIST;
	// exception occuring here will be catched by the caller
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
	pki->setDescription(desc);
}


void db_base::_removePKI(pki_base *pki, DbTxn *tid) 
{
	QString desc = pki->getIntName();
	removeItem(desc, tid);
}	

void db_base::removeItem(QString key, DbTxn *tid) 
{
	Dbt k((void *)key.latin1(), key.length() + 1);
	data->del(tid, &k, 0);
}


void db_base::deletePKI(pki_base *pki)
{
	DbTxn *tid = NULL;
	try {
		dbenv->txn_begin(NULL, &tid, 0);
		_removePKI(pki, tid);
		remFromCont(pki);
		tid->commit(0);
		delete(pki);
	}
	catch (DbException &err) {
		DBEX(err);
		tid->abort();
		throw errorEx(err.what());
	}
}

void db_base::renamePKI(pki_base *pki, QString desc)
{
	QString oldname = pki->getIntName();
	DbTxn *tid = NULL;
	try {
		dbenv->txn_begin(NULL, &tid, 0);
		_removePKI(pki, tid);
		pki->setIntName(desc);
		_writePKI(pki, false, tid);
		tid->commit(0);
	}
	catch (DbException &err) {
		DBEX(err);
		tid->abort();
		throw errorEx(err.what(), "rename PKI");
	}
}

void db_base::remFromCont(pki_base *pki)
{
	container.remove(pki);
}


void db_base::inToCont(pki_base *pki)
{
	container.append(pki);
}

void db_base::updatePKI(pki_base *pki) 
{
	DbTxn *tid = NULL;
	dbenv->txn_begin(NULL, &tid, 0);
	try {
		_writePKI(pki, true, tid);
		tid->commit(0);
	}
	catch (DbException &err) {
		DBEX(err);
		tid->abort();
		throw errorEx(err.what(), "update PKI");
	}
}

pki_base *db_base::getByName(QString desc)
{
	if (desc == "" ) return NULL;
	CERR( __FUNCTION__ << "desc = '" << desc << "'");
	pki_base *pki;
        QListIterator<pki_base> it(container);
        for ( ; it.current(); ++it ) {
                pki = it.current();
		if (pki->getIntName() == desc) return pki;
	}
	return NULL;
}

pki_base *db_base::getByReference(pki_base *refpki)
{
	pki_base *pki;
        QListIterator<pki_base> it(container);
        for ( ; it.current(); ++it ) {
                pki = it.current();
		if (refpki->compare(pki)) return pki;
	}
	return NULL;
}

pki_base *db_base::getByPtr(void *item)
{
	pki_base *pki;
	if (item == NULL) return NULL;
        QListIterator<pki_base> it(container);
        for ( ; it.current(); ++it ) {
                pki = it.current();
		if (item == pki->getLvi()) return pki;
	}
	return NULL;
}


QStringList db_base::getDesc()
{
	pki_base *pki;
	QStringList x;
	x.clear();
	for ( pki = container.first(); pki != 0; pki = container.next() )	{
		x.append(pki->getIntName());	
	}
	return x;
}



QList<pki_base> db_base::getContainer()
{
	QList<pki_base> c;
	c.clear();
	c = container;
	return c;
}	

