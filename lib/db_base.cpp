/* vi: set sw=4 ts=4: */
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
#include "view/XcaListView.h"
#include <qmessagebox.h>
#include <qlistview.h>
#include <qdir.h>


db_base::db_base(DbEnv *dbe, QString DBfile, QString DB, DbTxn *global_tid,
	XcaListView *lvi) 
{
	listview = lvi;
	dbenv = dbe;
	data = new Db(dbe, 0);
	try {
#if DB_VERSION_MAJOR >= 4 && DB_VERSION_MINOR >=1	
		data->open(NULL, DBfile.latin1(), DB.latin1(), DB_BTREE, DB_CREATE, 0600); 
#else
		data->open(DBfile.latin1(), DB.latin1(), DB_BTREE, DB_CREATE, 0600); 
#endif
	}
	catch (DbException &err) {
		throw errorEx(err.what());
	}
}


db_base::~db_base()
{
//	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
//    fprintf(stderr, "close 1:\n" );
//	CRYPTO_mem_leaks_fp(stderr);
	data->close(0);
	container.setAutoDelete(true);
	container.clear();
//    fprintf(stderr, "close 2:\n" );
//	CRYPTO_mem_leaks_fp(stderr);
//	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_OFF);
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
		throw errorEx(err.what());
	}
	return NULL;
}

void *db_base::getData(QString key, int *dsize)
{
	return getData((void *)key.latin1(), key.length()+ 1, dsize);
}


QString db_base::getString(QString key)
{
	QString x = "";
	int dsize;
	char *p = (char *)getData(key, &dsize);
	if (p == NULL) {
		return x;
	}
	if ( p[dsize-1] != '\0' ) {
		return x;
	}
	x = p;
	free(p);
	if ( (int)x.length() != (dsize-1) ) {
		// FIXME: Errorhandling...
	}
	return x;
}


QString db_base::getString(char *key)
{
	QString x = key;
	return getString(x);
}


int db_base::getInt(QString key)
{
	QString x = getString(key);
	return atoi(x.latin1());
}


void db_base::putData(void *key, int keylen, void *dat, int datalen, DbTxn *tid)
{
	
	Dbt k(key, keylen);
	Dbt d(dat, datalen);
	try {
		data->put(tid, &k, &d, 0 );
	}
	catch (DbException &err) {
		throw errorEx(err.what());
	}
}

void db_base::putString(QString key, void *dat, int datalen, DbTxn *tid)
{
	putData((void *)key.latin1(), key.length()+1, dat, datalen, tid);
}

void db_base::putString(QString key, QString dat, DbTxn *tid)
{
	putString(key, (void *)dat.latin1(), dat.length() +1, tid);
}

void db_base::putString(char *key, QString dat, DbTxn *tid)
{
	QString x = key;
	putString(x, dat, tid);
}

void db_base::putInt(QString key, int dat, DbTxn *tid)
{
	char buf[100];
	sprintf(buf,"%i",dat);
	QString x = buf;
	putString(key, x, tid);
}

void db_base::loadContainer()
{
//	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
				
	DbTxn *tid = NULL;
	Dbc *cursor = NULL;
	unsigned char *p;
	try {
		dbenv->txn_begin(NULL, &tid, 0);
		data->cursor(tid, &cursor, 0);
		Dbt *k = new Dbt();
		Dbt *d = new Dbt();
		QString desc;
		pki_base *pki;
		container.clear();
		while (!cursor->get(k, d, DB_NEXT)) {
			desc = (char *)k->get_data();
			p = (unsigned char *)d->get_data();
			int size = d->get_size();
			try {	
    fprintf(stderr, "loadContainer 1:\n" );
//	CRYPTO_mem_leaks_fp(stderr);
				pki = newPKI();
    fprintf(stderr, "loadContainer 2:\n" );
//	CRYPTO_mem_leaks_fp(stderr);
				pki->setIntName(desc);
    fprintf(stderr, "loadContainer 3:\n" );
//	CRYPTO_mem_leaks_fp(stderr);
				pki->fromData(p, size);
    fprintf(stderr, "loadContainer 4:\n" );
//	CRYPTO_mem_leaks_fp(stderr);
				container.append(pki);
			}
			catch (errorEx &err) {
				QMessageBox::warning(NULL,tr(XCA_TITLE),
				       	tr("Error loading: '") + desc + "'\n" +
						err.getCString());
				delete pki;
			}
		}
		delete (k);
		delete (d);
		cursor->close();
    fprintf(stderr, "loadContainer 5:\n" );
//	CRYPTO_mem_leaks_fp(stderr);
		preprocess();
    fprintf(stderr, "loadContainer 6:\n" );
//	CRYPTO_mem_leaks_fp(stderr);
		tid->commit(0);
	}
	catch (DbException &err) {
		tid->abort();
		throw errorEx(err.what());
	}
    fprintf(stderr, "loadContainer 7:\n" );
//	CRYPTO_mem_leaks_fp(stderr);
//	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_OFF);
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
		throw errorEx(err.what());
	}
	if (listview) {
		
		QListViewItem *lvi = new QListViewItem((QListView *)listview, pki->getIntName());
        listview->insertItem(lvi);
        pki->setLvi(lvi);
        pki->updateView();
	}
}
	
void db_base::_writePKI(pki_base *pki, bool overwrite, DbTxn *tid) 
{
	int flags = 0;
	if (!overwrite) flags = DB_NOOVERWRITE;
	QString desc = pki->getIntName();
	if (desc.isEmpty()) {
		desc="unnamed";
	}
	QString orig = desc;
	int size=0;
	char field[10];
	unsigned char *p = pki->toData(&size);
	int cnt=0;
	int x = DB_KEYEXIST;
	
	try {
		while (x == DB_KEYEXIST) {
			Dbt k((void *)desc.latin1(), desc.length() + 1);
			Dbt d((void *)p, size);
			if ((x = data->put(tid, &k, &d, flags ))!=0) {
				sprintf(field,"%02i", ++cnt);
				QString z = field;
		   		desc = orig + "_" + z ;
			}
		}
		pki->setIntName(desc);
		pki->updateView();
	}
	catch (DbException &err) {
		if (p)
			OPENSSL_free(p);
		throw errorEx(err.what(), "_writePKI");
	}
	if (p)
		OPENSSL_free(p);
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
		tid->abort();
		throw errorEx(err.what(), "update PKI");
	}
}

pki_base *db_base::getByName(QString desc)
{
	if (desc == "" ) return NULL;
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
	if (refpki == 0) return NULL;
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
	for ( pki = container.first(); pki != 0; pki = container.next() ){
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

pki_base *db_base::insert(pki_base *item)
{
	insertPKI(item);
	return item;
}

void db_base::writeAll(DbTxn *tid)
{
	bool tidwasnull = false;
	if (tid == NULL) { 
		tidwasnull = true;
		dbenv->txn_begin(NULL, &tid, 0);
	}
	try {
		for (pki_base *pki=container.first(); pki!=0; pki=container.next() ) 
			_writePKI(pki, true, tid);
	}
	catch (DbException &err) {
		tid->abort();
		throw errorEx(err.what());
	}
	if (tidwasnull)
		tid->commit(0);
}

