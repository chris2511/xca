/* uvi: set sw=4 ts=4: */
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

#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "NewX509.h"
#include "MainWindow_UI.h"
#include "lib/db_key.h"
#include "lib/db_x509req.h"
#include "lib/db_x509.h"
#include "lib/db_temp.h"
#include "lib/db_crl.h"
#include "lib/exception.h"
#include <qpixmap.h>
#include <qfiledialog.h>
#include <string>

#define DBFILE "xca.db"


class MainWindow: public MainWindow_UI
{
	Q_OBJECT

  protected:
	void init_images();
	void read_cmdline();
	DbTxn *global_tid;
	DbEnv *dbenv;
			    
   friend class pki_key;

   public:
	static db_x509 *certs;
	static db_x509req *reqs;
	static db_key *keys;
	static db_temp *temps;
	static db_crl *crls;
	static db_base *settings;
	static QPixmap *keyImg, *csrImg, *certImg, *tempImg, *nsImg, *revImg, *appIco;
	int exitApp;
	QString baseDir, dbfile;
	
	MainWindow(QWidget *parent, const char *name);
	~MainWindow(); 
	void loadSettings();
	void saveSettings();
	void initPass();
	static int passRead(char *buf, int size, int rwflag, void *userdata);
	static int passWrite(char *buf, int size, int rwflag, void *userdata);
	static void incProgress(int a, int b, void *progress);
	static void dberr(const char *errpfx, char *msg);
	static NewX509 *newX509(QPixmap *image);
	static pki_key *getKeyByName(QString name);
	string md5passwd();
	bool opensslError(pki_base *pki);
	QPixmap *loadImg(const char *name);
	void Error(errorEx &err);
	
	static QString getPath();
	static void setPath(QString path);
	bool mkDir(QString dir);
   slots: 
	void init_database();
	
};
#endif
