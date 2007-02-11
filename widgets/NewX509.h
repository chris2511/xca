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
 *	written by Eric Young (eay@cryptsoft.com)"
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


#ifndef __NEWX509_H
#define __NEWX509_H

#include "ui/NewX509.h"
#include "lib/oid.h"
#include "lib/db.h"
#include <openssl/x509v3.h>
#include <Qt/qlistwidget.h>

class MainWindow;
class extList;
class pki_temp;
class pki_x509req;
class pki_x509;
class pki_key;
class QPixmap;
class QListbox;
class x509name;
class x509v3ext;
class extList;

class NewX509: public QDialog, public Ui::NewX509
{
	Q_OBJECT
   private:
	NIDlist eku_nid;
	NIDlist dn_nid;
	NIDlist aia_nid;
#define EXPLICIT_NAME_CNT 7
	static int name_nid[EXPLICIT_NAME_CNT];
	QLineEdit *name_ptr[EXPLICIT_NAME_CNT];
	X509V3_CTX ext_ctx;
	void editV3ext(QLineEdit *le, QString types, int n);
	enum pki_type pt;
	void templateChanged(QString templatename);
   public:
	QRadioButton *selfQASignRB;
	NewX509(QWidget *parent);
	virtual ~NewX509();
	void initCtx();
	void setRequest(); // reduce to request form
	void setTemp(pki_temp *temp); // reduce to template form
	void setCert(); // reduce to certificate form
	void toTemplate(pki_temp *temp);
	void fromTemplate(pki_temp *temp);
	void defineTemplate(pki_temp *temp);
	void defineRequest(pki_x509req *req);
	void defineSigner(pki_x509 *defcert);
	int lb2int(QListWidget *lb);
	void int2lb(QListWidget *lb, int x);
	void templateChanged(pki_temp *templ);
	pki_key *getSelectedKey();
	pki_x509 *getSelectedSigner();
	pki_x509req *getSelectedReq();
	x509name getX509name();
	void setX509name(const x509name &n);
	void setImage(QPixmap *image);
	void setAuthInfAcc_string(QString aia_txt);
	QString getAuthInfAcc_string();
	x509v3ext getBasicConstraints();
	x509v3ext getSubKeyIdent();
	x509v3ext getAuthKeyIdent();
	x509v3ext getKeyUsage();
	x509v3ext getEkeyUsage();
	x509v3ext getSubAltName();
	x509v3ext getIssAltName();
	x509v3ext getCrlDist();
	x509v3ext getAuthInfAcc();
	x509v3ext getCertPol();
	extList getNetscapeExt();
	extList getAllExt();
	const EVP_MD *getHashAlgo();
	void initCtx(pki_x509 *subj, pki_x509 *iss, pki_x509req *req);
	void setBasicConstraints(const x509v3ext &e);
	void setExt(const x509v3ext &ext);
	QString createRequestText();
	void checkAuthKeyId();
	void switchHashAlgo();
   public slots:
	void on_fromReqCB_clicked();
	void on_keyList_currentIndexChanged(const QString &);
	void on_reqList_currentIndexChanged(const QString &);
	void toggleOkBut();
	void newKeyDone(QString name);
	void on_extDNadd_clicked();
	void on_extDNdel_clicked();
	void on_applyTime_clicked();
	void on_editSubAlt_clicked();
	void on_editIssAlt_clicked();
	void on_editCrlDist_clicked();
	void on_editAuthInfAcc_clicked();
	void on_foreignSignRB_toggled(bool checked);
	void on_selfSignRB_toggled(bool checked);
	void on_subKey_clicked();
	void on_genKeyBUT_clicked();
	void on_showReqBut_clicked();
	void on_description_textChanged(QString text);
	void on_countryName_textChanged(QString);
	void on_certList_currentIndexChanged(int index);
	void on_applyTemplate_clicked();
	void on_okButton_clicked();
   signals:
	void genKey();
	void showReq(QString req);
};

#endif
