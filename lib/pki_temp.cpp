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


#include "pki_temp.h"
#include "func.h"
#include "db.h"
#include <Qt/qdir.h>

QPixmap *pki_temp::icon=  NULL;

pki_temp::pki_temp(const pki_temp *pk)
	:pki_base(pk->desc)
{
	class_name = pk->class_name;
	dataVersion=pk->dataVersion;
	pkiType=pk->pkiType;
	cols=pk->cols;

	type=pk->type;
	xname=pk->xname;
	subAltName=pk->subAltName;
	issAltName=pk->issAltName;
	crlDist=pk->crlDist;
	authInfAcc=pk->authInfAcc;
	certPol=pk->certPol;
	nsCertType=pk->nsCertType;
	nsComment=pk->nsComment;
	nsBaseUrl=pk->nsBaseUrl;
	nsRevocationUrl=pk->nsRevocationUrl;
	nsCARevocationUrl=pk->nsCARevocationUrl;
	nsRenewalUrl=pk->nsRenewalUrl;
	nsCaPolicyUrl=pk->nsCaPolicyUrl;
	nsSslServerName=pk->nsSslServerName;
	ca=pk->ca;
	bcCrit=pk->bcCrit;
	keyUseCrit=pk->keyUseCrit;
	eKeyUseCrit=pk->eKeyUseCrit;
	subKey=pk->subKey;
	authKey=pk->authKey;
	subAltCp=pk->subAltCp;
	issAltCp=pk->issAltCp;
	pathLen=pk->pathLen;
	validN=pk->validN;
	validM=pk->validM;
	validMidn=pk->validMidn;
	keyUse=pk->keyUse;
	eKeyUse=pk->eKeyUse;
}

pki_temp::pki_temp(const QString d, int atype)
	:pki_base(d)
{
	class_name = "pki_temp";
	dataVersion=1;
	pkiType=tmpl;
	cols=2;

	type=atype;
	subAltName="";
	issAltName="";
	crlDist="";
	authInfAcc="";
	certPol="";
	nsCertType=0;
	nsComment="xca certificate";
	nsBaseUrl="";
	nsRevocationUrl="";
	nsCARevocationUrl="";
	nsRenewalUrl="";
	nsCaPolicyUrl="";
	nsSslServerName="";
	ca=0;
	bcCrit=false;
	keyUseCrit=false;
	eKeyUseCrit=false;
	subKey=false;
	authKey=false;
	subAltCp=false;
	issAltCp=false;
	validMidn=false;
	pathLen=0;
	validN=365;
	validM=0;
	keyUse=0;
	eKeyUse=0;
	if (type == CA) {
		ca=1;
		bcCrit=true;
		subKey=true;
		authKey=true;
		issAltCp=false;
		nsCertType=112;
		keyUse=96;
		validN=10;
		validM=2;
	}
	if (type == CLIENT) {
		ca=2;
		bcCrit=true;
		subKey=true;
		authKey=true;
		issAltCp=true;
		subAltCp=true;
		nsCertType=5;
		keyUse=13;
	}
	if (type == SERVER) {
		ca=2;
		bcCrit=true;
		subKey=true;
		authKey=true;
		issAltCp=true;
		subAltCp=true;
		nsCertType=2;
		keyUse=7;
	}

}


void pki_temp::fromData(const unsigned char *p, db_header_t *head )
{
	int version, size;

	size = head->len - sizeof(db_header_t);
	version = head->version;
	fromData(p, size, version);
}

void pki_temp::fromData(const unsigned char *p, int size, int version)
{
	const unsigned char *p1 = p;

	type=db::intFromData(&p1);
	bcCrit=db::boolFromData(&p1);
	keyUseCrit=db::boolFromData(&p1);
	eKeyUseCrit=db::boolFromData(&p1);
	subKey=db::boolFromData(&p1);
	authKey=db::boolFromData(&p1);
	subAltCp=db::boolFromData(&p1);
	issAltCp=db::boolFromData(&p1);
	ca =db:: intFromData(&p1);
	pathLen=db::intFromData(&p1);
	validN =db::intFromData(&p1);
	validM =db::intFromData(&p1);
	keyUse=db::intFromData(&p1);
	eKeyUse=db::intFromData(&p1);
	nsCertType=db::intFromData(&p1);
	subAltName=db::stringFromData(&p1);
	issAltName=db::stringFromData(&p1);
	crlDist=db::stringFromData(&p1);
	nsComment=db::stringFromData(&p1);
	nsBaseUrl=db::stringFromData(&p1);
	nsRevocationUrl=db::stringFromData(&p1);
	nsCARevocationUrl=db::stringFromData(&p1);
	nsRenewalUrl=db::stringFromData(&p1);
	nsCaPolicyUrl=db::stringFromData(&p1);
	nsSslServerName=db::stringFromData(&p1);
	p1 = xname.d2i(p1, size - (p1-p));
	authInfAcc=db::stringFromData(&p1);
	certPol=db::stringFromData(&p1);
	validMidn=db::boolFromData(&p1);

	if (p1-p != size) {
		openssl_error("Wrong Size");
	}
}


unsigned char *pki_temp::toData(int *size)
{
	unsigned char *p, *p1;
	*size = dataSize();
	p = (unsigned char*)OPENSSL_malloc(*size);
	p1 = p;

	db::intToData(&p1, type);
	db::boolToData(&p1, bcCrit);
	db::boolToData(&p1, keyUseCrit);
	db::boolToData(&p1, eKeyUseCrit);
	db::boolToData(&p1, subKey);
	db::boolToData(&p1, authKey);
	db::boolToData(&p1, subAltCp);
	db::boolToData(&p1, issAltCp);
	db::intToData(&p1, ca);
	db::intToData(&p1, pathLen);
	db::intToData(&p1, validN);
	db::intToData(&p1, validM);
	db::intToData(&p1, keyUse);
	db::intToData(&p1, eKeyUse);
	db::intToData(&p1, nsCertType);
	db::stringToData(&p1, subAltName);
	db::stringToData(&p1, issAltName);
	db::stringToData(&p1, crlDist);
	db::stringToData(&p1, nsComment);
	db::stringToData(&p1, nsBaseUrl);
	db::stringToData(&p1, nsRevocationUrl);
	db::stringToData(&p1, nsCARevocationUrl);
	db::stringToData(&p1, nsRenewalUrl);
	db::stringToData(&p1, nsCaPolicyUrl);
	db::stringToData(&p1, nsSslServerName);
	p1 = xname.i2d(p1);
	db::stringToData(&p1, authInfAcc);
	db::stringToData(&p1, certPol);
	db::boolToData(&p1, validMidn);

	*size = p1-p;
	return p;
}

void pki_temp::writeDefault(const QString fname)
{
	writeTemp(fname + QDir::separator() + getIntName() + ".xca");
}

void pki_temp::writeTemp(QString fname)
{
	int size = 0;
	unsigned char *p, buf[2*sizeof(int)], *p1=buf;
	FILE *fp = fopen(CCHAR(fname),"w");

	if (fp == NULL) {
		fopen_error(fname);
		return;
	}
	p = toData(&size);
	db::intToData(&p1, size);
	db::intToData(&p1, version);
	fwrite(buf, 2*sizeof(int), 1, fp);
	fwrite(p, 1, size, fp);
	OPENSSL_free(p);
	fclose(fp);
}

void pki_temp::loadTemp(QString fname)
{
	int size, s;
	unsigned char *p, buf[2*sizeof(int)];
	const unsigned char *p1 = buf;
	FILE *fp = fopen(CCHAR(fname),"r");
	if (fp == NULL) {
		fopen_error(fname);
		return;
	}
	if (fread(buf, 2*sizeof(int), 1, fp) != 1)
		openssl_error(tr("Template file content error"));
	size = db::intFromData(&p1);
	version = db::intFromData(&p1);
	printf("Size=%d, Version=%d\n", size, version);

	if (size > 65535 || size <0)
		openssl_error(tr("Template file content error"));

	p = (unsigned char *)OPENSSL_malloc(size);
	if ((s=fread(p, 1, size, fp)) != size) {
		OPENSSL_free(p);
		openssl_error(tr("Template file content error"));
	}
	printf("read Size=%d , size=%d\n",s , size);
	fromData(p, size, version);
	OPENSSL_free(p);

	setIntName(rmslashdot(fname));
	fclose(fp);
}

pki_temp::~pki_temp()
{

}


int pki_temp::dataSize()
{
	int s = 9 * sizeof(int) +
	       8 * sizeof(char) +
	       xname.derSize() + (
	subAltName.length() +
	issAltName.length() +
	crlDist.length() +
	authInfAcc.length() +
	certPol.length() +
	nsComment.length() +
	nsBaseUrl.length() +
	nsRevocationUrl.length() +
	nsCARevocationUrl.length() +
	nsRenewalUrl.length() +
	nsCaPolicyUrl.length() +
	nsSslServerName.length() +
	12 ) * sizeof(char);
	printf("Size of template = %d\n", s);
	return s;
}


bool pki_temp::compare(pki_base *ref)
{
 // we don't care if templates with identical contents
 // are stored in the database ...
	return false;
}

QVariant pki_temp::column_data(int col)
{
	QString typec[]={tr("Empty"), tr("CA"), tr("Client"), tr("Server")};
	switch (col) {
		case 0:
			return QVariant(getIntName());
		case 1:
			return QVariant(typec[type]);
	}
	return QVariant();
}

QVariant pki_temp::getIcon()
{
	return QVariant(*icon);
}

void pki_temp::oldFromData(unsigned char *p, int size )
{
	const unsigned char *p1 = p;
	version=intFromData(&p1);
	type=intFromData(&p1);
	if (version == 1) {
		ca = 2;
		bool mca = intFromData(&p1);
		if (mca) ca = 1;
	}
	bcCrit=db::boolFromData(&p1);
	keyUseCrit=db::boolFromData(&p1);
	eKeyUseCrit=db::boolFromData(&p1);
	subKey=db::boolFromData(&p1);
	authKey=db::boolFromData(&p1);
	subAltCp=db::boolFromData(&p1);
	issAltCp=db::boolFromData(&p1);
	if (version >= 2) { 
		ca = intFromData(&p1);
	}
	pathLen=intFromData(&p1);
	validN = intFromData(&p1);
	validM = intFromData(&p1);
	keyUse=intFromData(&p1);
	eKeyUse=intFromData(&p1);
	nsCertType=intFromData(&p1);
	if (version == 1) {
		xname.addEntryByNid(OBJ_sn2nid("C"), db::stringFromData(&p1));
		xname.addEntryByNid(OBJ_sn2nid("ST"), db::stringFromData(&p1));
		xname.addEntryByNid(OBJ_sn2nid("L"), db::stringFromData(&p1));
		xname.addEntryByNid(OBJ_sn2nid("O"), db::stringFromData(&p1));
		xname.addEntryByNid(OBJ_sn2nid("OU"), db::stringFromData(&p1));
		xname.addEntryByNid(OBJ_sn2nid("CN"), db::stringFromData(&p1));
		xname.addEntryByNid(OBJ_sn2nid("Email"),db::stringFromData(&p1));
	}
	subAltName=db::stringFromData(&p1);
	issAltName=db::stringFromData(&p1);
	crlDist=db::stringFromData(&p1);
	nsComment=db::stringFromData(&p1);
	nsBaseUrl=db::stringFromData(&p1);
	nsRevocationUrl=db::stringFromData(&p1);
	nsCARevocationUrl=db::stringFromData(&p1);
	nsRenewalUrl=db::stringFromData(&p1);
	nsCaPolicyUrl=db::stringFromData(&p1);
	nsSslServerName=db::stringFromData(&p1);
	// next version:
	if (version >= 2) {
		p1 = xname.d2i(p1, size - (p1-p));
	}
	if (version >= 3) {
		authInfAcc=db::stringFromData(&p1);
		certPol=db::stringFromData(&p1);
		validMidn=db::intFromData(&p1);
	}

	if (p1-p != size) {
		openssl_error("Wrong Size");
	}

	//set version to 3
	version = 3;
}

