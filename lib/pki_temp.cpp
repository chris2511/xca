
//Added by the Qt porting tool:
#include <QPixmap>

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


#include "pki_temp.h"
#include "func.h"
#include <Qt/qdir.h>

QPixmap *pki_temp::icon=  NULL;

pki_temp::pki_temp(const pki_temp *pk) 
	:pki_base(pk->desc)
{
	class_name = pk->class_name;
	version=pk->version;
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
	version=3;
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


void pki_temp::fromData(const unsigned char *p, int size )
{
	const unsigned char *p1 = p;
	version=intFromData(&p1);
	type=intFromData(&p1);
	if (version == 1) {
		ca = 2;
		bool mca = boolFromData(&p1);
		if (mca) ca = 1;
	}
	bcCrit=boolFromData(&p1);
	keyUseCrit=boolFromData(&p1);
	eKeyUseCrit=boolFromData(&p1);
	subKey=boolFromData(&p1);
	authKey=boolFromData(&p1);
	subAltCp=boolFromData(&p1);
	issAltCp=boolFromData(&p1);
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
		xname.addEntryByNid(OBJ_sn2nid("C"), stringFromData(&p1));
		xname.addEntryByNid(OBJ_sn2nid("ST"), stringFromData(&p1));
		xname.addEntryByNid(OBJ_sn2nid("L"), stringFromData(&p1));
		xname.addEntryByNid(OBJ_sn2nid("O"), stringFromData(&p1));
		xname.addEntryByNid(OBJ_sn2nid("OU"), stringFromData(&p1));
		xname.addEntryByNid(OBJ_sn2nid("CN"), stringFromData(&p1));
		xname.addEntryByNid(OBJ_sn2nid("Email"),stringFromData(&p1));
	}
	subAltName=stringFromData(&p1);
	issAltName=stringFromData(&p1);
	crlDist=stringFromData(&p1);
	nsComment=stringFromData(&p1);
	nsBaseUrl=stringFromData(&p1);
	nsRevocationUrl=stringFromData(&p1);
	nsCARevocationUrl=stringFromData(&p1);
	nsRenewalUrl=stringFromData(&p1);
	nsCaPolicyUrl=stringFromData(&p1);
	nsSslServerName=stringFromData(&p1);
	// next version:
	if (version >= 2) { 
		p1 = xname.d2i(p1, size - (p1-p));
	}
	if (version >= 3) { 
		authInfAcc=stringFromData(&p1);
		certPol=stringFromData(&p1);
		validMidn=boolFromData(&p1);
	}
	
	if (p1-p != size) {
		openssl_error("Wrong Size");
	}
	 
	//set version to 3
	version = 3;
}


unsigned char *pki_temp::toData(int *size) 
{
	unsigned char *p, *p1;
	*size = dataSize();
	p = (unsigned char*)OPENSSL_malloc(*size);
	p1 = p;
	version = 3;
	intToData(&p1, version);
	intToData(&p1, type);
	boolToData(&p1, bcCrit);
	boolToData(&p1, keyUseCrit);
	boolToData(&p1, eKeyUseCrit);
	boolToData(&p1, subKey);
	boolToData(&p1, authKey);
	boolToData(&p1, subAltCp);
	boolToData(&p1, issAltCp);
	intToData(&p1, ca);
	intToData(&p1, pathLen);
	intToData(&p1, validN);
	intToData(&p1, validM);
	intToData(&p1, keyUse);
	intToData(&p1, eKeyUse);
	intToData(&p1, nsCertType);
	stringToData(&p1, subAltName);
	stringToData(&p1, issAltName);
	stringToData(&p1, crlDist);
	stringToData(&p1, nsComment);
	stringToData(&p1, nsBaseUrl);
	stringToData(&p1, nsRevocationUrl);
	stringToData(&p1, nsCARevocationUrl);
	stringToData(&p1, nsRenewalUrl);
	stringToData(&p1, nsCaPolicyUrl);
	stringToData(&p1, nsSslServerName);
	p1 = xname.i2d(p1);
	stringToData(&p1, authInfAcc);
	stringToData(&p1, certPol);
	boolToData(&p1, validMidn);
	return p;
}

void pki_temp::writeDefault(const QString fname)
{
	writeTemp(fname + QDir::separator() + getIntName() + ".xca");
}

void pki_temp::writeTemp(QString fname)
{
	int size = 0;
	unsigned char *p;
	FILE *fp = fopen(fname,"w");
	if (fp == NULL) {
		fopen_error(fname);
		return;
	}
	p = toData(&size);
	fwrite(&size, sizeof(size), 1, fp);
	fwrite(p, 1, size, fp);
	OPENSSL_free(p);
	fclose(fp);
}

void pki_temp::loadTemp(QString fname)
{
	unsigned int size;
	unsigned char *p;
	FILE *fp = fopen(fname,"r");
	if (fp == NULL) {
		fopen_error(fname);
		return;
	}
	if (fread(&size, sizeof(size), 1, fp) != 1)
		openssl_error(tr("Template file content error"));
	if (size > 65535 )
		openssl_error(tr("Template file content error"));
	p = (unsigned char *)OPENSSL_malloc(size);
	if (fread(p, 1, size, fp) != size) {
		OPENSSL_free(p);
		openssl_error(tr("Template file content error"));
	}
	fromData(p, (int)size);
	OPENSSL_free(p);
	
	setIntName(rmslashdot(fname));
	fclose(fp);
}

pki_temp::~pki_temp()
{

}


int pki_temp::dataSize()
{
	return 9 * sizeof(int) + 
	       8 * sizeof(bool) + 
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
		
}


bool pki_temp::compare(pki_base *ref)
{
 // we don't care if templates with identical contents
 // are stored in the database ...
	return false;
}	

void pki_temp::updateView()
{
	pki_base::updateView();
	if (!pointer) return;
	pointer->setPixmap(0, *icon);
	QString typec[]={tr("Empty"), tr("CA"), tr("Client"), tr("Server")};
	pointer->setText(1, typec[type]);
}


