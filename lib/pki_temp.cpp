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


pki_temp::pki_temp(const pki_temp *pk) 
	:pki_base(pk->desc)
{
	version=pk->version;
	type=pk->type;
	C=pk->C;
	P=pk->P;
	L=pk->L;
	O=pk->O;
	OU=pk->OU;
	CN=pk->CN;
	EMAIL=pk->EMAIL;
	subAltName=pk->subAltName;
	issAltName=pk->issAltName;
	crlDist=pk->crlDist;
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
	keyUse=pk->keyUse;
	eKeyUse=pk->eKeyUse;
}

pki_temp::pki_temp(const string d, int atype)
	:pki_base(d)
{ 
	version=1;
	type=atype;
	C="";
	P="";
	L="";
	O="";
	OU="";
	CN="";
	EMAIL="";
	subAltName="";
	issAltName="";
	crlDist="";
	nsCertType=0;
	nsComment="xca certificate";
	nsBaseUrl="";
	nsRevocationUrl="";
	nsCARevocationUrl="";
	nsRenewalUrl="";
	nsCaPolicyUrl="";
	nsSslServerName="";
	ca=false;
	bcCrit=false;
	keyUseCrit=false;
	eKeyUseCrit=false;
	subKey=false;
	authKey=false;
	subAltCp=false;
	issAltCp=false;
	pathLen=0;
	validN=356;
	validM=0;
	keyUse=0;
	eKeyUse=0;
	if (type==tCA) {
		ca=true;
		bcCrit=true;
		authKey=true;
		issAltCp=true;
		nsCertType=112;
		keyUse=96;
	}
	if (type==tCLIENT) {
		ca=false;
		bcCrit=true;
		authKey=true;
		issAltCp=true;
		subAltCp=true;
		nsCertType=5;
		keyUse=13;
	}
	if (type==tSERVER) {
		ca=false;
		bcCrit=true;
		authKey=true;
		issAltCp=true;
		subAltCp=true;
		nsCertType=2;
		keyUse=7;
	}

}	


bool pki_temp::fromData(unsigned char *p, int size )
{
	CERR("Temp fromData");
	unsigned char *p1 = p;
	version=intFromData(&p1);
	type=intFromData(&p1);
	ca=boolFromData(&p1);
	bcCrit=boolFromData(&p1);
	keyUseCrit=boolFromData(&p1);
	eKeyUseCrit=boolFromData(&p1);
	subKey=boolFromData(&p1);
	authKey=boolFromData(&p1);
	subAltCp=boolFromData(&p1);
	issAltCp=boolFromData(&p1);
	pathLen=intFromData(&p1);
	validN=intFromData(&p1);
	validM=intFromData(&p1);
	keyUse=intFromData(&p1);
	eKeyUse=intFromData(&p1);
	nsCertType=intFromData(&p1);
	C=stringFromData(&p1);
	P=stringFromData(&p1);
	L=stringFromData(&p1);
	O=stringFromData(&p1);
	OU=stringFromData(&p1);
	CN=stringFromData(&p1);
	EMAIL=stringFromData(&p1);
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
	//next version:
	//if (version == 2) { ..... }
	if (p1-p != size) {
		CERR( "AAAAarrrrgghhhhh wrong tempsize..." << (p1-p) << " - " <<size );
		return false;
	}
	return true;
}


unsigned char *pki_temp::toData(int *size) 
{
	CERR("temp toData " << getDescription() );
	unsigned char *p, *p1;
	*size = dataSize();
	p = (unsigned char*)OPENSSL_malloc(*size);
	p1 = p;
	intToData(&p1, version);
	intToData(&p1, type);
	boolToData(&p1, ca);
	boolToData(&p1, bcCrit);
	boolToData(&p1, keyUseCrit);
	boolToData(&p1, eKeyUseCrit);
	boolToData(&p1, subKey);
	boolToData(&p1, authKey);
	boolToData(&p1, subAltCp);
	boolToData(&p1, issAltCp);
	intToData(&p1, pathLen);
	intToData(&p1, validN);
	intToData(&p1, validM);
	intToData(&p1, keyUse);
	intToData(&p1, eKeyUse);
	intToData(&p1, nsCertType);
	stringToData(&p1, C);
	stringToData(&p1, P);
	stringToData(&p1, L);
	stringToData(&p1, O);
	stringToData(&p1, OU);
	stringToData(&p1, CN);
	stringToData(&p1, EMAIL);
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

	CERR( "Temp toData end ..."<< (p1-p) << " - "<<*size );
	return p;
}



pki_temp::~pki_temp()
{

}


int pki_temp::dataSize()
{
	return 8 * sizeof(int) + 8 * sizeof(bool) + (
	C.length() +
	P.length() +
	L.length() +
	O.length() +
	OU.length() +
	CN.length() +
	EMAIL.length() +
	subAltName.length() +
	issAltName.length() +
	crlDist.length() +
	nsComment.length() +
	nsBaseUrl.length() +
	nsRevocationUrl.length() +
	nsCARevocationUrl.length() +
	nsRenewalUrl.length() +
	nsCaPolicyUrl.length() +
	nsSslServerName.length() +
	17 ) * sizeof(char);
		
}


bool pki_temp::compare(pki_base *ref)
{
 // we don't care if templates with identical contents
 // are stored in the database ...
	return false;
}	


