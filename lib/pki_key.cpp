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


#include "pki_key.h"
#include "pass_info.h"
#include "func.h"
#include <openssl/rand.h>
#include <qprogressdialog.h>
#include <qapplication.h>
#include <qdir.h>
#include <widgets/MainWindow.h>

char pki_key::passwd[40]={0,};

QPixmap *pki_key::icon[2]= { NULL, NULL };

void pki_key::erasePasswd(){
	for (int i=0; i<40; i++)
		passwd[i] = 0;
}

void pki_key::init(int type)
{
	ucount = 0;
	key = EVP_PKEY_new();
	key->type = type;
	class_name = "pki_key";
	encKey = NULL;
	encKey_len = 0;
	ownPass = 0;
}

void pki_key::incProgress(int a, int b, void *progress)
{
	int i = ((QProgressDialog *)progress)->progress();
			((QProgressDialog *)progress)->setProgress(++i);
}

QString pki_key::getIntNameWithType()
{
	QString postfix;
	switch (key->type) {
		case EVP_PKEY_RSA:
			postfix = " (RSA)";
			break;
		case EVP_PKEY_DSA:
			postfix = " (DSA)";
			break;
		default:
			postfix = " (---)";
	}
	return getIntName() + postfix;
}

QString pki_key::removeTypeFromIntName(QString n)
{
	if (n.right(1) != ")" ) return n;
	n.truncate(n.length() - 6);
	return n;
}

void pki_key::setOwnPass(int x)
{
	EVP_PKEY *pk;
	if (x) x=1;
	if (ownPass == x) return;
	
	pk = decryptKey();
	if (pk == NULL) return;
	
	EVP_PKEY_free(key);
	key = pk;
	ownPass = x;
	encryptKey();
}

void pki_key::generate(int bits, int type)
{
	RSA *rsakey = NULL;
	DSA *dsakey = NULL;
	QProgressDialog *progress = new QProgressDialog(
		qApp->tr("Please wait, Key generation is in progress"),
		qApp->tr("Cancel"),90, 0, 0, true);
	progress->setMinimumDuration(0);
	progress->setProgress(0);   
	progress->setCaption(XCA_TITLE);
	
	if (type == EVP_PKEY_RSA) {
		rsakey = RSA_generate_key(bits, 0x10001, &incProgress, progress);
		if (rsakey) EVP_PKEY_set1_RSA(key, rsakey);
	} else if (type == EVP_PKEY_DSA) {
 		dsakey = DSA_generate_parameters(bits,NULL,0,NULL,NULL,&incProgress, progress);
		DSA_generate_key(dsakey);
		if(dsakey) EVP_PKEY_set1_DSA(key,dsakey);
	}
	
	progress->cancel();
	delete progress;
				 
	openssl_error();
	encryptKey();
}

pki_key::pki_key(const pki_key *pk) 
	:pki_base(pk->desc)
{
	init();
	openssl_error();	
	if (pk == NULL) return;
	key->type = pk->key->type;
	if (key->type == EVP_PKEY_RSA) {
		//rsakey = RSA_dup(pk->key->pkey.rsa);
		key->pkey.rsa=((RSA *)ASN1_dup( (int (*)())i2d_RSAPrivateKey, (char *(*)())d2i_RSAPrivateKey,(char *)pk->key->pkey.rsa));
	}
	if (key->type == EVP_PKEY_DSA) {
		key->pkey.dsa=((DSA *)ASN1_dup( (int(*)())i2d_DSAPrivateKey, (char *(*)())d2i_DSAPrivateKey,(char *)pk->key->pkey.dsa));
	}
	 
	openssl_error();
	encryptKey();
}

pki_key::pki_key(const QString name, int type )
	:pki_base(name)
{ 
	init(type);
	openssl_error();
}	

pki_key::pki_key(EVP_PKEY *pkey)
	:pki_base()
{ 
	init();
	if (pkey) {
		EVP_PKEY_free(key);
	}
	key = pkey;
}	

void pki_key::fload(const QString fname)
{ 
	pass_info p(XCA_TITLE, tr("Please enter the password to decrypt the private key.")
		+ "\n'" + fname + "'"); 
	pem_password_cb *cb = &MainWindow::passRead;
	FILE *fp = fopen(fname.latin1(), "r");
	EVP_PKEY *pkey = NULL;
	bool priv = true;
	
	if (fp != NULL) {
		pkey = PEM_read_PrivateKey(fp, NULL, cb, &p);

		if (!pkey) {
			ign_openssl_error();
			rewind(fp);
	   		pkey = d2i_PrivateKey_fp(fp, NULL);
		}
		if (!pkey) {
			ign_openssl_error();
			rewind(fp);
			pkey = PEM_read_PUBKEY(fp, NULL, cb, &p);
			if (pkey) priv=false;
		}
		if (!pkey) {
			ign_openssl_error();
			rewind(fp);
			pkey = d2i_PUBKEY_fp(fp, NULL);
			if (pkey) priv=false;
		}
		if (pkey){
			if (key)
				EVP_PKEY_free(key);
			key = pkey;
			if (priv)
				encryptKey();
			setIntName(rmslashdot(fname));
		}
		
		openssl_error();
	}	
	else fopen_error(fname);
	fclose(fp);
}

void pki_key::fromData(const unsigned char *p, int size )
{
	const unsigned char *p1;
	int version, type;
	
	p1 = p;
	
	version = intFromData(&p1);
	if (version != 1) { // backward compatibility
		oldFromData(p, size);
		return;
	}
	if (key)
		EVP_PKEY_free(key);
	
	key = NULL;
	type = intFromData(&p1);
	ownPass = intFromData(&p1);
	
	D2I_CLASHT(d2i_PublicKey, type, &key, &p1, size - (2*sizeof(int)));
	openssl_error(); 
	
	encKey_len = size - (p1-p); 
	if (encKey_len) {
		encKey = (unsigned char *)OPENSSL_malloc(encKey_len);
		memcpy(encKey, p1 ,encKey_len);
	}
	
}

void pki_key::oldFromData(const unsigned char *p, int size )
{
	unsigned char *sik, *pdec;
	const unsigned char *pdec1, *sik1;
	int outl, decsize;
	unsigned char iv[EVP_MAX_IV_LENGTH];
	unsigned char ckey[EVP_MAX_KEY_LENGTH];
	memset(iv, 0, EVP_MAX_IV_LENGTH);
	RSA *rsakey;
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER *cipher = EVP_des_ede3_cbc();
	sik = (unsigned char *)OPENSSL_malloc(size);
	openssl_error();
	pdec = (unsigned char *)OPENSSL_malloc(size);
	if (pdec == NULL ) {
		OPENSSL_free(sik); 
		openssl_error();
	}
	pdec1=pdec;
	sik1=sik;
	memcpy(iv, p, 8); /* recover the iv */
	/* generate the key */
	EVP_BytesToKey(cipher, EVP_sha1(), iv, (unsigned char *)passwd,
		strlen(passwd), 1, ckey,NULL);
	/* we use sha1 as message digest, 
	 * because an md5 version of the password is 
	 * stored in the database...
	 */
	EVP_CIPHER_CTX_init (&ctx);
	EVP_DecryptInit( &ctx, cipher, ckey, iv);
	EVP_DecryptUpdate( &ctx, pdec , &outl, p + 8, size -8 );
	decsize = outl;
	EVP_DecryptFinal( &ctx, pdec + decsize , &outl );
	decsize += outl;
	openssl_error();
	memcpy(sik, pdec, decsize);
	if (key->type == EVP_PKEY_RSA) {
		rsakey = d2i_RSAPrivateKey(NULL, &pdec1, decsize);
		if (ign_openssl_error()) {
			rsakey = D2I_CLASH(d2i_RSA_PUBKEY, NULL, &sik1, decsize);
		}
		openssl_error(); 
		if (rsakey) EVP_PKEY_assign_RSA(key, rsakey);
	}
	OPENSSL_free(sik);
	OPENSSL_free(pdec);
	EVP_CIPHER_CTX_cleanup(&ctx);
	openssl_error();
}

EVP_PKEY *pki_key::decryptKey()
{
	unsigned char *p;
	const unsigned char *p1;
	int outl, decsize;
	unsigned char iv[EVP_MAX_IV_LENGTH];
	unsigned char ckey[EVP_MAX_KEY_LENGTH];
	
	EVP_PKEY *tmpkey;
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER *cipher = EVP_des_ede3_cbc();
	char ownPassBuf[MAX_PASS_LENGTH];
	
	/* This key has its  own password */
	if (ownPass == 1) {
		pass_info pi(XCA_TITLE, tr("Please enter the password to decrypt the private key: '" + getIntName() + "'"));
		MainWindow::passRead(ownPassBuf, MAX_PASS_LENGTH, 0, &pi);
	}
	else {
		memcpy(ownPassBuf, passwd, MAX_PASS_LENGTH);
	}
	
	p = (unsigned char *)OPENSSL_malloc(encKey_len);
	openssl_error();
	p1 = p;
	memset(iv, 0, EVP_MAX_IV_LENGTH);
	
	memcpy(iv, encKey, 8); /* recover the iv */
	/* generate the key */
	EVP_BytesToKey(cipher, EVP_sha1(), iv, (unsigned char *)ownPassBuf,
		strlen(ownPassBuf), 1, ckey,NULL);
	/* we use sha1 as message digest, 
	 * because an md5 version of the password is 
	 * stored in the database...
	 */
	EVP_CIPHER_CTX_init (&ctx);
	EVP_DecryptInit( &ctx, cipher, ckey, iv);
	EVP_DecryptUpdate( &ctx, p , &outl, encKey + 8, encKey_len - 8 );
	decsize = outl;
	EVP_DecryptFinal( &ctx, encKey + decsize , &outl );
	decsize += outl;
	openssl_error();
	tmpkey = D2I_CLASHT(d2i_PrivateKey, key->type, NULL, &p1, decsize);
	OPENSSL_free(p);
	EVP_CIPHER_CTX_cleanup(&ctx);
	openssl_error();
	return tmpkey;
}

unsigned char *pki_key::toData(int *size) 
{
	unsigned char *p, *p1;
	int pubsize;
	
	pubsize = i2d_PublicKey(key, NULL);
	*size = pubsize + encKey_len + (3*sizeof(int));
	p = (unsigned char *)OPENSSL_malloc(*size);
	openssl_error();
	p1 = p;
	intToData(&p1, 1);
	intToData(&p1, key->type);
	intToData(&p1, ownPass);
	i2d_PublicKey(key, &p1);
	openssl_error();
	if (encKey_len) {
		memcpy(p1, encKey, encKey_len);
	}
	return p;
}

void pki_key::encryptKey() 
{
	int outl, keylen;
	EVP_PKEY *pkey1 = NULL;
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER *cipher = EVP_des_ede3_cbc();
	unsigned char iv[EVP_MAX_IV_LENGTH], *punenc, *punenc1;
	const unsigned char *punencc;
	unsigned char ckey[EVP_MAX_KEY_LENGTH];
	char ownPassBuf[MAX_PASS_LENGTH];

	/* This key has its own, private password ? */
	if (ownPass == 1) {
		pass_info p(XCA_TITLE, tr("Please enter the password to protect the private key: '" + getIntName() + "'"));
		MainWindow::passWrite(ownPassBuf, MAX_PASS_LENGTH, 0, &p);
	}
	else {
		memcpy(ownPassBuf, passwd, MAX_PASS_LENGTH);
	}
	
	/* Prepare Encryption */
	memset(iv, 0, EVP_MAX_IV_LENGTH);
	RAND_pseudo_bytes(iv,8);      /* Generate a salt */
	EVP_BytesToKey(cipher, EVP_sha1(), iv, (unsigned char *)ownPassBuf,
		   	strlen(ownPassBuf), 1, ckey, NULL);
	EVP_CIPHER_CTX_init (&ctx);
	openssl_error();
	if (encKey) 
		OPENSSL_free(encKey);
	encKey_len = 0;

	/* reserve space for unencrypted and encrypted key */
	keylen = i2d_PrivateKey(key, NULL);
	encKey = (unsigned char *)OPENSSL_malloc(keylen + EVP_MAX_KEY_LENGTH + 8);
	punenc = (unsigned char *)OPENSSL_malloc(keylen);
	openssl_error();
	punencc = punenc1 = punenc;
	memcpy(encKey, iv, 8); /* store the iv */
	/* convert rsa/dsa to Pubkey */
    i2d_PublicKey(key, &punenc);
	punenc = punenc1;	
	D2I_CLASHT(d2i_PublicKey, key->type, &pkey1, &punencc, keylen);
	openssl_error();
    i2d_PrivateKey(key, &punenc);
	punenc = punenc1;	

	/* do the encryption */
	/* store key right after the iv */
	EVP_EncryptInit( &ctx, cipher, ckey, iv);
	EVP_EncryptUpdate( &ctx, encKey + 8, &outl, punenc, keylen );
	encKey_len = outl;
	EVP_EncryptFinal( &ctx, encKey + encKey_len + 8, &outl );
	encKey_len += outl + 8;

	/* Cleanup */
	EVP_CIPHER_CTX_cleanup(&ctx);
	OPENSSL_free(punenc);
	openssl_error();	
	
	EVP_PKEY_free(key);
	key = pkey1;
	openssl_error();
	
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_OFF);
	
	return;
}



pki_key::~pki_key()
{
	if (key)
		EVP_PKEY_free(key);
	if (encKey)
		OPENSSL_free(encKey);
}


void pki_key::writePKCS8(const QString fname, pem_password_cb *cb)
{
	EVP_PKEY *pkey;
	pass_info p(XCA_TITLE, tr("Please enter the password protecting the PKCS#8 key"));
	FILE *fp = fopen(fname.latin1(),"w");
	if (fp != NULL) {
		if (key){
			pkey = decryptKey();
			PEM_write_PKCS8PrivateKey_nid(fp, pkey, 
						NID_pbeWithMD5AndDES_CBC, NULL, 0, cb, &p);
			EVP_PKEY_free(pkey);
			openssl_error();
	   }
	}
	else fopen_error(fname);
	fclose(fp);
}

static int mycb(char *buf, int size, int rwflag, void *userdata)
{
	strncpy(buf, pki_key::passwd, size);
	return strnlen(pki_key::passwd, size);
}

void pki_key::writeDefault(const QString fname)
{
	writeKey(fname + QDir::separator() + getIntName() + ".pem",
			EVP_des_ede3_cbc(), mycb, true);
}

void pki_key::writeKey(const QString fname, const EVP_CIPHER *enc, 
			pem_password_cb *cb, bool PEM)
{
	EVP_PKEY *pkey;
	pass_info p(XCA_TITLE, tr("Please enter the export password for the private key"));
	if (isPubKey()) {
		writePublic(fname, PEM);
		return;
	}
	FILE *fp = fopen(fname.latin1(), "w");
	if (fp != NULL) {
		if (key){
			pkey = decryptKey();
			if (PEM) {
				PEM_write_PrivateKey(fp, pkey, enc, NULL, 0, cb, &p);
			} else {
				i2d_PrivateKey_fp(fp, pkey);
	        }
			EVP_PKEY_free(pkey);
	   		openssl_error();
		}
	}
	else fopen_error(fname);
	fclose(fp);
}

void pki_key::writePublic(const QString fname, bool PEM)
{
	FILE *fp = fopen(fname.latin1(),"w");
	if (fp != NULL) {
		if (key->type == EVP_PKEY_RSA) {
			if (PEM)
				PEM_write_PUBKEY(fp, key);
			else
				i2d_PUBKEY_fp(fp, key);
		openssl_error();
	   }
	}
	else fopen_error(fname);
	fclose(fp);
}


QString pki_key::length()
{
	char st[64];
	sprintf(st,"%i bit", EVP_PKEY_size(key) * 8 );
	openssl_error();
	QString x = st;
	return x;
}

QString pki_key::BN2QString(BIGNUM *bn)
{
	if (bn == NULL) return "--";
	QString x="";
	char zs[10];
	int j;
	int size = BN_num_bytes(bn);
	unsigned char *buf = (unsigned char *)OPENSSL_malloc(size);
	BN_bn2bin(bn, buf);
	for (j = 0; j< size; j++) {
		sprintf(zs, "%02X%c",buf[j], ((j+1)%16 == 0) ?'\n':':');
		x += zs;
	}
	OPENSSL_free(buf);
	openssl_error();
	return x;
}

QString pki_key::modulus() {
	if (key->type != EVP_PKEY_RSA) return "??no rsa??";
	return BN2QString(key->pkey.rsa->n);
}

QString pki_key::pubEx() {
	if (key->type != EVP_PKEY_RSA) return "??no rsa??";
	return BN2QString(key->pkey.rsa->e);
}

QString pki_key::subprime() {
	if (key->type != EVP_PKEY_DSA) return "??no dsa??";
	return BN2QString(key->pkey.dsa->q);
}

QString pki_key::pubkey() {
	if (key->type != EVP_PKEY_DSA) return "??no dsa??";
	return BN2QString(key->pkey.dsa->pub_key);
}

bool pki_key::compare(pki_base *ref)
{
	pki_key *kref = (pki_key *)ref;
	if(key->type == EVP_PKEY_RSA) {
		if (kref==NULL || kref->key==NULL || kref->key->pkey.rsa->n==NULL)
			return false;
		if (key == NULL || key->pkey.rsa->n == NULL)
		   	return false;
		if (
			BN_cmp(key->pkey.rsa->n, kref->key->pkey.rsa->n) ||
			BN_cmp(key->pkey.rsa->e, kref->key->pkey.rsa->e) 
		){
			openssl_error();
			return false;
		}
	} else if(key->type == EVP_PKEY_DSA) {
		if(kref==NULL || kref->key==NULL || kref->key->pkey.dsa->pub_key==NULL)
			return false;
		if(key==NULL || key->pkey.dsa->pub_key==NULL)
		   	return false;
		if(BN_cmp(key->pkey.dsa->pub_key,kref->key->pkey.dsa->pub_key)){
			openssl_error();
			return false;
		}
	}													 
	openssl_error();
	return true;
}	


bool pki_key::isPubKey()
{
	if (encKey_len == 0 || encKey == NULL) {
		return true;
	}
	return false;
}

bool pki_key::isPrivKey()
{
	return ! isPubKey();
}

int pki_key::verify()
{
	bool veri = false;
	return true;
	if (key->type == EVP_PKEY_RSA && isPrivKey()) {
	   if (RSA_check_key(key->pkey.rsa) == 1) veri = true;
	}
	if (isPrivKey()) veri = true;
	openssl_error();
	return veri;
}
		
int pki_key::getType()
{
	return key->type;
}

int pki_key::incUcount()
{
	ucount++;
	updateView();
	return ucount;
}
int pki_key::decUcount()
{
	ucount--;
	updateView();
	return ucount;
}

int pki_key::getUcount()
{
	return ucount;
}

void pki_key::updateView()
{
	QString type_str = "";
	pki_base::updateView();
	int pixnum = 0;
	
	if (!pointer) return;
	if (isPubKey()) pixnum += 1;
	
	switch (key->type) {
		case EVP_PKEY_RSA: type_str = "RSA"; break;
		case EVP_PKEY_DSA: type_str = "DSA"; break;
		default: type_str = "???"; break;
	}
	
	pointer->setPixmap(0, *icon[pixnum]);
	pointer->setText(1, length());
	pointer->setText(2, QString::number(getUcount()));
	pointer->setText(3, type_str);
}


