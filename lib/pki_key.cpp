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

char pki_key::passwd[40]="\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

void pki_key::init()
{
	ucount = 0;
	className = "pki_key";
}
	
pki_key::pki_key(const string d, void (*cb)(int, int,void *),void *prog, int bits = 1024, int type): pki_base(d)
{
	init();
	key = EVP_PKEY_new();
	openssl_error();	
	key->type = type;
	if (type == EVP_PKEY_RSA) {
	   RSA *rsakey;
	   rsakey = RSA_generate_key(bits, 0x10001, cb, prog);
	   if (rsakey) EVP_PKEY_set1_RSA(key, rsakey);
	}
	openssl_error();	
}

pki_key::pki_key(const pki_key *pk) 
	:pki_base(pk->desc)
{
	init();
	key = EVP_PKEY_new();
	openssl_error();	
	key->type = pk->key->type;
	if (key->type == EVP_PKEY_RSA) {
		key->pkey.rsa=((RSA *)ASN1_dup( (int (*)())i2d_RSAPrivateKey, (char *(*)())d2i_RSAPrivateKey,(char *)pk->key->pkey.rsa));
	}
	// TODO add DSA support.....	
	openssl_error();
}

pki_key::pki_key(const string d, int type )
	:pki_base(d)
{ 
	init();
	key = EVP_PKEY_new();
	key->type = type;
	openssl_error();
}	

pki_key::pki_key(EVP_PKEY *pkey)
	:pki_base("")
{ 
	init();
	key = pkey;
}	

pki_key::pki_key(const string fname, pem_password_cb *cb, int type )
	:pki_base(fname)
{ 
	init();
	PASS_INFO p;
	string title = XCA_TITLE;
	string description = "Please enter the password to decrypt the RSA key."; 
	p.title = &title;
	p.description = &description;
	key = EVP_PKEY_new();
	key->type = EVP_PKEY_type(type);
	error = "";
	FILE *fp = fopen(fname.c_str(), "r");
	RSA *rsakey = NULL;
	if (fp != NULL) {
	   rsakey = PEM_read_RSAPrivateKey(fp, NULL, cb, &p);
	   if (!rsakey) {
		ign_openssl_error();
		rewind(fp);
		CERR("Fallback to privatekey DER"); 
	   	rsakey = d2i_RSAPrivateKey_fp(fp, NULL);
	   }
	   if (!rsakey) {
		ign_openssl_error();
		rewind(fp);
		CERR("Fallback to pubkey"); 
	   	rsakey = PEM_read_RSA_PUBKEY(fp, NULL, cb, &p);
	   }
	   if (!rsakey) {
		ign_openssl_error();
		rewind(fp);
		CERR("Fallback to pubkey DER"); 
	   	rsakey = d2i_RSA_PUBKEY_fp(fp, NULL);
	   }
	   if (!rsakey) {
	        ign_openssl_error();
	        rewind(fp);
		title = "Password for PKCS#8 private key";
		description = "Please enter the password to decrypt the PKCS#8 private key.";
		CERR("Fallback to PKCS#8 Private key"); 
	        d2i_PKCS8PrivateKey_fp(fp, &key, cb, &p);
	   }
	   else {
	   	EVP_PKEY_set1_RSA(key,rsakey);
		openssl_error();
		CERR("assigning loaded key");
	   }
	   int r = fname.rfind('.');
#ifdef WIN32
	   int l = fname.rfind('\\');
#else
	   int l = fname.rfind('/');
#endif
	   CERR( fname << "r,l: "<< r <<","<< l );
	   setDescription(fname.substr(l+1,r-l-1));
	   openssl_error();
	}	
	else fopen_error(fname);
	CERR("end of loading");
	fclose(fp);
}


void pki_key::fromData(unsigned char *p, int size )
{
	CERR( "KEY fromData");
	unsigned char *sik, *pdec, *pdec1, *sik1;
	int outl, decsize;
        unsigned char iv[EVP_MAX_IV_LENGTH];
        unsigned char ckey[EVP_MAX_KEY_LENGTH];
	memset(iv, 0, EVP_MAX_IV_LENGTH);
	RSA *rsakey;
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER *cipher = EVP_des_ede3_cbc();
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
        EVP_BytesToKey(cipher, EVP_sha1(), iv, (unsigned char *)passwd, strlen(passwd), 1, ckey,NULL); /* generate the key */
	/* we use sha1 as message digest, because an md5 version of the password is stored in the database... */
	EVP_CIPHER_CTX_init (&ctx);
	EVP_DecryptInit( &ctx, cipher, ckey, iv);
	EVP_DecryptUpdate( &ctx, pdec , &outl, p + 8, size -8 );
	decsize = outl;
	EVP_DecryptFinal( &ctx, pdec + decsize , &outl );
	decsize += outl;
	CERR("Decryption  done: DB:" << size << " encrypted:" << size-8 << " decrypted:" << decsize);
	openssl_error();
	memcpy(sik, pdec, decsize);
	if (key->type == EVP_PKEY_RSA) {
	   rsakey = d2i_RSAPrivateKey(NULL, &pdec, decsize);
	   if (ign_openssl_error()) {
		rsakey = d2i_RSA_PUBKEY(NULL, &sik, decsize);
	   }
	   openssl_error(); 
	   if (rsakey) EVP_PKEY_set1_RSA(key, rsakey);
	}
	OPENSSL_free(sik1);
	OPENSSL_free(pdec1);
	openssl_error();
}


unsigned char *pki_key::toData(int *size) 
{
	CERR("KEY toData " << getDescription());
	unsigned char *p, *p1, *penc;
	int outl, encsize=0;
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER *cipher = EVP_des_ede3_cbc();
        unsigned char iv[EVP_MAX_IV_LENGTH];
        unsigned char ckey[EVP_MAX_KEY_LENGTH];
	memset(iv, 0, EVP_MAX_IV_LENGTH);
        RAND_pseudo_bytes(iv,8);      /* Generate a salt */
        EVP_BytesToKey(cipher, EVP_sha1(), iv, (unsigned char *)passwd, strlen(passwd), 1, ckey,NULL);
	EVP_CIPHER_CTX_init (&ctx);
	EVP_EncryptInit( &ctx, cipher, ckey, iv);
	openssl_error();
	//if (key->type == EVP_PKEY_RSA) {
	if (true) {
	   if (isPubKey()) {
	      *size = i2d_RSA_PUBKEY(key->pkey.rsa, NULL);
	      CERR("Sizeofpubkey: " << *size );
	      p = (unsigned char *)OPENSSL_malloc(*size);
	      openssl_error();
	      penc = (unsigned char *)OPENSSL_malloc(*size +  EVP_MAX_KEY_LENGTH + 8);
	      if (!penc) {
		      OPENSSL_free(p);
		      openssl_error();
	      }
	      p1 = p;
	      memcpy(penc,iv,8); /* store the iv */
	      i2d_RSA_PUBKEY(key->pkey.rsa, &p1);
	      EVP_EncryptUpdate( &ctx, penc + 8, &outl, p, *size );
	      encsize = outl;
	      openssl_error();
	      
	   }
	   else {
	      *size = i2d_RSAPrivateKey(key->pkey.rsa, NULL);
	      CERR("Sizeofprivkey: " << *size );
	      openssl_error();
	      p = (unsigned char *)OPENSSL_malloc(*size);
	      openssl_error();
	      penc = (unsigned char *)OPENSSL_malloc(*size +  EVP_MAX_KEY_LENGTH + 8);
	      if (!penc) {
		      OPENSSL_free(p);
		      openssl_error();
	      }
	      p1 = p;
	      memcpy(penc, iv, 8); /* store the iv */
	      i2d_RSAPrivateKey(key->pkey.rsa, &p1);
	      EVP_EncryptUpdate( &ctx, penc + 8, &outl, p, *size ); /* store key right after the iv */
	      encsize = outl;
	      openssl_error();
	   }
	}
	EVP_EncryptFinal( &ctx, penc + encsize + 8, &outl );
	encsize += outl ;
	OPENSSL_free(p);
	openssl_error();	
	CERR("KEY toData end DB:"<< encsize+8 << " encrypted:"<< encsize << " decrypted:" << *size);
	*size = encsize + 8;
	return penc;
}



pki_key::~pki_key()
{
	//RSA_free(key);
	EVP_PKEY_free(key);
}


void pki_key::writePKCS8(const string fname, pem_password_cb *cb)
{
	PASS_INFO p;
	string title=XCA_TITLE;
	string description="Please enter the password protecting the PKCS#8 key";
	p.title = &title;
	p.description = &description;
	FILE *fp = fopen(fname.c_str(),"w");
	if (fp != NULL) {
	   if (key){
		CERR( "writing PKCS8");
		PEM_write_PKCS8PrivateKey_nid(fp, key, 
		   NID_pbeWithMD5AndDES_CBC, NULL, 0, cb, &p);
		openssl_error();
	   }
	}
	else fopen_error(fname);
	fclose(fp);
}

void pki_key::writeKey(const string fname, EVP_CIPHER *enc, 
			pem_password_cb *cb, bool PEM)
{
	PASS_INFO p;
	string title=XCA_TITLE;
	string description="Please enter the password protecting the RSA private key";
	p.title = &title;
	p.description = &description;
	if (isPubKey()) {
		writePublic(fname, PEM);
		return;
	}
	FILE *fp = fopen(fname.c_str(),"w");
	if (fp != NULL) {
	   if (key){
		CERR("writing Private Key");
		if (PEM) 
		   PEM_write_PrivateKey(fp, key, enc, NULL, 0, cb, NULL);
		else {
		   i2d_RSAPrivateKey_fp(fp, key->pkey.rsa);
	        }
	   	openssl_error();
	   }
	}
	else fopen_error(fname);
	fclose(fp);
}


void pki_key::writePublic(const string fname, bool PEM)
{
	FILE *fp = fopen(fname.c_str(),"w");
	if (fp != NULL) {
	   if (key->type == EVP_PKEY_RSA) {
		CERR("writing Public Key");
		if (PEM)
		   PEM_write_RSA_PUBKEY(fp, key->pkey.rsa);
		else
		   i2d_RSA_PUBKEY_fp(fp, key->pkey.rsa);
		openssl_error();
	   }
	}
	else fopen_error(fname);
	fclose(fp);
}


string pki_key::length()
{
	char st[64];
	sprintf(st,"%i bit", EVP_PKEY_size(key) * 8 );
	openssl_error();
	string x = st;
	return x;
}

string pki_key::BN2string(BIGNUM *bn)
{
	if (bn == NULL) return "--";
	string x="";
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

string pki_key::modulus() {
	return BN2string(key->pkey.rsa->n);
}

string pki_key::pubEx() {
	return BN2string(key->pkey.rsa->e);
}

string pki_key::privEx() {
	if (isPubKey()) return "Not existent (not a private key)";
	return BN2string(key->pkey.rsa->d);
}

bool pki_key::compare(pki_base *ref)
{
	pki_key *kref = (pki_key *)ref;
	if (kref == NULL) return false;
	if (kref->key == NULL) return false;
	if (kref->key->pkey.rsa->n == NULL) return false;
	if (key == NULL) return false;
	if (key->pkey.rsa->n == NULL) return false;
	if (
	   BN_cmp(key->pkey.rsa->n, kref->key->pkey.rsa->n) ||
	   BN_cmp(key->pkey.rsa->e, kref->key->pkey.rsa->e) 
	){
		openssl_error();
		return false;
	}
	openssl_error();
	return true;
}	


bool pki_key::isPubKey()
{
	if (key == NULL) {
	   CERR("key is null");
	   return false;
	}
	if (key->pkey.rsa == 0) {
	   CERR("key->pkey is null");
	   return false;
	}
	return (key->pkey.rsa->d == NULL);
	
}

bool pki_key::isPrivKey()
{
	return ! isPubKey();
	
}

int pki_key::verify()
{
	bool veri = false;
	return true;
	CERR("verify start");
	if (key->type == EVP_PKEY_RSA && isPrivKey()) {
	   if (RSA_check_key(key->pkey.rsa) == 1) veri = true;
	}
	if (isPrivKey()) veri = true;
	openssl_error();
	CERR("verify end: "<< veri );
	return veri;
}
		
int pki_key::getType()
{
	return key->type;
}

int pki_key::incUcount()
{
	return ++ucount;
}
int pki_key::decUcount()
{
	return --ucount;
}

int pki_key::getUcount()
{
	return ucount;
}
