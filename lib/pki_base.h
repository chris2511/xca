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

#include <openssl/err.h>
#include <iostream>
#include "exception.h"

#ifndef PKI_BASE_H
#define PKI_BASE_H

struct PASS_INFO {
	std::string *title;
	std::string *description;
};


class pki_base
{
    protected:
	std::string desc;
	std::string error;
	std::string className;
	void *pointer; 
	void openssl_error(const std::string myerr = "");
	void fopen_error(const std::string fname);
	bool ign_openssl_error();
	int intToData(unsigned char **p, const int val);
	int intFromData(unsigned char **p);
	int boolToData(unsigned char **p, const bool val);
	bool boolFromData(unsigned char **p);
	int stringToData(unsigned char **p, const std::string val);
	std::string stringFromData(unsigned char **p);
    public:
	pki_base(const std::string d);
	pki_base();
	virtual void fromData(unsigned char *p, int size)
		{ CERR("VIRTUAL FUNCTION CALLED: fromData"); };
	virtual unsigned char *toData(int *size)
		{ CERR("VIRTUAL FUNCTION CALLED: toData"); return NULL;};
	virtual bool compare(pki_base *ref)
		{ CERR("VIRTUAL FUNCTION CALLED: compare"); return false;};
	virtual ~pki_base();
        std::string getDescription();
        void setDescription(const std::string d );
	std::string getError();
	void setPointer(void *ptr) { pointer = ptr; }
	void delPointer() { pointer = NULL; }
	void *getPointer() { return pointer; }
	std::string getClassName();
};

#endif
