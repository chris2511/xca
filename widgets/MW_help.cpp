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


#include "MainWindow.h"
#include <qapplication.h>
#include <qmime.h>
#include <qtextbrowser.h>
#include <qpixmap.h>
#include <qlabel.h>
#include <iostream.h>
#include "ui/About.h"
#include "ui/Help.h"
#include "lib/func.h"


void MainWindow::cmd_help(const char* msg) {

fprintf(stderr, " -v show version information and exit\n"
" -k expect all following non-option arguments to be RSA keys\n"
" -r expect all following non-option arguments to be\n"
"    Certificate signing requests or SPKAC requests\n"
" -c expect all following non-option arguments to be Certificates\n"
" -p expect all following non-option arguments to be PKCS#12 files\n"
" -7 expect all following non-option arguments to be PKCS#7 files\n"
" -l expect all following non-option arguments to be Revokation lists\n"
" -t expect all following non-option arguments to be XCA templates\n"
" -d expect the following argument to be the database name to use\n"
" -b expect the following argument to be the basedirectory for oids\n"
"    and database logs\n"
" -x Exit after processing all commandline options\n\n");

qFatal("Cmdline Error (%s)\n", msg);
}

void MainWindow::about()
{
	About_UI *about = new About_UI(this, 0, true );
	QString cont="<p><h3><center><u>XCA</u></center></h3>"
	"<p>Copyright 2002 - 2003 by Christian Hohnst&auml;dt - "
	"version : <b>" VER "</b>"
	"<p><hr><br><table border=0>"
	"<tr><th align=left>Christian Hohnst&auml;dt</th><td><u>&lt;christian@hohnstaedt.de&gt;</u></td></tr>"
	"<tr><td></td><td>Programming, Translation and Testing</td></tr>"
	"<tr><th align=left>Kerstin Steinhauff</th><td><u>&lt;tine@kerstine.de&gt;</td></u></tr>"
	"<tr><td></td><td>Arts and Graphics</td></tr>"
	"<tr><th align=left>Ilya Kozhevnikov</th><td><u>&lt;ilya@ef.unn.ru&gt;</u></td></tr>"
	"<tr><td></td><td>Windows binaries and Registry stuff</td></tr>"
	"<tr><th align=left>Wolfgang Glas</th><td><u>&lt;wolfgang.glas@ev-i.at&gt;</u></td></tr>"
	"<tr><td></td><td>SPKAC support and Testing</td></tr>"
	"</table><hr><center><u><b>General support</b></u></center>"
	"<p><b>Mark Foster</b> <u>&lt;mark@foster.cc&gt;</u>";
	
	about->setCaption(tr(XCA_TITLE));
	about->image->setPixmap( *keyImg );
	about->image1->setPixmap( *certImg );
	about->textbox->setText(cont);
	about->exec();
}

void MainWindow::help()
{
	Help_UI *h = new Help_UI(this, 0, true );
	h->setCaption(tr(XCA_TITLE));
	h->textbox->mimeSourceFactory()->setFilePath(getPrefix());
	h->textbox->setSource("xca.html");
	h->exec();
}
		
