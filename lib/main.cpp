/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <signal.h>
#include <QtGui/QApplication>
#include <QtCore/QTranslator>
#include <QtCore/QTextCodec>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <openssl/rand.h>
#include "widgets/MainWindow.h"
#include "lib/func.h"
#include "lib/db.h"
#include "lib/main.h"
#ifdef WIN32
#include <windows.h>
#endif

QLocale XCA_application::lang = QLocale::system();
QFont XCA_application::tableFont;

void XCA_application::setMainwin(MainWindow *m)
{
	mainw = m;
}

XCA_application::XCA_application(int &argc, char *argv[])
	:QApplication(argc, argv)
{
	qtTr = NULL;
	xcaTr = NULL;
	mainw = NULL;

	QFile file(getUserSettingsDir() +
			QDir::separator() + "defaultlang");

	if (file.open(QIODevice::ReadOnly)) {
		lang = QLocale(QString(file.read(128)));
	}
	setupLanguage(lang);
#ifdef Q_WS_MAC
	QStringList libp = libraryPaths();
	libp.prepend(applicationDirPath() + "/../Plugins");
	setLibraryPaths(libp);
#endif

	tableFont = QFont("Courier", QApplication::font().pointSize()
#if defined(_WIN32) || defined(USE_CYGWIN)
	+1
#else
	+2
#endif
	);
	timer.start();
	installEventFilter(this);
}

void XCA_application::setupLanguage(QLocale l)
{
	QStringList dirs;

	lang = l;
	if (qtTr) {
		removeTranslator(qtTr);
		delete qtTr;
	}
	qtTr = new XcaTranslator();
	if (xcaTr) {
		removeTranslator(xcaTr);
		delete xcaTr;
	}
	xcaTr = new XcaTranslator();
	dirs
#ifdef XCA_DEFAULT_QT_TRANSLATE
		<< XCA_DEFAULT_QT_TRANSLATE
#endif
		<< getPrefix()
#ifndef WIN32
		<< "/usr/local/share/qt4/translations/"
		<< "/usr/share/qt4/translations/"
		<< "/usr/share/qt/translations/"
#endif
		;

	foreach(QString dir, dirs) {
		if (qtTr->load(lang, "qt", dir)) {
			break;
		}
	}
	xcaTr->load(lang, "xca", getPrefix());

	installTranslator(qtTr);
	installTranslator(xcaTr);
}

void XCA_application::switchLanguage(QAction* a)
{
	QLocale lang = a->data().toLocale();
	setupLanguage(lang);

	QString dir = getUserSettingsDir();
	QFile file(dir +QDir::separator() +"defaultlang");

	if (lang == QLocale::system()) {
		file.remove();
		return;
	}

	QDir d;
	d.mkpath(dir);
	if (file.open(QIODevice::WriteOnly)) {
		file.write(lang.name().toUtf8());
	}
}

#define rand_buf_siz (sizeof(rand_buf)/sizeof(rand_buf[0]))
unsigned char XCA_application::rand_buf[128];
unsigned XCA_application::rand_pos;

void XCA_application::add_entropy(int rand)
{
	rand_buf[rand_pos++ % rand_buf_siz] = rand & 0xff;
}

void XCA_application::seed_rng()
{
	if (rand_pos > rand_buf_siz)
		rand_pos = rand_buf_siz;

	RAND_seed(rand_buf, rand_pos);
	rand_pos = 0;
}

bool XCA_application::eventFilter(QObject *watched, QEvent *ev)
{
	static int mctr;
	QMouseEvent *me;
	QStringList l;
	int key;

	switch (ev->type()) {
	case QEvent::FileOpen:
		l << static_cast<QFileOpenEvent *>(ev)->file();
		mainw->openURLs(l);
		return true;
	case QEvent::MouseMove:
	case QEvent::NonClientAreaMouseMove:
		if (mctr++ > 16) {
			me = static_cast<QMouseEvent *>(ev);
			add_entropy(me->globalX());
			add_entropy(me->globalY());
			mctr = 0;
		}
		break;
	case QEvent::KeyPress:
		key = static_cast<QKeyEvent *>(ev)->key();
		if (key < 0x100) {
			add_entropy(key ^ timer.elapsed());
			timer.restart();
		}
		break;
	default:
		break;
	}
	return false;
}

XCA_application::~XCA_application()
{
}

int usage_extract(char *argv[])
{
	fprintf(stderr,
		"Usage: %s %s <database> <type> <name>\n"
		"  database : the filename of the database\n"
		"  type     : one of 'crl' 'cert' 'req'\n",
				argv[0], argv[1]);
	return 1;
}
int main_extract(int argc, char *argv[])
{
	QFile dbfile;
	enum pki_type pkitype = none;
	unsigned char *p;
        db_header_t head;
	QString pkiname, name, fname;
	pki_base *pki;
	BIO *b;

	if (argc != 5) {
		fprintf(stderr, "Wrong number of arguments\n");
		return usage_extract(argv);
	}
	fname = filename2QString(argv[2]);
        dbfile.setFileName(fname);
	if (!dbfile.exists()) {
		fprintf(stderr, "Database '%s' not found\n",argv[2]);
		return usage_extract(argv);
	}
	pkiname = argv[3];
	if (pkiname == "cert")
		pkitype = x509;
	else if (pkiname == "crl")
		pkitype = revokation;
	else if (pkiname == "req")
		pkitype = x509_req;
	else {
		fprintf(stderr, "Invalid type: '%s'\n", argv[3]);
		return usage_extract(argv);
	}
	db mydb(fname);
	name = argv[4];
	if (mydb.find(pkitype, name)) {
		fprintf(stderr, "Item of type %s with name '%s' not found.\n",
			argv[3], argv[4]);
		return usage_extract(argv);
	}
	p = mydb.load(&head);
	if (!p) {
		fprintf(stderr, "Load was empty !");
		return usage_extract(argv);
	}
	name = QString::fromUtf8(head.name);
	switch (pkitype) {
	case x509: pki = new pki_x509(name); break;
	case x509_req: pki = new pki_x509req(name); break;
	case revokation: pki = new pki_crl(name); break;
	default: return usage_extract(argv);
	}
	if (pki->getVersion() < head.version) {
		fprintf(stderr, "Item[%s]: Version %d > known version: %d",
			head.name, head.version, pki->getVersion());
		free(p);
		delete pki;
		return usage_extract(argv);
	}
	pki->setIntName(QString::fromUtf8(head.name));
	try {
		pki->fromData(p, &head);
	} catch (errorEx &err) {
		fprintf(stderr, "Failed to load item from database: %s",
			CCHAR(err.getString()));
	}
	b = BIO_new_fp(stdout, BIO_NOCLOSE);
	pki->pem(b);
	BIO_free(b);
	return 0;
}

char segv_data[1024];

#ifdef WIN32
static LONG CALLBACK w32_segfault(LPEXCEPTION_POINTERS e)
{
	if (e->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
		if (segv_data[0]) {
			XCA_WARN(segv_data);
			abort();
		}
		return EXCEPTION_CONTINUE_EXECUTION;
	} else
		return EXCEPTION_CONTINUE_SEARCH;
}
#else
static void segv_handler_gui(int)
{
	if (segv_data[0])
		XCA_WARN(segv_data);
	abort();
}
#endif

int main( int argc, char *argv[] )
{
	int ret = 0, pkictr;
	MainWindow *mw;

#ifdef WIN32
	SetUnhandledExceptionFilter(w32_segfault);
	RAND_screen();
#else
	signal(SIGSEGV, segv_handler_gui);

	if (QFile::exists("/dev/random"))
		RAND_load_file("/dev/random", 64);
	if (QFile::exists("/dev/hwrng"))
		RAND_load_file("/dev/hwrng", 64);
#endif

	if (QString(argv[1]) == "extract") {
		return main_extract(argc, argv);
	}
	XCA_application a(argc, argv);
	mw = new MainWindow(NULL);
	try {
		a.setMainwin(mw);
		mw->read_cmdline();
		if (mw->exitApp == 0) {
			mw->load_history();
			if (mw->open_default_db() != 2) {
				mw->show();
				ret = a.exec();
			 }
		}
	} catch (errorEx &ex) {
		mw->Error(ex);
	}

	delete mw;
	pkictr =  pki_base::get_pki_counter();
	if (pkictr)
		fprintf(stderr, "PKI Counter (%d)\n", pkictr);

	return ret;
}
