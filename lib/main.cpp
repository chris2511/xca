/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <signal.h>

#include <QDir>
#include <QDebug>

#include "widgets/MainWindow.h"
#include "ui_MainWindow.h"
#include "widgets/XcaApplication.h"
#include "func.h"
#include "entropy.h"
#include "settings.h"
#include "pki_multi.h"
#include "arguments.h"
#include "pki_export.h"
#include "debug_info.h"
#if defined(Q_OS_WIN32)
//For the segfault handler
#include <windows.h>
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
#include <openssl/provider.h>
#endif
#include <openssl/ui.h>

#include <QTextStream>

char segv_data[1024];

#if defined(Q_OS_WIN32)
static LONG CALLBACK w32_segfault(LPEXCEPTION_POINTERS e)
{
	if (e->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
		if (segv_data[0]) {
			XCA_WARN(QString(segv_data));
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
		XCA_WARN(QString(segv_data));
	abort();
}
#endif

int uiwriter(UI *, UI_STRING *uis)
{
	qWarning() << "ui-writer called:" << UI_get0_action_string(uis)
			<< UI_get0_output_string(uis);
	return 1;
}

int read_cmdline(int, char **, bool, pki_multi **);

int main(int argc, char *argv[])
{
	const char *xca_special = getenv("XCA_ARGUMENTS");
	if (xca_special && *xca_special) {
		puts(CCHAR(arguments::doc(xca_special)));
		return 0;
	}
	debug_info::init();

#if defined(Q_OS_WIN32)
	// If no style provided externally
	if (!QApplication::style())
		QApplication::setStyle("Fusion");

	AttachConsole(-1);

	int wargc;
	wchar_t **wargv = CommandLineToArgvW(GetCommandLineW(), &wargc);
	if (wargv && wargc) {
		int i;
		if (argc != wargc)
			qWarning() << "argc != wargc" << argc << wargc;
		if (argc > wargc)
			argc = wargc;
		qDebug() << "wargc" << wargc << argc;
		for (i = 0; i < argc; i++) {
			QString s = QString::fromWCharArray(wargv[i]);
			QByteArray ba = s.toUtf8();
			argv[i] = strdup(ba.constData());
			qDebug() << "wargv" << i << argv[i] << s;
		}
		argv[i] = NULL;
		LocalFree(wargv);
	}
	SetUnhandledExceptionFilter(w32_segfault);
#else
	signal(SIGSEGV, segv_handler_gui);
#endif

	bool console_only = arguments::is_console(argc, argv);
	XcaApplication *gui = nullptr;
	QCoreApplication *coreApp = nullptr;

#if !defined(Q_OS_WIN32)
	if (console_only) {
		coreApp = new QCoreApplication(argc, argv);
	} else
#endif
	{
		/* On windows, always instantiate a GUI app */
		coreApp = gui = new XcaApplication(argc, argv);
		is_gui_app = true;
	}

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
	{
		QString path;
#if defined(Q_OS_WIN32)
		path = QCoreApplication::applicationDirPath();
#elif defined(Q_OS_MACOS)
		path = QCoreApplication::applicationDirPath() + "/../PlugIns";
#endif
		if (!path.isEmpty()) {
			OSSL_PROVIDER_set_default_search_path(NULL, path.toUtf8().data());
			qDebug() << "OSSL_PROVIDER_set_default_search_path" << path;
		}
	}
	MainWindow::legacy_loaded = OSSL_PROVIDER_try_load(0, "legacy", 1);
	if (MainWindow::legacy_loaded)
		qDebug() << "Legacy provider loaded";
	else
		qWarning() << "Legacy provider NOT loaded";
#endif
	QSharedPointer<UI_METHOD> uimeth(
			UI_create_method("xca-method"), UI_destroy_method);
	UI_method_set_writer(uimeth.data(), uiwriter);
	UI_set_default_method(uimeth.data());

	coreApp->setApplicationName("de.hohnstaedt.xca");
	coreApp->setOrganizationDomain("hohnstaedt.de");
	coreApp->setApplicationVersion(XCA_VERSION);
	xcaWarning::setGui(new xcaWarningCore());

	migrateOldPaths();

	pki_multi *cmdline_items = nullptr;
	Entropy entropy;
	Settings.clear();
	try {
		initOIDs();
	} catch (errorEx &e) {
		XCA_ERROR(e);
	}

	int ret = EXIT_SUCCESS;

	for (int i=0; i < argc; i++)
		qDebug() << "wargv" << argc << i << argv[i];
	try {
		if (gui && !console_only) {
			mainwin = new MainWindow();
			gui->setMainwin(mainwin);
			read_cmdline(argc, argv, console_only, &cmdline_items);
			if (cmdline_items)
				qDebug() << "CMD Items" << cmdline_items->get().size();
			if (cmdline_items && cmdline_items->get().size() > 0) {
				mainwin->importMulti(cmdline_items, 1);
				cmdline_items = nullptr;
			} else {
				delete cmdline_items;
				enum open_result r = open_abort;

				if (!Database.isOpen())
					r = mainwin->init_database(QString());
				else
					r = mainwin->setup_open_database();

				qDebug() << "PWret" << r << pw_cancel << pw_ok;
				if (r != pw_exit) {
					mainwin->show();
					gui->exec();
				}
			}
		} else {
			ret = read_cmdline(argc, argv, console_only, &cmdline_items);
			delete cmdline_items;
		}
	} catch (errorEx &ex) {
		XCA_ERROR(ex);
	} catch (enum open_result r) {
		qDebug() << "DB open failed: " << r;
	}
	Database.close();

	delete mainwin;
	delete gui;
	pki_export::free_elements();
#if defined(Q_OS_WIN32)
	FreeConsole();
#endif
	return ret;
}
