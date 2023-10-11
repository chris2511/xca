/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "func.h"
#include "exception.h"
#include "asn1time.h"
#include "settings.h"
#include "XcaWarningCore.h"
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#ifdef Q_OS_MACOS
#include <IOKit/IOKitLib.h>
#define I18N_DIR ""
#else
#define I18N_DIR "i18n/"
#endif
#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QStringList>
#include <QCoreApplication>
#include <QDebug>
#include <QRegularExpression>

#if defined(Q_OS_WIN32)
#include <shlobj.h>
#include <conio.h>
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x04
#endif
#else
#include <termios.h>
#include <unistd.h>
#define getch() getchar()
#endif

int console_write(FILE *fp, const QByteArray &ba)
{
	if (ba.size() == 0)
		return 0;
#if defined(Q_OS_WIN32)
	HANDLE con = GetStdHandle(fp == stderr ? STD_ERROR_HANDLE :
						 STD_OUTPUT_HANDLE);
	if (con != INVALID_HANDLE_VALUE) {
		QString string = QString::fromUtf8(ba);
		WriteConsoleW(con, string.utf16(), string.size(), NULL, NULL);
		//return 0;
	}
#endif
	fputs(ba.constData(), fp);
	fflush(fp);
	return 0;
}

Passwd readPass()
{
	Passwd pw;
#if !defined(Q_OS_WIN32)
	struct termios t, back;
	if (tcgetattr(0, &t))
		throw errorEx(strerror(errno));
	back = t;
	t.c_lflag &= ~(ECHO | ICANON);
	if (tcsetattr(0, TCSAFLUSH, &t))
		throw errorEx(strerror(errno));
#else
	qFatal("Password input not supported");
#endif
	while(1) {
		char p = getch();
		if (p == '\n' || p == '\r')
			break;
		if (p == 0x7f)
			pw.chop(1);
		else
			pw += p;
	}
	fputc('\n', stdout);
#if !defined(Q_OS_WIN32)
	if (tcsetattr(0, TCSAFLUSH, &back))
		throw errorEx(strerror(errno));
#endif
	return pw;
}

#if defined(Q_OS_WIN32)
static QString registryInstallDir()
{
	QString dir;
	wchar_t inst_dir[2048] = L"";
	ULONG len = sizeof inst_dir;

	if (RegGetValueW(HKEY_LOCAL_MACHINE, L"Software\\xca",
			L"Install_Dir64", RRF_RT_REG_SZ, NULL,
			inst_dir, &len) != ERROR_SUCCESS)
		return dir;

	/* "len" is in octets */
	len /= sizeof inst_dir[0];
	/* "len" includes the trailing \0\0 */
	dir = QString::fromWCharArray(inst_dir, len -1);
	return QFileInfo(dir).canonicalFilePath();
}
#endif

int portable_app()
{
	static int portable = -1;
	QString f1, f2;
	if (portable == -1) {
#if defined(Q_OS_WIN32)
		f1 = registryInstallDir();
		f2 = QCoreApplication::applicationDirPath();
		/* f1 == f2 Registry entry of install dir exists and matches
		 * path of this xca.exe -> Installed. Not the portable app
		 */
		portable = f1 == f2 ? 0 : 1;
		qDebug() << "Portable:" << f1 << " != " << f2;
#else
		const char *p = getenv("XCA_PORTABLE");
		portable = p && *p;
#endif
	}
	return portable;
}

#if defined(Q_OS_WIN32)
static QString specialFolder(int csidl)
{
	LPITEMIDLIST pidl = NULL;
	wchar_t buf[MAX_PATH] = L"";

	if (SUCCEEDED(SHGetSpecialFolderLocation(NULL, csidl, &pidl)))
		SHGetPathFromIDListW(pidl, buf);

	QString f = QString::fromWCharArray(buf);
	qDebug() << "Special Folder" << csidl << f;
	return QFileInfo(f).canonicalFilePath();
}
#endif

const QString getHomeDir()
{
	return portable_app() ? QCoreApplication::applicationDirPath() :
				QStandardPaths::writableLocation(
					QStandardPaths::DocumentsLocation);
}

/* For portable APP remove leading file name if it is
 * the app directory.
 */
QString relativePath(QString path)
{
	QFileInfo fi_path(path);
	QFileInfo fi_home(getHomeDir());

	QString prefix = fi_home.absoluteFilePath();
	path = fi_path.absoluteFilePath();

	if (portable_app()) {
		if (path.startsWith(prefix))
			path = path.mid(prefix.length()+1);
	}
	return path;
}

const QString getLibDir()
{
#if defined(Q_OS_WIN32)
	return specialFolder(CSIDL_SYSTEM);
#else
	QString ulib = "/usr/lib/";
	QString lib = "/lib/";
	QString multi;
	QString hd = ulib;

	QFile f(ulib + "pkg-config.multiarch");
	if (f.open(QIODevice::ReadOnly)) {
		QTextStream in(&f);
		multi = in.readLine();
		if (!multi.isEmpty())
			multi += "/";
	}
	QStringList dirs; dirs
		<< ulib + multi + "pkcs11/"
		<< lib + multi + "pkcs11/"
		<< ulib + "pkcs11/"
		<< lib + "pkcs11/"
		<< ulib + multi
		<< lib + multi
		<< ulib
		<< lib;
	foreach(QString dir, dirs) {
		if (QDir(dir).exists()) {
			hd = dir;
			break;
		}
	}
	return QFileInfo(hd).canonicalFilePath();
#endif
}

const QString getDocDir()
{
	static QString docdir;

	if (!docdir.isEmpty())
		return docdir;

	QStringList docs;
#ifdef DOCDIR
	docs << QString(DOCDIR);
#endif
	docs += QStandardPaths::standardLocations(QStandardPaths::AppDataLocation);
	foreach (docdir, docs) {
#ifndef Q_OS_MACOS
		docdir += "/html";
#endif
		if (QFileInfo::exists(docdir + "/xca.qhc")) {
			qDebug() << "Detected" << docdir + "/xca.qhc";
			return docdir;
		}
	}
	docdir = QString();
	return docdir;
}

// The intent of this function is to return the proper location for
// user-controlled settings on the current platform
const QString getUserSettingsDir()
{
	static QString dir;

	if (!dir.isEmpty())
		return dir;

	dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);

#if defined(Q_OS_WIN32)
	if (portable_app())
		dir = QCoreApplication::applicationDirPath() + "/settings";

#endif
	if (!QDir().mkpath(dir))
		qCritical("Failed to create Path: '%s'", CCHAR(dir));

	return dir;
}

const QString getI18nDir()
{
	QString qm = QStandardPaths::locate(QStandardPaths::AppDataLocation,
		I18N_DIR "xca_de.qm");
	return QFileInfo(qm).path();
}

void migrateOldPaths()
{
	QString old;
#if defined(Q_OS_UNIX)
	old = QDir::homePath() + "/.xca";

#elif defined(Q_OS_MACOS)
	old = QStandardPaths::writableLocation(
		QStandardPaths::GenericDataLocation) + "/data/" +
		QCoreApplication::applicationName();
#endif
	QDir old_dir(old);
	if (old.isEmpty() || !old_dir.exists())
		return;
	qDebug() << "Old XCA directory exists" << old;
	QString new_dir = getUserSettingsDir() + "/";
	foreach(QString n, QStringList({"dbhistory", "defaultdb",
					"defaultlang", ".rnd"}))
	{
		old_dir.rename(n, new_dir + n);
		qDebug() << "Move file" << old + "/" + n << new_dir + n;
	}
	old_dir.rmdir(old);
}

QString hostId()
{
	static QString id;
	unsigned char guid[100] = "", md[SHA_DIGEST_LENGTH];

	if (!id.isEmpty())
		return id;

#if defined(Q_OS_WIN32)
#define REG_CRYPTO "SOFTWARE\\Microsoft\\Cryptography"
#define REG_GUID "MachineGuid"
	ULONG dwGuid = sizeof guid;
	HKEY hKey;

	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, REG_CRYPTO, 0,
			KEY_READ, &hKey) != ERROR_SUCCESS) {
		XCA_WARN("Registry Key: '" REG_CRYPTO "' not found");
	} else {
		if (RegQueryValueExA(hKey, REG_GUID, NULL, NULL,
			guid, &dwGuid) != ERROR_SUCCESS) {
			XCA_WARN("Registry Key: '" REG_CRYPTO "\\" REG_GUID
				 "' not found");
		}
	}
	RegCloseKey(hKey);

#elif defined(Q_OS_MACOS)
	io_registry_entry_t ioRegistryRoot = IORegistryEntryFromPath(
				kIOMasterPortDefault, "IOService:/");
	CFStringRef uuidCf = (CFStringRef)IORegistryEntryCreateCFProperty(
				ioRegistryRoot, CFSTR(kIOPlatformUUIDKey),
				kCFAllocatorDefault, 0);


	CFStringGetCString(uuidCf, (char*)guid, sizeof guid,
					kCFStringEncodingMacRoman);

	qDebug() << QString::fromCFString(uuidCf) << (char*)guid;

	IOObjectRelease(ioRegistryRoot);
	CFRelease(uuidCf);

#else
	QString mach_id;
	QStringList dirs; dirs <<
			"/etc" << "/var/lib/dbus" << "/var/db/dbus";
	foreach(QString dir, dirs) {
		QFile file(dir + "/machine-id");
		if (file.open(QIODevice::ReadOnly)) {
			QTextStream in(&file);
			mach_id = in.readLine().trimmed();
			file.close();
		}
		qDebug() << "ID:" << mach_id;
		if (!mach_id.isEmpty()) {
			snprintf((char*)guid, sizeof guid, "%s", CCHAR(mach_id));
			break;
		}
	}
	if (mach_id.isEmpty())
		sprintf((char*)guid, "%ld", gethostid());
#endif
	guid[sizeof guid -1] = 0;
	SHA1(guid, strlen((char*)guid), md);
	id = QByteArray((char*)md, (int)sizeof md).toBase64().mid(0, 8);

	qDebug() << "GUID:" << guid << "ID:" << id;

	return id;
}

QString fingerprint(const QByteArray &data, const EVP_MD *type)
{
	return formatHash(Digest(data, type),
			Settings["fp_separator"], Settings["fp_digits"]);
}

void update_workingdir(const QString &file)
{
	Settings["workingdir"] = QFileInfo(file).absolutePath();
}
