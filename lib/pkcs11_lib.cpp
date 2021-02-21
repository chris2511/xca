/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2009 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "pkcs11.h"
#include "pk11_attribute.h"
#include "exception.h"
#include "db_base.h"
#include "func.h"
#include "pass_info.h"

#include <openssl/rand.h>
#include <QMessageBox>
#include <QTextCodec>
#include <ltdl.h>
#include "ui_SelectToken.h"

QByteArray find_filecodec(const QString &file)
{
#if defined(Q_OS_WIN32)
	QList<QByteArray> codecs = QTextCodec::availableCodecs();
	QString fil = nativeSeparator(file);

	foreach(QByteArray codec, QTextCodec::availableCodecs())
	{
		auto tc = QTextCodec::codecForName(codec);
		bool can = tc->canEncode(file);
		int fd = -1;
		QByteArray fn;
		if (can) {
			fn = tc->fromUnicode(fil);
			fd = open(fn, O_RDONLY);
			if (fd != -1)
				close(fd);
		}
		qDebug() << "TestCodec" << codec << can << fn << fd;
		if (fd != -1)
			return fn;
	}
	return fil.toLocal8Bit();
#else
	return file.toUtf8();
#endif
}

pkcs11_lib::pkcs11_lib(const QString &f)
{
	CK_RV (*c_get_function_list)(CK_FUNCTION_LIST_PTR_PTR);
	CK_RV rv;
	file = name2File(f, &enabled);
	p11 = NULL;
	dl_handle = NULL;

	if (!enabled)
		return;

	lt_dlinit();

	try {
		/* PKCS11 libs without path should be looked up locally */
		QString realfile = file;
		if (!realfile.contains("/") && !realfile.isEmpty())
			realfile.prepend("./");
		QByteArray localfn = find_filecodec(realfile);
		if (localfn.isEmpty())
			throw errorEx(QObject::tr("Invalid filename: %1").arg(file));
		dl_handle = lt_dlopen(localfn);
		if (dl_handle == NULL)
			throw errorEx(QObject::tr("Failed to open PKCS11 library: %1: %2").arg(file).arg(lt_dlerror()));

		/* Get the list of function pointers */
		c_get_function_list = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR))
				lt_dlsym(dl_handle, "C_GetFunctionList");
		if (!c_get_function_list)
			throw errorEx(QObject::tr("This does not look like a PKCS#11 library. Symbol 'C_GetFunctionList' not found."));

		qDebug() << "Trying to load PKCS#11 provider" << file;
		rv = c_get_function_list(&p11);
		if (rv != CKR_OK)
			pk11error("C_GetFunctionList", rv);

		CALL_P11_C(this, C_Initialize, NULL);
		if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)
			pk11error("C_Initialize", rv);

		qDebug() << "Successfully loaded PKCS#11 provider" << file;
	} catch (errorEx &err) {
		load_error = err.getString();
		WAITCURSOR_END;
		if (p11)
			p11 = NULL;
		if (dl_handle)
			lt_dlclose(dl_handle);
		lt_dlexit();
		qDebug() << "Failed to load PKCS#11 provider" << file;
	}
}

pkcs11_lib::~pkcs11_lib()
{
	CK_RV rv;
	(void)rv;
	if (!isLoaded())
		return;
	qDebug() << "Unloading PKCS#11 provider" << file;
	CALL_P11_C(this, C_Finalize, NULL);
	lt_dlclose(dl_handle);
	lt_dlexit();
	qDebug() << "Unloaded PKCS#11 provider" << file;
}

QList<unsigned long> pkcs11_lib::getSlotList()
{
	CK_RV rv;
	CK_SLOT_ID *p11_slots = NULL;
	QList<unsigned long> sl;
	unsigned long i, num_slots = 0;

	if (!isLoaded())
		return sl;

	/* This one helps to avoid errors.
	 * Fist time it fails, 2nd time it works */
	CALL_P11_C(this, C_GetSlotList, CK_TRUE, p11_slots, &num_slots);
	while (1) {
		CALL_P11_C(this, C_GetSlotList, CK_TRUE, p11_slots, &num_slots);
		if (rv != CKR_OK && rv != CKR_BUFFER_TOO_SMALL)
			pk11error("C_GetSlotList", rv);

		if (num_slots == 0)
			break;
		if ((rv == CKR_OK) && p11_slots)
			break;

		p11_slots = (CK_SLOT_ID *)realloc(p11_slots,
					num_slots *sizeof(CK_SLOT_ID));
		check_oom(p11_slots);
	}

	for (i=0; i<num_slots; i++) {
		sl << p11_slots[i];
	}
	if (p11_slots)
		free(p11_slots);
	return sl;
}

QString pkcs11_lib::driverInfo() const
{
	CK_INFO info;
	CK_RV rv;

	if (!enabled)
		return QObject::tr("Disabled");

	if (!isLoaded()) {
		if (load_error.isEmpty())
			return QObject::tr("Library loading failed");
		return load_error;
	}

	CALL_P11_C(this, C_GetInfo, &info);
	if (rv != CKR_OK) {
		pk11error("C_GetInfo", rv);
	}

	return QString(
	"Cryptoki version: %1.%2\n"
	"Manufacturer: %3\n"
	"Library: %4 (%5.%6)\n").
	arg(info.cryptokiVersion.major).arg(info.cryptokiVersion.minor).
	arg(UTF8QSTRING(info.manufacturerID, 32)).
	arg(UTF8QSTRING(info.libraryDescription, 32)).
	arg(info.libraryVersion.major).arg(info.libraryVersion.minor);
}

QString pkcs11_lib::name2File(const QString &name, bool *enabled)
{
	QString libname = name;
	QString ena = name.mid(0,2);
	if (enabled)
		*enabled = true;
	if (ena == "0:" || ena == "1:") {
		libname = name.mid(2);
		if (enabled)
			*enabled = ena[0] != '0';
	}
	return relativePath(libname);
}

pkcs11_lib *pkcs11_lib_list::add_lib(const QString &fname)
{
	int idx = -1;
	pkcs11_lib *l = NULL;

	if (fname.isEmpty())
		return NULL;

	for (int i = 0; i < libs.size(); i++) {
		l = libs[i];
		if (!l->isLib(fname))
			continue;
		if (model_data.contains(i))
			return l;
		idx = i;
		break;
	}
	if (idx == -1) {
		pkcs11_lib *l = new pkcs11_lib(fname);
		idx = libs.size();
		libs << l;
	}
	beginInsertRows(QModelIndex(), model_data.size(), model_data.size());
	model_data << idx;
	endInsertRows();
	return l;
}

void pkcs11_lib_list::load(const QString &list)
{
	beginResetModel();
	QString orig = getPkcs11Provider();
	QList<pkcs11_lib*> newlist;
	foreach(QString name, list.split('\n')) {
		pkcs11_lib *newitem = NULL;
		name = name.trimmed();
		if (name.isEmpty())
			continue;
		for (int i = 0; i < libs.size(); i++) {
			if (name == libs[i]->toData()) {
				newitem = libs.takeAt(i);
				break;
			}
		}
		if (!newitem) {
			newitem = new pkcs11_lib(name);
		}
		newlist << newitem;
	}
	qDeleteAll(libs);
	libs = newlist;
	model_data.clear();
	for (int i = 0; i < libs.size(); i++)
		model_data << i;

	endResetModel();
	qDebug() << "Libs reloaded from" << orig << "to" << getPkcs11Provider();
}

slotidList pkcs11_lib_list::getSlotList() const
{
	slotidList list;
	QString ex;
	bool success = false;

	foreach(pkcs11_lib *l, libs) {
		if (!l->isLoaded())
			continue;
		try {
			QList<unsigned long> realids;
			realids = l->getSlotList();
			foreach(int id, realids)
				list << slotid(l, id);
			success = true;
		} catch (errorEx &e) {
			ex = e.getString();
		}
	}
	if (success || ex.isEmpty())
		return list;
	throw errorEx(ex);
}

QString pkcs11_lib_list::getPkcs11Provider() const
{
	QStringList prov;
	foreach(int i, model_data)
		prov << libs[i]->toData();
	return prov.size() == 0 ? QString() : prov.join("\n");
}

void pkcs11_lib_list::remove_libs()
{
	if (libs.isEmpty() == 0)
		return;
	beginRemoveRows(QModelIndex(), 0, libs.size() -1);
	qDeleteAll(libs);
	libs.clear();
	model_data.clear();
	endRemoveRows();
}

bool pkcs11_lib_list::loaded() const
{
	foreach(pkcs11_lib *l, libs)
		if (l->isLoaded())
			return true;
	return false;
}

int pkcs11_lib_list::rowCount(const QModelIndex &) const
{
	return model_data.size();
}

pkcs11_lib *pkcs11_lib_list::libByModelIndex(const QModelIndex &index) const
{
	if (!index.isValid())
		return NULL;
	int idx = model_data[index.row()];
	return (idx >= 0 && idx < libs.size()) ? libs[idx] : NULL;
}

QVariant pkcs11_lib_list::data(const QModelIndex &index, int role) const
{
	pkcs11_lib *l = libByModelIndex(index);
	if (!l)
		return QVariant();

	QString pixmap;

	switch (role) {
	case Qt::DisplayRole:
		return QVariant(nativeSeparator(l->filename()));
	case Qt::DecorationRole:
		pixmap = l->pixmap();
		if (pixmap.isEmpty()) {
			QPixmap p(QSize(20, 20));
			p.fill(Qt::transparent);
			return QVariant(p);
		}
		return QVariant(QPixmap(pixmap));
	case Qt::ToolTipRole:
		return QVariant(l->driverInfo().trimmed());
	case Qt::CheckStateRole:
		return l->checked();
	}
	return QVariant();
}

QMap<int, QVariant> pkcs11_lib_list::itemData(const QModelIndex &index) const
{
	QMap<int, QVariant> map;
	if (index.isValid())
		map[Qt::UserRole] = QVariant(model_data[index.row()]);
	return map;
}

bool pkcs11_lib_list::setItemData(const QModelIndex &index,
				const QMap<int, QVariant> &roles)
{
	if (index.isValid() && roles[Qt::UserRole].isValid()) {
		model_data[index.row()] = roles[Qt::UserRole].toInt();
		return true;
	}
	return false;
}

bool pkcs11_lib_list::setData(const QModelIndex &index,
				const QVariant &value, int role)
{
	pkcs11_lib *l = libByModelIndex(index);
	if (!l || role != Qt::CheckStateRole)
		return false;

	if (value == l->checked()) {
		/* No changes */
		return true;
	}
	QString file = l->toData(value == Qt::Checked);

	delete l;
	int idx = model_data[index.row()];
	libs[idx] = new pkcs11_lib(file);

	emit dataChanged(index, index);
	return true;
}

Qt::ItemFlags pkcs11_lib_list::flags(const QModelIndex & index) const
{
	if (index.isValid())
		return Qt::ItemIsEnabled | Qt::ItemIsSelectable |
			Qt::ItemIsDragEnabled | Qt::ItemIsUserCheckable;
	return QAbstractListModel::flags(index) | Qt::ItemIsDropEnabled;
}

Qt::DropActions pkcs11_lib_list::supportedDropActions() const
{
	return Qt::MoveAction;
}

bool pkcs11_lib_list::removeRows(int row, int count, const QModelIndex &parent)
{
	if (parent.isValid() || row < 0 || count == 0 ||
	    row + count > model_data.size())
		return false;

	beginRemoveRows(parent, row, row + count - 1);
	while (count-- > 0 && row < model_data.size())
		model_data.removeAt(row);
	endRemoveRows();
	return true;
}

bool pkcs11_lib_list::insertRows(int row, int count, const QModelIndex &parent)
{
	if (parent.isValid() || row < 0 || count == 0)
		return false;

	beginInsertRows(parent, row, row +count -1);
	for (int i = 0; i < count; i++)
		model_data.insert(row +i, 0);
	endInsertRows();
	return true;
}

const char *pk11errorString(unsigned long rv)
{
#define PK11_ERR(x) case x : return #x;

	switch (rv) {
		PK11_ERR(CKR_OK)
		PK11_ERR(CKR_CANCEL)
		PK11_ERR(CKR_HOST_MEMORY)
		PK11_ERR(CKR_SLOT_ID_INVALID)
		PK11_ERR(CKR_GENERAL_ERROR)
		PK11_ERR(CKR_FUNCTION_FAILED)
		PK11_ERR(CKR_ARGUMENTS_BAD)
		PK11_ERR(CKR_NO_EVENT)
		PK11_ERR(CKR_NEED_TO_CREATE_THREADS)
		PK11_ERR(CKR_CANT_LOCK)
		PK11_ERR(CKR_ATTRIBUTE_READ_ONLY)
		PK11_ERR(CKR_ATTRIBUTE_SENSITIVE)
		PK11_ERR(CKR_ATTRIBUTE_TYPE_INVALID)
		PK11_ERR(CKR_ATTRIBUTE_VALUE_INVALID)
		PK11_ERR(CKR_DATA_INVALID)
		PK11_ERR(CKR_DATA_LEN_RANGE)
		PK11_ERR(CKR_DEVICE_ERROR)
		PK11_ERR(CKR_DEVICE_MEMORY)
		PK11_ERR(CKR_DEVICE_REMOVED)
		PK11_ERR(CKR_ENCRYPTED_DATA_INVALID)
		PK11_ERR(CKR_ENCRYPTED_DATA_LEN_RANGE)
		PK11_ERR(CKR_FUNCTION_CANCELED)
		PK11_ERR(CKR_FUNCTION_NOT_PARALLEL)
		PK11_ERR(CKR_FUNCTION_NOT_SUPPORTED)
		PK11_ERR(CKR_KEY_HANDLE_INVALID)
		PK11_ERR(CKR_KEY_SIZE_RANGE)
		PK11_ERR(CKR_KEY_TYPE_INCONSISTENT)
		PK11_ERR(CKR_KEY_NOT_NEEDED)
		PK11_ERR(CKR_KEY_CHANGED)
		PK11_ERR(CKR_KEY_NEEDED)
		PK11_ERR(CKR_KEY_INDIGESTIBLE)
		PK11_ERR(CKR_KEY_FUNCTION_NOT_PERMITTED)
		PK11_ERR(CKR_KEY_NOT_WRAPPABLE)
		PK11_ERR(CKR_KEY_UNEXTRACTABLE)
		PK11_ERR(CKR_MECHANISM_INVALID)
		PK11_ERR(CKR_MECHANISM_PARAM_INVALID)
		PK11_ERR(CKR_OBJECT_HANDLE_INVALID)
		PK11_ERR(CKR_OPERATION_ACTIVE)
		PK11_ERR(CKR_OPERATION_NOT_INITIALIZED)
		PK11_ERR(CKR_PIN_INCORRECT)
		PK11_ERR(CKR_PIN_INVALID)
		PK11_ERR(CKR_PIN_LEN_RANGE)
		PK11_ERR(CKR_PIN_EXPIRED)
		PK11_ERR(CKR_PIN_LOCKED)
		PK11_ERR(CKR_SESSION_CLOSED)
		PK11_ERR(CKR_SESSION_COUNT)
		PK11_ERR(CKR_SESSION_HANDLE_INVALID)
		PK11_ERR(CKR_SESSION_PARALLEL_NOT_SUPPORTED)
		PK11_ERR(CKR_SESSION_READ_ONLY)
		PK11_ERR(CKR_SESSION_EXISTS)
		PK11_ERR(CKR_SESSION_READ_ONLY_EXISTS)
		PK11_ERR(CKR_SESSION_READ_WRITE_SO_EXISTS)
		PK11_ERR(CKR_SIGNATURE_INVALID)
		PK11_ERR(CKR_SIGNATURE_LEN_RANGE)
		PK11_ERR(CKR_TEMPLATE_INCOMPLETE)
		PK11_ERR(CKR_TEMPLATE_INCONSISTENT)
		PK11_ERR(CKR_TOKEN_NOT_PRESENT)
		PK11_ERR(CKR_TOKEN_NOT_RECOGNIZED)
		PK11_ERR(CKR_TOKEN_WRITE_PROTECTED)
		PK11_ERR(CKR_UNWRAPPING_KEY_HANDLE_INVALID)
		PK11_ERR(CKR_UNWRAPPING_KEY_SIZE_RANGE)
		PK11_ERR(CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT)
		PK11_ERR(CKR_USER_ALREADY_LOGGED_IN)
		PK11_ERR(CKR_USER_NOT_LOGGED_IN)
		PK11_ERR(CKR_USER_PIN_NOT_INITIALIZED)
		PK11_ERR(CKR_USER_TYPE_INVALID)
		PK11_ERR(CKR_USER_ANOTHER_ALREADY_LOGGED_IN)
		PK11_ERR(CKR_USER_TOO_MANY_TYPES)
		PK11_ERR(CKR_WRAPPED_KEY_INVALID)
		PK11_ERR(CKR_WRAPPED_KEY_LEN_RANGE)
		PK11_ERR(CKR_WRAPPING_KEY_HANDLE_INVALID)
		PK11_ERR(CKR_WRAPPING_KEY_SIZE_RANGE)
		PK11_ERR(CKR_WRAPPING_KEY_TYPE_INCONSISTENT)
		PK11_ERR(CKR_RANDOM_SEED_NOT_SUPPORTED)
		PK11_ERR(CKR_RANDOM_NO_RNG)
		PK11_ERR(CKR_DOMAIN_PARAMS_INVALID)
		PK11_ERR(CKR_BUFFER_TOO_SMALL)
		PK11_ERR(CKR_SAVED_STATE_INVALID)
		PK11_ERR(CKR_INFORMATION_SENSITIVE)
		PK11_ERR(CKR_STATE_UNSAVEABLE)
		PK11_ERR(CKR_CRYPTOKI_NOT_INITIALIZED)
		PK11_ERR(CKR_CRYPTOKI_ALREADY_INITIALIZED)
		PK11_ERR(CKR_MUTEX_BAD)
		PK11_ERR(CKR_MUTEX_NOT_LOCKED)
		PK11_ERR(CKR_VENDOR_DEFINED)
	}
	return "unknown PKCS11 error";
}

void pk11error(const QString &func, int rv)
{
	WAITCURSOR_END
	errorEx err(QObject::tr("PKCS#11 function '%1' failed: %2").arg(func).
		arg(pk11errorString(rv)));
	throw err;
}

void pk11error(const slotid &slot, const QString &func, int rv)
{
	WAITCURSOR_END
	errorEx err(QObject::tr("PKCS#11 function '%1' failed: %2\nIn library %3\n%4").
		arg(func).arg(pk11errorString(rv)).arg(slot.lib->filename()).
		arg(slot.lib->driverInfo()));
	throw err;
}
