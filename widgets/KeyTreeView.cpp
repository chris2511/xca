/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "lib/pki_scard.h"
#include "lib/load_obj.h"
#include "KeyTreeView.h"
#include "MainWindow.h"
#include "KeyDetail.h"
#include "NewKey.h"
#include "ExportDialog.h"
#include "XcaWarning.h"
#include <QAbstractItemView>
#include <QActionGroup>
#include <QMenu>

void KeyTreeView::fillContextMenu(QMenu *menu, QMenu *subExport,
			const QModelIndex &index, QModelIndexList indexes)
{
	QMenu *clipboard;
	QAction *a;
	bool multi = indexes.size() > 1;
	QActionGroup *group = new QActionGroup(menu);

	pki_key *key = db_base::fromIndex<pki_key>(index);
	int exp_type = Settings["KeyFormat"];
	const pki_export *x;

	clipboard = menu->addMenu(tr("Clipboard format"));
	foreach(x, pki_export::select(asym_key, 0)) {
		if (!(x->flags & F_CLIPBOARD))
			continue;
		a = clipboard->addAction(x->desc);
		a->setData(x->id);
		a->setCheckable(true);
		a->setChecked(exp_type == x->id);
		group->addAction(a);
	}

	connect(group, SIGNAL(triggered(QAction*)),
		this, SLOT(clipboardFormat(QAction*)));

	if (indexes.size() == 0 || !key)
		return;

	if (!multi && key && key->isPrivKey() && !key->isToken()) {
		switch (key->getOwnPass()) {
		case pki_key::ptCommon:
			menu->addAction(tr("Change password"), this,
					SLOT(setOwnPass()));
			break;
		case pki_key::ptPrivate:
			menu->addAction(tr("Reset password"), this,
					SLOT(resetOwnPass()));
			break;
		default:
			break;
		}
	}

	if (!pkcs11::libraries.loaded() || multi)
		return;

	if (key->isToken()) {
		menu->addAction(tr("Change PIN"), this,
			SLOT(changePin()));
		menu->addAction(tr("Init PIN with SO PIN (PUK)"), this,
			SLOT(initPin()));
		menu->addAction(tr("Change SO PIN (PUK)"), this,
			SLOT(changeSoPin()));
	} else if (subExport) {
		subExport->addAction(tr("Security token"),
			this, SLOT(toToken()));
	}
}

void KeyTreeView::setOwnPass()
{
	if (!basemodel)
		return;
	try {
		keys()->setOwnPass(currentIndex(), pki_key::ptPrivate);
	} catch (errorEx &err) {
		XCA_ERROR(err);
	}
}

void KeyTreeView::resetOwnPass()
{
	if (!basemodel)
		return;
	try {
		keys()->setOwnPass(currentIndex(), pki_key::ptCommon);
	} catch (errorEx &err) {
		XCA_ERROR(err);
	}
}

void KeyTreeView::changePin()
{
	pki_scard *scard;
	QModelIndex currentIdx = currentIndex();

	if (!currentIdx.isValid())
		return;
	scard = db_base::fromIndex<pki_scard>(currentIdx);
	try {
		if (!scard->isToken()) {
			throw errorEx(tr("This is not a token"));
		}
		scard->changePin();
	} catch (errorEx &err) {
		XCA_ERROR(err);
	}
}

void KeyTreeView::initPin()
{
	pki_scard *scard;
	QModelIndex currentIdx = currentIndex();

	if (!currentIdx.isValid())
		return;
	scard = db_base::fromIndex<pki_scard>(currentIdx);
	try {
		if (!scard->isToken()) {
			throw errorEx(tr("This is not a token"));
		}
		scard->initPin();
	} catch (errorEx &err) {
		XCA_ERROR(err);
	}
}

void KeyTreeView::changeSoPin()
{
	pki_scard *scard;
	QModelIndex currentIdx = currentIndex();

	if (!currentIdx.isValid())
		return;
	scard = db_base::fromIndex<pki_scard>(currentIdx);
	try {
		if (!scard->isToken()) {
			throw errorEx(tr("This is not a token"));
		}
		scard->changeSoPin();
	} catch (errorEx &err) {
		XCA_ERROR(err);
	}
}

void KeyTreeView::toToken()
{
	QModelIndex currentIdx = currentIndex();

	if (!currentIdx.isValid() || !basemodel)
		return;

	pki_key *key = db_base::fromIndex<pki_key>(currentIdx);
	if (!key || !pkcs11::libraries.loaded() || key->isToken())
		return;

	pki_scard *card = NULL;
	try {
		pkcs11 p11;
		slotid slot;

		if (!p11.selectToken(&slot, mainwin))
			return;
		card = new pki_scard(key->getIntName());
		card->store_token(slot, key->decryptKey());
		card->pkiSource = key->pkiSource;
		QString msg = tr("Shall the original key '%1' be replaced by the key on the token?\nThis will delete the key '%1' and make it unexportable").
			arg(key->getIntName());
		if (XCA_YESNO(msg)) {
			keys()->deletePKI(currentIdx);
			keys()->insertPKI(card);
			card = NULL;
		}
	} catch (errorEx &err) {
		XCA_ERROR(err);
	}
	delete card;
}

void KeyTreeView::showPki(pki_base *pki)
{
	pki_key *key = dynamic_cast<pki_key *>(pki);
	KeyDetail::showKey(this, key);
}

void KeyTreeView::newItem() {
	newItem("");
}

void KeyTreeView::newItem(const QString &name)
{
	if (!basemodel)
		return;

	NewKey *dlg = new NewKey(this, name);

	if (dlg->exec())
		keys()->newKey(dlg->getKeyJob(), dlg->keyDesc->text());
	delete dlg;
}

void KeyTreeView::clipboardFormat(QAction *a)
{
	Settings["KeyFormat"] = a->data().toInt();
}

void KeyTreeView::load(void)
{
	load_key l;
	load_default(&l);
}

ExportDialog *KeyTreeView::exportDialog(const QModelIndexList &indexes)
{
	if (indexes.size() == 0)
		return NULL;
	pki_key *key = db_base::fromIndex<pki_key>(indexes[0]);
	return new ExportDialog(this,
		tr("Key export"),
		tr("Private Keys ( *.pem *.der *.pk8 );; "
		   "SSH Public Keys ( *.pub )"), indexes,
		QPixmap(key->isToken() ? ":scardImg" : ":keyImg"),
		pki_export::select(asym_key, basemodel->exportFlags(indexes)),
		"keyexport");
}
