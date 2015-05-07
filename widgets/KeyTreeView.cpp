/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "lib/pki_scard.h"
#include "XcaTreeView.h"
#include "MainWindow.h"
#include <QtCore/QAbstractItemModel>
#include <QtGui/QAbstractItemView>
#include <QtGui/QMenu>

void KeyTreeView::fillContextMenu(QMenu *menu, QMenu *subExport,
			const QModelIndex &index, QModelIndexList indexes)
{
	bool multi = indexes.size() > 1;

	pki_key *key = static_cast<pki_key*>(index.internalPointer());

	if (index == QModelIndex())
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
		}
	}

	if (!pkcs11::loaded() || multi)
		return;

	if (key->isToken()) {
		menu->addAction(tr("Change PIN"), this,
			SLOT(changePin()));
		menu->addAction(tr("Init PIN with SO PIN (PUK)"), this,
			SLOT(initPin()));
		menu->addAction(tr("Change SO PIN (PUK)"), this,
			SLOT(changeSoPin()));
	} else {
		menu->addAction(tr("Store on Security token"),
			this, SLOT(toToken()));
	}
}

void KeyTreeView::setOwnPass()
{
	try {
		keys->setOwnPass(currentIndex(), pki_key::ptPrivate);
	} catch (errorEx &err) {
		mainwin->Error(err);
	}
}

void KeyTreeView::resetOwnPass()
{
	try {
		keys->setOwnPass(currentIndex(), pki_key::ptCommon);
	} catch (errorEx &err) {
		mainwin->Error(err);
	}
}

void KeyTreeView::changePin()
{
	pki_scard *scard;
	QModelIndex currentIdx = currentIndex();

	if (!currentIdx.isValid())
		return;
	scard = static_cast<pki_scard*>(currentIdx.internalPointer());
	try {
		if (!scard->isToken()) {
			throw errorEx(tr("Tried to change PIN of a key"));
		}
		scard->changePin();
	} catch (errorEx &err) {
		mainwin->Error(err);
	}
}

void KeyTreeView::initPin()
{
	pki_scard *scard;
	QModelIndex currentIdx = currentIndex();

	if (!currentIdx.isValid())
		return;
	scard = static_cast<pki_scard*>(currentIdx.internalPointer());
	try {
		if (!scard->isToken()) {
			throw errorEx(tr("Tried to init PIN of a key"));
		}
		scard->initPin();
	} catch (errorEx &err) {
		mainwin->Error(err);
	}
}

void KeyTreeView::changeSoPin()
{
	pki_scard *scard;
	QModelIndex currentIdx = currentIndex();

	if (!currentIdx.isValid())
		return;
	scard = static_cast<pki_scard*>(currentIdx.internalPointer());
	try {
		if (!scard->isToken()) {
			throw errorEx(tr("Tried to change SO PIN of a key"));
		}
		scard->changeSoPin();
	} catch (errorEx &err) {
		mainwin->Error(err);
	}
}

void KeyTreeView::toToken()
{
	QModelIndex currentIdx = currentIndex();

	if (!currentIdx.isValid())
		return;

	pki_key *key = static_cast<pki_scard*>(currentIdx.internalPointer());
	if (!key || !pkcs11::loaded() || key->isToken())
		return;

	pki_scard *card = NULL;
	try {
		pkcs11 p11;
		slotid slot;

		if (!p11.selectToken(&slot, mainwin))
			return;
		card = new pki_scard(key->getIntName());
		card->store_token(slot, key->decryptKey());
		QString msg = tr("Shall the original key '%1' be replaced by the key on the token?\nThis will delete the key '%1' and make it unexportable").
			arg(key->getIntName());
		if (XCA_YESNO(msg)) {
			keys->deletePKI(currentIdx);
			keys->insertPKI(card);
			card = NULL;
		}
	} catch (errorEx &err) {
		mainwin->Error(err);
        }
	if (card)
		delete card;
}
