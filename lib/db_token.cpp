
#include "db_token.h"
#include "exception.h"
#include "pki_scard.h"
#include "sql.h"
#include "widgets/XcaWarning.h"

db_token::db_token() : db_base("manageTokens")
{
	updateHeaders();
}

void db_token::saveHeaderState()
{
}

void db_token::rename_token_in_database(pki_scard *token)
{
	if (!token)
		return;
	Transaction;
	if (!TransBegin())
		return;
	QList<pki_scard*> list = Store.sqlSELECTpki<pki_scard>(
                QString("SELECT item FROM tokens "
			"WHERE card_serial=? AND card_model=? and object_id=?"),
                QList<QVariant>() << QVariant(token->getSerial())
				<< QVariant(token->getModel())
				<< QVariant(token->getId()));

	foreach(pki_scard *item, list) {
		if (token->compare(item))
			item->updateLabel(token->getIntName());
	}
	TransCommit();
}

bool db_token::setData(const QModelIndex &index, const QVariant &value, int role)
{
	QString on, nn;
	pki_base *item;
	if (index.isValid() && role == Qt::EditRole) {
		nn = value.toString();
		item = fromIndex(index);
		on = item->getIntName();
		if (on == nn)
			return true;
		try {
			if (item->renameOnToken(slot, nn)) {
				item->setIntName(nn);
				rename_token_in_database(
					dynamic_cast<pki_scard*>(item));
				emit dataChanged(index, index);
				return true;
			}
		} catch (errorEx &err) {
			XCA_ERROR(err);
		}
	}
	return false;
}
