
#include "db_token.h"
#include "exception.h"
#include "widgets/MainWindow.h"

db_token::db_token(QString db, MainWindow *mw)
        :db_base(db, mw)
{
	class_name = "manageTokens";
	updateHeaders();
}

bool db_token::setData(const QModelIndex &index, const QVariant &value, int role)
{
	QString on, nn;
	pki_base *item;
	if (index.isValid() && role == Qt::EditRole) {
		nn = value.toString();
		item = static_cast<pki_base*>(index.internalPointer());
		on = item->getIntName();
		if (on == nn)
			return true;
		try {
			if (item->renameOnToken(slot, nn)) {
				item->setIntName(nn);
				emit dataChanged(index, index);
				return true;
			}
		} catch (errorEx &err) {
			mainwin->Error(err);
		}
	}
	return false;
}
