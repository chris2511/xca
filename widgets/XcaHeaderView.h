/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __XCAHEADERVIEW_H
#define __XCAHEADERVIEW_H

#include <QHeaderView>

class XcaHeaderView: public QHeaderView
{
	Q_OBJECT

    public:
	XcaHeaderView();
	void contextMenuEvent(QContextMenuEvent *e);

    public slots:
	void resetMoves();
};
#endif
