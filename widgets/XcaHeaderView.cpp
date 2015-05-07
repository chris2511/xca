/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "XcaHeaderView.h"
#include "XcaTreeView.h"

XcaHeaderView::XcaHeaderView()
	:QHeaderView(Qt::Horizontal)
{
	setMovable(true);
}

void XcaHeaderView::contextMenuEvent(QContextMenuEvent *e)
{
	XcaTreeView *tv = static_cast<XcaTreeView *>(parentWidget());
	if (tv)
		tv->headerEvent(e, logicalIndexAt(e->pos()));
}

void XcaHeaderView::resetMoves()
{
	for (int i=0; i<count(); i++) {
		if (i != visualIndex(i)) {
			moveSection(visualIndex(i), i);
			i=0;
		}
	}
	resizeSections(QHeaderView::ResizeToContents);
}
