
#include <qapplication.h>
#include "MainWindow.h"


int main( int argc, char *argv[] )
{
    QApplication a( argc, argv );
    MainWindow mw( NULL, "Main Widget");
    QString title;
    mw.setCaption(title.sprintf("xca - V%s", VER)); 
    a.setMainWidget( &mw );
    mw.show();
    return a.exec();
}
