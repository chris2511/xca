
#include <qapplication.h>
#include "MainWindow.h"


int main( int argc, char *argv[] )
{
    QApplication a( argc, argv );
    MainWindow mw( NULL, "Main Widget");
    mw.setCaption("X Certification Authority");
    a.setMainWidget( &mw );
    mw.show();
    return a.exec();
    
}
