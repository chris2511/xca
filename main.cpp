#include <qapplication.h>
#include <qtranslator.h>
#include <qtextcodec.h>
#include "MainWindow.h"


int main( int argc, char *argv[] )
{
    QApplication a( argc, argv );
    MainWindow mw( NULL, "Main Widget");
    mw.setCaption("X Certification Authority"); 
    a.setMainWidget( &mw );
    	
    // translation file for Qt
    QTranslator qtTr( 0 );
    qtTr.load( QString( "qt_" ) + QTextCodec::locale(), "." );
    a.installTranslator( &qtTr );
    //translation file for application strings
    QTranslator xcaTr( 0 );
    xcaTr.load( QString( "xca_" ) + QTextCodec::locale(), "." );
    a.installTranslator( &xcaTr );
    
    mw.show();
    return a.exec();
}
