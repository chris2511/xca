#!/bin/sh

VERSION=$(cat VERSION)
echo "Creating distribution disk image for xca $VERSION"

QTDEPLOY=/usr/bin/macdeployqt

if [ -x "`which macdeployqt`" ]
then
    QTDEPLOY=`which macdeployqt`
fi

if [ -x "$QTDEPLOY" ]
then
    echo "$QTDEPLOY will be used for packaging qt into release builds of the application bundle"
else
    echo "macdeployqt was not found. Unable to package."
    exit 1
fi

if [ -f xca-$VERSION.dmg ]
then
    echo "xca-$VERSION.dmg already exists. Move it out of the way to repackage."
    exit 1
fi

if [ ! -d "build/Release/xca.app" ]
then
    echo "No release build was found. This script only makes sense for packaging release builds."
    exit 1
fi
DMGSTAGELOC=./dmgstage/xca
rm -rf $DMGSTAGELOC
mkdir -p $DMGSTAGELOC
if ! cp -r build/Release/xca.app $DMGSTAGELOC
then
    echo "Could not copy the release build into directory dmgstage."
    exit
fi
if [ -x "$QTDEPLOY" ]; then
    CWD=`pwd`
    cd $DMGSTAGELOC
    $QTDEPLOY xca.app
    cd $CWD
else
    echo "Warning: this release package will require users to have installed Qt on their systems."
fi

cp COPYRIGHT $DMGSTAGELOC

if [ -z "$HTML_DOCDIR" -a -e "doc/xca.html" ]
then
    HTML_DOCDIR="doc"
fi

if [ -n "$HTML_DOCDIR" ]
then
    echo "Using HTML documentation from: $HTML_DOCDIR"
    mkdir $DMGSTAGELOC/manual
    # copy the manual onto the disk image so that users can read it
    # without launching the app
    cp $HTML_DOCDIR/xc*.html $DMGSTAGELOC/manual
    # also copy the manual into the bundle so that help works
    cp $HTML_DOCDIR/xc*.html $DMGSTAGELOC/xca.app/Contents/Resources
else
    echo "Warning: No manual will be included on the disk image and help will be unavailable. (Set HTML_DOCDIR to the directory containing xca.html ff.)"
fi

hdiutil create -srcfolder $DMGSTAGELOC xca-$VERSION.dmg

