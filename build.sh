#! /bin/sh

BUILD=build
EXEC=sca_2
LINK=sca_2

CREAT="$BUILD"

rm --force -rf $CREAT
mkdir -p $BUILD
cd $BUILD
cmake ..
make
cd ..
ln -s ./$BUILD/$EXEC $LINK

chmod 500 $BUILD/$EXEC