#! /bin/sh

BUILD=build
EXEC=xpa_attack
LINK=xpa_attack

CREAT="$BUILD"

SAMPLE_FILE=./

rm --force -rf $CREAT
mkdir -p $BUILD
cd $BUILD
cmake -DCMAKE_BUILD_TYPE=Debug ..
make
cd ..
#ln -s ./$BUILD/$EXEC $LINK

#chmod 500 $BUILD/$EXEC