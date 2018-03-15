TEMPLATE = lib
TARGET = sailfishcryptoplugin
TARGET = $$qtLibraryTarget($$TARGET)
CONFIG += plugin hide_symbols

include($$PWD/../../common.pri)
include($$PWD/../../lib/libsailfishcrypto.pri)

QT += qml core

HEADERS += $$PWD/plugintypes.h
SOURCES += $$PWD/main.cpp
OTHER_FILES += $$PWD/qmldir

target.path = /usr/lib/qt5/qml/Sailfish/Crypto/
qmlfiles.path = /usr/lib/qt5/qml/Sailfish/Crypto/
qmlfiles.files += qmldir

INSTALLS += target qmlfiles
