TEMPLATE = lib
CONFIG += plugin hide_symbols
TARGET = sailfishcrypto-smime
TARGET = $$qtLibraryTarget($$TARGET)
LIBS += $$system(gpgme-config --libs)
QT = core         

include($$PWD/../../../common.pri)
include($$PWD/../../../lib/libsailfishcrypto.pri)
INCLUDEPATH += ..

HEADERS += $$PWD/plugin.h $$PWD/../gpgmebase.h $$PWD/../gpgmestorage.h $$PWD/../gpgme_p.h
SOURCES += $$PWD/plugin.cpp $$PWD/../gpgmebase.cpp $$PWD/../gpgmestorage.cpp

target.path = /usr/lib/Sailfish/Crypto/
INSTALLS += target
