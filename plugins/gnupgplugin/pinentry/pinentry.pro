TEMPLATE=app
TARGET=pinentry
QT-=gui
CONFIG += link_pkgconfig
PKGCONFIG += gpg-error mlite5

LIBS += -lassuan
include($$PWD/../../../lib/libsailfishsecrets.pri)

HEADERS += qassuanserver.h
SOURCES += qassuanserver.cpp pinentry.cpp

target.path = $$INSTALL_ROOT/usr/bin
INSTALLS += target
