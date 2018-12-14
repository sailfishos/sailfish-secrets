TEMPLATE = app
TARGET = tst_secretscrypto
target.path = /opt/tests/Sailfish/SecretsCrypto/
include($$PWD/../../../lib/libsailfishsecretscrypto.pri)
CONFIG -= qt
CONFIG += link_pkgconfig
PKGCONFIG += glib-2.0 gio-2.0
SOURCES += tst_secretscrypto.c
INSTALLS += target
