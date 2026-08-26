TEMPLATE = app
TARGET = tst_keymintbinderclient
target.path = /opt/tests/Sailfish/Crypto/

QT += testlib
CONFIG += c++11 link_pkgconfig
PKGCONFIG += libgbinder openssl

SOURCES += tst_keymintbinderclient.cpp

INSTALLS += target
