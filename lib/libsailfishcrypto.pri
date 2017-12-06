CONFIG += qt
QT += dbus

CONFIG += link_pkgconfig
PKGCONFIG += dbus-1

LIBS += -L$$shadowed($$PWD/Crypto) -lsailfishcrypto

INCLUDEPATH += $$PWD
DEPENDPATH += $$INCLUDEPATH
