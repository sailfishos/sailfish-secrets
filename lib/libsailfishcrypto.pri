CONFIG += qt
QT += dbus
LIBS += -L$$shadowed($$PWD/Crypto) -lsailfishcrypto

INCLUDEPATH += $$PWD
DEPENDPATH += $$INCLUDEPATH
