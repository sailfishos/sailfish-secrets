CONFIG += qt
QT += dbus
LIBS += -L$$shadowed($$PWD) -lsailfishcrypto

INCLUDEPATH += $$PWD
DEPENDPATH = $$INCLUDEPATH
