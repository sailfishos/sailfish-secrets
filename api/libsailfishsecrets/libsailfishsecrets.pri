CONFIG += qt
QT += dbus

LIBS += -L$$shadowed($$PWD) -lsailfishsecrets

INCLUDEPATH += $$PWD
DEPENDPATH = $$INCLUDEPATH
