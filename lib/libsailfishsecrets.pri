CONFIG += qt
QT += dbus

LIBS += -L$$shadowed($$PWD/Secrets) -lsailfishsecrets

INCLUDEPATH += $$PWD
DEPENDPATH += $$INCLUDEPATH
