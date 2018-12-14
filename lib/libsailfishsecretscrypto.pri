CONFIG -= qt

LIBS += -L$$shadowed($$PWD/SecretsCrypto) -lsailfishsecretscrypto

INCLUDEPATH += $$PWD
DEPENDPATH += $$INCLUDEPATH
