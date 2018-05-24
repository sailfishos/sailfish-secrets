include($$PWD/libsailfishsecrets.pri)
LIBS += -L$$shadowed($$PWD/Secrets/Plugins) -lsailfishsecretspluginapi
