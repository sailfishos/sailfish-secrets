include($$PWD/libsailfishsecrets.pri)
LIBS += -L$$shadowed($$PWD/SecretsPluginApi) -lsailfishsecretspluginapi
