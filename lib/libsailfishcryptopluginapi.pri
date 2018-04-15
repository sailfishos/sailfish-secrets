include($$PWD/libsailfishsecretspluginapi.pri)
include($$PWD/libsailfishcrypto.pri)
LIBS += -L$$shadowed($$PWD/CryptoPluginApi) -lsailfishcryptopluginapi
