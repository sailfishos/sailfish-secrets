TEMPLATE = aux

CONFIG += mer-qdoc-template
MER_QDOC.project = sailfish-crypto
MER_QDOC.config = sailfish-crypto.qdocconf
MER_QDOC.style = offline
MER_QDOC.path = /usr/share/doc/Sailfish/Crypto/

OTHER_FILES += \
    $$PWD/sailfish-crypto.qdocconf \
    $$PWD/sailfish-crypto-overview.qdoc \
    $$PWD/sailfish-crypto-plugins.qdoc \
    $$PWD/sailfish-crypto.cpp \
    $$PWD/../../../doc/index.qdoc \
    $$PWD/../../../doc/sailfish.cpp
