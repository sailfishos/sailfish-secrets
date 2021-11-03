TEMPLATE = aux

CONFIG += sailfish-qdoc-template
SAILFISH_QDOC.project = sailfish-crypto
SAILFISH_QDOC.config = sailfish-crypto.qdocconf
SAILFISH_QDOC.style = offline
SAILFISH_QDOC.path = /usr/share/doc/Sailfish/Crypto/

OTHER_FILES += \
    $$PWD/sailfish-crypto.qdocconf \
    $$PWD/sailfish-crypto-overview.qdoc \
    $$PWD/sailfish-crypto-plugins.qdoc \
    $$PWD/sailfish-crypto.cpp \
    $$PWD/../../../doc/sailfish.cpp
