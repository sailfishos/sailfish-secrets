TEMPLATE = aux

CONFIG += sailfish-qdoc-template
SAILFISH_QDOC.project = sailfish-secrets
SAILFISH_QDOC.config = sailfish-secrets.qdocconf
SAILFISH_QDOC.style = offline
SAILFISH_QDOC.path = /usr/share/doc/Sailfish/Secrets/

OTHER_FILES += \
    $$PWD/sailfish-secrets.qdocconf \
    $$PWD/sailfish-secrets-overview.qdoc \
    $$PWD/sailfish-secrets-plugins.qdoc \
    $$PWD/sailfish-secrets.cpp \
    $$PWD/../../../doc/sailfish.cpp
