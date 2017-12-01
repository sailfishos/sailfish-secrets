TEMPLATE = subdirs
SUBDIRS += \
    libsailfishsecrets \
    libsailfishsecretsplugin \
    libsailfishcrypto

libsailfishsecretsplugin.depends = libsailfishsecrets
