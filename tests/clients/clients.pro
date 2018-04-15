TEMPLATE = subdirs

packagesExist(qt5-boostable) {
    SUBDIRS += \
        authentication
} else {
    warning("qt5-boostable not available; authentication client won't be compiled")
}



