# common implementation of SQL database helper type
# used by both the daemon and various plugins
INCLUDEPATH += $$PWD
DEPENDPATH = $$INCLUDEPATH
SOURCES += $$PWD/database.cpp
HEADERS += $$PWD/database_p.h
