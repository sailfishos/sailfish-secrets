/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_PLUGIN_STORAGE_SQLITE_DATABASE_P_H
#define SAILFISHSECRETS_PLUGIN_STORAGE_SQLITE_DATABASE_P_H

#include "database_p.h"

static const char *setupEnforceForeignKeys =
        "\n PRAGMA foreign_keys = ON;";

static const char *setupEncoding =
        "\n PRAGMA encoding = \"UTF-16\";";

static const char *setupTempStore =
        "\n PRAGMA temp_store = MEMORY;";

static const char *setupJournal =
        "\n PRAGMA journal_mode = WAL;";

static const char *setupSynchronous =
        "\n PRAGMA synchronous = FULL;";

static const char *createCollectionsTable =
        "\n CREATE TABLE Collections ("
        "   CollectionName TEXT NOT NULL,"
        "   PRIMARY KEY (CollectionName));";

static const char *createSecretsTable =
        "\n CREATE TABLE Secrets ("
        "   CollectionName TEXT NOT NULL,"
        "   SecretName TEXT NOT NULL,"
        "   Secret BLOB,"
        "   Timestamp DATE,"
        "   FOREIGN KEY (CollectionName) REFERENCES Collections(CollectionName) ON DELETE CASCADE,"
        "   PRIMARY KEY (CollectionName, SecretName));";

static const char *createSecretsFilterDataTable =
        "\n CREATE TABLE SecretsFilterData ("
        "   CollectionName TEXT NOT NULL,"
        "   SecretName TEXT NOT NULL,"
        "   Field TEXT NOT NULL,"
        "   Value TEXT,"
        "   FOREIGN KEY (CollectionName, SecretName) REFERENCES Secrets (CollectionName, SecretName) ON DELETE CASCADE,"
        "   PRIMARY KEY (CollectionName, SecretName, Field));";

static const char *setupStatements[] =
{
    setupEnforceForeignKeys,
    setupEncoding,
    setupTempStore,
    setupJournal,
    setupSynchronous,
    NULL
};

static const char *createStatements[] =
{
    createCollectionsTable,
    createSecretsTable,
    createSecretsFilterDataTable,
    NULL
};

static Sailfish::Secrets::Daemon::Sqlite::UpgradeOperation upgradeVersions[] = {
    { 0, 0 },
};

static const int currentSchemaVersion = 1;

#endif // SAILFISHSECRETS_PLUGIN_STORAGE_SQLITE_DATABASE_P_H
