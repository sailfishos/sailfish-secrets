/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_APIIMPL_SECRETSDATABASE_P_H
#define SAILFISHSECRETS_APIIMPL_SECRETSDATABASE_P_H

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
        "   CollectionId INTEGER PRIMARY KEY AUTOINCREMENT,"
        "   CollectionName TEXT NOT NULL,"
        "   ApplicationId TEXT NOT NULL,"
        "   UsesDeviceLockKey INTEGER NOT NULL,"
        "   StoragePluginName TEXT NOT NULL,"
        "   EncryptionPluginName TEXT NOT NULL,"
        "   AuthenticationPluginName TEXT NOT NULL,"
        "   UnlockSemantic INTEGER NOT NULL,"
        "   CustomLockTimeoutMs INTEGER NOT NULL,"
        "   AccessControlMode INTEGER NOT NULL,"
        "   CONSTRAINT collectionNameUnique UNIQUE (CollectionName));";

static const char *createSecretsTable =
        "\n CREATE TABLE Secrets ("
        "   SecretId INTEGER PRIMARY KEY AUTOINCREMENT,"
        "   CollectionName TEXT NOT NULL,"
        "   HashedSecretName TEXT NOT NULL,"
        "   ApplicationId TEXT NOT NULL,"
        "   UsesDeviceLockKey INTEGER NOT NULL,"
        "   StoragePluginName TEXT NOT NULL,"
        "   EncryptionPluginName TEXT NOT NULL,"
        "   AuthenticationPluginName TEXT NOT NULL,"
        "   UnlockSemantic INTEGER NOT NULL,"
        "   CustomLockTimeoutMs INTEGER NOT NULL,"
        "   AccessControlMode INTEGER NOT NULL,"
        "   FOREIGN KEY (CollectionName) REFERENCES Collections(CollectionName) ON DELETE CASCADE,"
        "   CONSTRAINT collectionSecretNameUnique UNIQUE (CollectionName, HashedSecretName));";

static const char *createKeyEntriesTable =
        "\n CREATE TABLE KeyEntries ("
        "   KeyId INTEGER PRIMARY KEY AUTOINCREMENT,"
        "   CollectionName TEXT NOT NULL,"
        "   HashedSecretName TEXT NOT NULL,"
        "   KeyName TEXT NOT NULL,"        /* potential security (known-plaintext) issue!!! */
        "   CryptoPluginName TEXT NOT NULL,"
        "   StoragePluginName TEXT NOT NULL,"
        "   FOREIGN KEY (CollectionName, HashedSecretName) REFERENCES Secrets(CollectionName,HashedSecretName) ON DELETE CASCADE,"
        "   CONSTRAINT collectionKeyNameUnique UNIQUE (CollectionName, KeyName));";

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
    createKeyEntriesTable,
    NULL
};

static Sailfish::Secrets::Daemon::Sqlite::UpgradeOperation upgradeVersions[] = {
    { 0, 0 },
};

static const int currentSchemaVersion = 1;

#endif // SAILFISHSECRETS_APIIMPL_SECRETSDATABASE_P_H
