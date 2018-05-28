/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Timur Kristóf <timur.kristof@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "../logging_p.h"
#include "dataprotector_p.h"

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QSaveFile>
#include <QtCore/QVector>
#include <QtCore/QMap>
#include <QtCore/QUuid>
#include <QtCore/QSharedPointer>

#include <algorithm>

/*
    Implements a data protection mechanism for sensitive sailfish-secrets data files.

    What we want to protect from:
    * When the device shuts down while writing new data
    * When the flash blocks are corrupted in a very small way

    Out of scope:
    * Preventing the user or others from purposedly tampering with the data
    * Protection from major flash corruption (your system will be highly unlikely to boot anyway)

    How we do it:
    The data is stored in 3 files, each of them have the same content

    When storing the data:
    1. We create a new directory
    2. We write the 3 new files (with the same content) into this directory
    3. Finally, we delete the old data directory

    When accessing the data:
    1. If more than one directory exists, we assume that the store operation was incomplete,
       so we delete all but the oldest directory
    2. We read all files from the directory and make a majority decision about which one is correct
    3. Return the correct file contents to the caller
*/

namespace Sailfish {

namespace Secrets {

namespace Daemon {

namespace ApiImpl {

DataProtector::DataProtector(const QString &path, QObject *parent)
    : QObject(parent)
    , m_path(path)
{
}

QString DataProtector::path() const
{
    return m_path;
}

DataProtector::Status DataProtector::getData(QByteArray *result)
{
    if (result == Q_NULLPTR) {
        return ErrorGotNullptr;
    }

    if (!m_data.isEmpty()) {
        *result = m_data;
        return Success;
    }

    *result = QByteArray();

    QDir dir(m_path);

    // Check if the main directory exists, create if not
    if (!dir.exists()) {
        qCDebug(lcSailfishSecretsDaemon) << "Protected root directory wasn't found by getData, so the data is empty.";
        return Success;
    }

    // Get all subdirectories, we want oldest first
    QFileInfoList subdirs = dir.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot, QDir::Time);
    if (subdirs.size() == 0) {
        qCDebug(lcSailfishSecretsDaemon) << "No subdirectories found by getData, so the data is empty.";
        return Success;
    }

    // Keep only the oldest subdirectory, we assume it has correct data and was not already deleted
    // because we didn't finish writing the newer ones
    for (int i = 1; i < subdirs.size(); i++) {
        QString subdirPath = subdirs.at(i).absoluteFilePath();
        qCDebug(lcSailfishSecretsDaemon) << "getData is assuming incomplete data directory, deleting it:" << subdirPath;
        dir.rmdir(subdirPath);
    }

    // Get the oldest data directory and examine its files
    QString dataDirPath = subdirs.at(0).absoluteFilePath();
    QDir dataDir(dataDirPath);
    QFileInfoList filesInDataDir = dataDir.entryInfoList(QDir::Files);

    // Make sure the directory contains at least one file
    if (filesInDataDir.size() == 0) {
        qCWarning(lcSailfishSecretsDaemon) << "Data directory doesn't contain any files:" << dataDirPath;
        return Irretrievable;
    }

    // QSharedPointer is used here because QFile is non-copy-constructible, and move semantics are not there yet in 5.6.3,
    // This makes the std alogrithms usable, which spare a lot of copy-paste code here.
    // TODO: change this code to eliminate the QSharedPointer when we upgrade to a version of Qt which has move semantics for QFile
    QVector<QSharedPointer<QFile> > files;
    std::transform(filesInDataDir.begin(), filesInDataDir.end(), std::back_inserter(files), [](const QFileInfo &fileInfo) {
        QString path = fileInfo.absoluteFilePath();
        QSharedPointer<QFile> file(new QFile(path));
        file->open(QIODevice::ReadOnly);
        return file;
    });

    // Open all files
    // NOTE: the negative naming of noFilesOpen is ugly, but std::any_of is short-circuited, so we use all_of here.
    bool noFilesOpen = std::all_of(files.begin(), files.end(), [](QSharedPointer<QFile> &file) {
        bool isOpen = file->isOpen();
        if (!isOpen) {
            // Loss of any individual file here doesn't yet necessarily mean an error
            qWarning(lcSailfishSecretsDaemon) << "can't open file:" << file->fileName();
        }
        return !isOpen;
    });

    // If none of the files could be opened, we are very unlucky
    if (noFilesOpen) {
        qWarning(lcSailfishSecretsDaemon) << "Could not open any files. Data is irretrieveable.";
        return Irretrievable;
    }

    // Read all files
    QVector<QByteArray> fileContents;
    std::transform(files.begin(), files.end(), std::back_inserter(fileContents), [](QSharedPointer<QFile> &file) {
        return file->readAll();
    });

    std::remove_if(fileContents.begin(), fileContents.end(), [](QByteArray &byteArray) {
        return byteArray.isEmpty();
    });

    //  If none of the files could be read, again we are unlucky
    if (fileContents.size() == 0) {
        qWarning(lcSailfishSecretsDaemon) << "Could not read any of the files. Data is irretrievable.";
        return Irretrievable;
    }

    // Assuming that any of the byte arrays can differ from any of the others,
    // count how many times each occours. Ideally we end up with 3 occourences
    // on the first index, and 0 on the others.
    QVector<int> occourences(fileContents.size());
    for (const QByteArray &currentData : fileContents) {
        for (int i = 0; i < fileContents.size(); i++) {
            if (currentData == fileContents.at(i)) {
                occourences[i]++;
                break;
            }
        }
    }

    // Assume that the version that occours the most is the correct version.
    int maxOccourenceIndex = 0;
    for (int i = 0; i < occourences.size(); i++) {
        if (occourences[i] > occourences[maxOccourenceIndex]) {
            maxOccourenceIndex = i;
        }
    }
    int minimumValidOccourences = fileContents.size() / 2 + 1;
    if (occourences[maxOccourenceIndex] < minimumValidOccourences) {
        qWarning(lcSailfishSecretsDaemon) << "Could not decide which file is correct, there is no majority.";
        return Irretrievable;
    }

    m_data = fileContents[maxOccourenceIndex];
    *result = m_data;

    return Success;
}

DataProtector::Status DataProtector::putData(const QByteArray &bytes)
{
    QDir dir(m_path);

    // Check if the main directory exists, create if not
    if (!dir.exists()) {
        if (!dir.mkpath(m_path)) {
            qCWarning(lcSailfishSecretsDaemon) << "Can't create protected root directory when writing new data:" << m_path;
            return ErrorCannotCreateDirectory;
        }

        qCDebug(lcSailfishSecretsDaemon) << "Protected root directory didn't exist, so putData assumes the data is empty.";
    }

    // Get list of old directories, these will be deleted at the end
    QFileInfoList oldDirectories = dir.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot);

    // Create new data directory
    QString dataDirName = QUuid::createUuid().toString().remove('{').remove('}');
    QString dataDirPath = m_path + QStringLiteral("/") + dataDirName;
    if (!dir.mkdir(dataDirPath)) {
        qCWarning(lcSailfishSecretsDaemon) << "Can't create data directory when writing new data:" << dataDirPath;
        return ErrorCannotCreateDirectory;
    }

    // Create redundant files in new data directory
    QVector<QString> dataFilePaths = {
        dataDirPath + QStringLiteral("/file0"),
        dataDirPath + QStringLiteral("/file1"),
        dataDirPath + QStringLiteral("/file2"),
    };
    QVector<QSharedPointer<QSaveFile> > files;
    std::transform(dataFilePaths.begin(), dataFilePaths.end(), std::back_inserter(files), [](const QString &filePath) {
        return QSharedPointer<QSaveFile>(new QSaveFile(filePath));
    });

    bool allOpen = std::all_of(files.begin(), files.end(), [](QSharedPointer<QSaveFile> &file) {
        bool isOpen = file->open(QIODevice::WriteOnly);
        if (!isOpen) {
            qCWarning(lcSailfishSecretsDaemon) << "Can't open file for writing:" << file->fileName();
        }
        return isOpen;
    });

    if (!allOpen) {
        qCWarning(lcSailfishSecretsDaemon) << "Not all files could be open for writing.";
        return ErrorCannotOpenFile;
    }

    // Write redundant data
    for (QSharedPointer<QSaveFile> &file : files) {
        qint64 bytesWritten = file->write(bytes);
        if (bytesWritten != bytes.size()) {
            qCWarning(lcSailfishSecretsDaemon) << "Can't write file:" << file->fileName();
            return ErrorCannotWriteFile;
        }
        if (!file->commit()) {
            qCWarning(lcSailfishSecretsDaemon) << "Could not commit file:" << file->fileName();
            return ErrorCannotWriteFile;
        }
    }

    // Remove old data directories
    for (QFileInfo &fileInfo : oldDirectories) {
        QDir oldDataDir(fileInfo.absoluteFilePath());
        if (!oldDataDir.removeRecursively()) {
            qCWarning(lcSailfishSecretsDaemon) << "Could not remove old data after writing new data:" << fileInfo.absoluteFilePath();
            return ErrorCannotDeleteDirectory;
        }
    }

    // Clear in-memory data, so it gets refreshed on next call
    m_data.clear();
    return Success;
}

}

}

}

}
