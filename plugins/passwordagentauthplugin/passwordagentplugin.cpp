/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "passwordagentplugin.h"

#include <nemo-devicelock/authenticator.h>

#include <QtDBus/QDBusAbstractAdaptor>
#include <QtDBus/QDBusConnection>
#include <QtDBus/QDBusMessage>
#include <QtDBus/QDBusMetaType>
#include <QtDBus/QDBusPendingCallWatcher>
#include <QtDBus/QDBusObjectPath>
#include <QtDBus/QDBusReply>

#include <QtCore/QFile>
#include <QtCore/QLoggingCategory>
#include <QtCore/QTimer>

#include <QStandardPaths>

Q_PLUGIN_METADATA(IID Sailfish_Secrets_AuthenticationPlugin_IID)

/*
<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
<node name="/org/sailfishos/Security/PasswordAuthority" xmlns:doc="http://www.freedesktop.org/dbus/1.0/doc.dtd">
 <interface name="org.sailfishos.Security.PasswordAuthority">
  <method name="RegisterSessionAgent">
   <doc:doc>
    <doc:description>
     <doc:para>
      Registers a session global password input agent with the secrets daemon.
     </doc:para>
     <doc:para>
      If the user needs to be prompted to enter a password the secrets daemon will
      invoke one of the members of org.sailfishos.Security.PasswordAgent interface
      on this agent.
     </doc:para>
     <doc:para>
      Only one session agent is allowed concurrently. If a second agent attempts to register
      an error will be returned.
     </doc:para>
    </doc:description>
   </doc:doc>
   <arg name="agent" type="o" direction="in">
    <doc:doc>
     <doc:summary>
      <doc:para>
       The object path of the password agent being registered. This object must implement
       the interface org.sailfishos.Security.PasswordAgent.
      </doc:para>
     </doc:summary>
    </doc:doc>
   </arg>
  </method>
  <method name="UnregisterSessionAgent">
   <doc:doc>
    <doc:description>
     <doc:para>
      Unregisters an agent previously registered with RegisterSessionAgent.
     </doc:para>
    </doc:description>
   </doc:doc>
   <arg name="agent" type="o" direction="in">
     <doc:summary>
      <doc:para>
       The object path of the password agent being unregistered.
      </doc:para>
     </doc:summary>
    </doc:doc>
   </arg>
  </method>
  <method name="ValidatePassword">
   <doc:doc>
    <doc:description>
     <doc:para>
      Validates an existing password entered into the agent. If this method returns without error
      the password agent will accept the password as being valid and return. If an error is
      the user will be prompted to enter their password again.
     </doc:para>
    </doc:description>
   </doc:doc>
   <arg name="cookie" type="s" direction="in">
    <doc:doc>
     <doc:summary>
      <doc:para>
       The unique cookie of the password request.
      </doc:para>
     </doc:summary>
    </doc:doc>
   </arg>
   <arg name="password" type="s" direction="in">
    <doc:doc>
     <doc:summary>
      <doc:para>
       The password entered by the user.
      </doc:para>
     </doc:summary>
    </doc:doc>
   </arg>
  </method>
 </interface>
</node>

<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
<node>
 <interface name="org.sailfishos.Security.PasswordAgent">
  <method name="CreatePassword">
   <doc:doc>
    <doc:description>
     <doc:para>
      Prompts the user to enter a new password.
     </doc:para>
    </doc:description>
   </doc:doc>
   <arg name="cookie" type="s" direction="in">
    <doc:doc>
     <doc:summary>
      <doc:para>
       A unique cookie which identifies this request.
      </doc:para>
     </doc:summary>
    </doc:doc>
   </arg>
   <arg name="message" type="s" direction="in">
    <doc:doc>
     <doc:summary>
      <doc:para>
       A message prompting the user to enter a new password.
      </doc:para>
     </doc:summary>
    </doc:doc>
   </arg>
   <arg name="properties" type="a{sv}" direction="in">
    <doc:doc>
     <doc:summary>
      <doc:para>
       A map of overrides the default labels and options for the user prompt.
      </doc:para>
     </doc:summary>
    </doc:doc>
   </arg>
   <arg name="password" type="s" direction="out">
    <doc:doc>
     <doc:summary>
      <doc:para>
       The new password entered by the user.
      </doc:para>
     </doc:summary>
    </doc:doc>
   </arg>
  </method>
  <method name="ChangePassword">
   <doc:doc>
    <doc:description>
     <doc:para>
      Prompts the user to change the password. They will be asked to enter both a new password
      and their existing password.
     </doc:para>
     <doc:para>
      This will return the new password after the existing one is validated by a call to
      ValidatePassword on the invoking password authority.
     </doc:para>
    </doc:description>
   </doc:doc>
   <arg name="cookie" type="s" direction="in"/>
   <arg name="message" type="s" direction="in"/>
   <arg name="properties" type="a{sv}" direction="in"/>
   <arg name="password" type="s" direction="out"/>
  </method>
  <method name="QueryPassword">
    <doc:description>
     <doc:para>
      Prompts the user to enter an existing password.
     </doc:para>
     <doc:para>
      This will return after the entered password is validated by a call to ValidatePassword on the
      invoking password authority.
     </doc:para>
    </doc:description>
   </doc:doc>
   <arg name="cookie" type="s" direction="in"/>
   <arg name="message" type="s" direction="in"/>
   <arg name="properties" type="a{sv}" direction="in"/>
  </method>
  <method name="Cancel">
    <doc:description>
     <doc:para>
      Cancels a current request for a user to enter a password.
     </doc:para>
    </doc:description>
   </doc:doc>
   <arg name="cookie" type="s" direction="in">
    <doc:doc>
     <doc:summary>
      <doc:para>
       The unique cookie that was passed as argument to the request to be canceled.
      </doc:para>
     </doc:summary>
    </doc:doc>
   </arg>
  </method>
 </interface>
</node>

*/

namespace {

struct PolkitSubject
{
    QString type;
    QVariantMap details;
};

struct PolkitAuthorizationResult
{
    bool isAuthorized;
    bool isChallenge;
    QHash<QString, QString> details;
};

}

Q_DECLARE_METATYPE(PolkitSubject)
Q_DECLARE_METATYPE(PolkitAuthorizationResult)

QDBusArgument &operator <<(QDBusArgument &argument, const PolkitSubject &subject)
{
    argument.beginStructure();
    argument << subject.type << subject.details;
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator >>(const QDBusArgument &argument, PolkitSubject &subject)
{
    argument.beginStructure();
    argument >> subject.type >> subject.details;
    argument.endStructure();
    return argument;
}

QDBusArgument &operator <<(QDBusArgument &argument, const PolkitAuthorizationResult &result)
{
    argument.beginStructure();
    argument << result.isAuthorized << result.isChallenge << result.details;
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator >>(const QDBusArgument &argument, PolkitAuthorizationResult &result)
{
    argument.beginStructure();
    argument >> result.isAuthorized >> result.isChallenge >> result.details;
    argument.endStructure();
    return argument;
}

QDBusMessage createPolkitMethodCall(const QString &member, const QVariantList &arguments)
{
    QDBusMessage methodCall = QDBusMessage::createMethodCall(
                QStringLiteral("org.freedesktop.PolicyKit1"),
                QStringLiteral("/org/freedesktop/PolicyKit1/Authority"),
                QStringLiteral("org.freedesktop.PolicyKit1.Authority"),
                member);
    methodCall.setArguments(arguments);
    return methodCall;
}

namespace Sailfish {

namespace Secrets {

namespace Daemon {

namespace Plugins {

Q_DECLARE_LOGGING_CATEGORY(lcPasswordAgent)
Q_LOGGING_CATEGORY(lcPasswordAgent, "org.sailfishos.secrets.plugin.authentication.passwordagent", QtWarningMsg)

static int cookieCounter = 0;

class PasswordAgentPlugin::PolkitResponse : public QDBusPendingCallWatcher
{
public:
    PolkitResponse(
            const QDBusPendingCall &call,
            uint callerPid,
            qint64 requestId,
            const QString &cookie,
            QObject *parent)
        : QDBusPendingCallWatcher(call, parent)
        , cookie(cookie)
        , requestId(requestId)
        , callerPid(callerPid)
    {
    }

    void cancel()
    {
        QDBusConnection::systemBus().send(
                    createPolkitMethodCall(QStringLiteral("CancelCheckAuthorization"), { cookie }));
    }

    const QString cookie;
    const qint64 requestId;
    const uint callerPid;
};

class PasswordAgentPlugin::PasswordResponse : public QDBusPendingCallWatcher
{
public:
    PasswordResponse(const QDBusPendingCall &call,
                uint callerPid,
                qint64 requestId,
                const InteractionParameters &parameters,
                const QString &address,
                const QString &cookie,
                QObject *parent)
        : QDBusPendingCallWatcher(call, parent)
        , parameters(parameters)
        , address(address)
        , cookie(cookie)
        , requestId(requestId)
        , callerPid(callerPid)
    {
    }

    const InteractionParameters parameters;
    const QString address;
    const QString cookie;
    QByteArray password;
    const qint64 requestId;
    const uint callerPid;

};

struct PasswordAgentPlugin::Agent
{
    Agent(const QDBusConnection &connection, const QString &service, const QString &path)
        : connection(connection)
        , service(service)
        , path(path)
    {
    }

    ~Agent()
    {
        qDeleteAll(responses);
    }

    QDBusMessage createMethodCall(const QString &member, const QVariantList &arguments)
    {
        QDBusMessage methodCall = QDBusMessage::createMethodCall(
                    service, path, QStringLiteral("org.sailfishos.Security.PasswordAgent"), member);
        methodCall.setArguments(arguments);
        return methodCall;
    }

    QDBusPendingCall asyncCall(const QString &member, const QVariantList &arguments, int timeout = -1)
    {
        return connection.asyncCall(createMethodCall(member, arguments), timeout);
    }

    void call(const QString &member, const QVariantList &arguments)
    {
        connection.send(createMethodCall(member, arguments));
    }

    void cancel(const QString &cookie)
    {
        call(QStringLiteral("Cancel"), { cookie });
    }

    const QDBusConnection connection;
    const QString service;
    const QString path;
    QHash<QString, PasswordResponse *> responses;
};

PasswordAgentPlugin::PasswordAgentPlugin(QObject *parent)
    : AuthenticationPlugin(parent)
{
}

void PasswordAgentPlugin::initialize()
{
    m_server.reset(new QDBusServer(QStringLiteral("unix:path=%1/sailfishsecretsd-p2pSocket-agent").arg(
                QStandardPaths::writableLocation(QStandardPaths::RuntimeLocation))));

    qDBusRegisterMetaType<PolkitSubject>();
    qDBusRegisterMetaType<PolkitAuthorizationResult>();
    qDBusRegisterMetaType<QHash<QString, QString>>();

    connect(m_server.data(), &QDBusServer::newConnection, this, [this](const QDBusConnection &connection) {
        if (!QDBusConnection(connection).connect(
                    QString(),
                    QStringLiteral("/org/freedesktop/DBus/Local"),
                    QStringLiteral("org.freedesktop.DBus.Local"),
                    QStringLiteral("Disconnected"),
                    this,
                    SLOT(disconnected()))) {
            qCWarning(lcPasswordAgent, "Failed to connect to DBus connection disconnect signal");
        }

        addConnection(connection);
    });
}

PasswordAgentPlugin::~PasswordAgentPlugin()
{
    if (m_sessionAgent) {
        for (PasswordResponse *response : m_sessionAgent->responses) {
            m_sessionAgent->cancel(response->cookie);
        }
    }
    for (PolkitResponse *response : m_polkitResponses) {
        response->cancel();
        delete response;
    }
}

AuthenticationPlugin::AuthenticationTypes PasswordAgentPlugin::authenticationTypes() const
{
    return AuthenticationPlugin::SystemDefaultAuthentication;
}

InteractionParameters::InputTypes PasswordAgentPlugin::inputTypes() const
{
    return InteractionParameters::NumericInput | InteractionParameters::AlphaNumericInput;
}

Result PasswordAgentPlugin::beginAuthentication(
        uint callerPid,
        qint64 requestId,
        const Sailfish::Secrets::InteractionParameters::PromptText &promptText)
{
    quint64 startTime = 0;
    {
        QFile file(QStringLiteral("/proc/%1/stat").arg(callerPid));
        if (file.open(QIODevice::ReadOnly)) {
            const QByteArray data = file.readAll();

            sscanf(data.data(),
                    "%*d "  // pid
                    "%*s "  // comm
                    "%*c "  // state
                    "%*d "  // ppid
                    "%*d "  // pgrp
                    "%*d "  // session
                    "%*d "  // tty_nr
                    "%*d "  // tpgid
                    "%*u "  // flags
                    "%*u "  // minflt
                    "%*u "  // cminflt
                    "%*u "  // majflt
                    "%*u "  // cmajflt
                    "%*u "  // utime
                    "%*u "  // stime
                    "%*d "  // cutime
                    "%*d "  // cstime
                    "%*d "  // priority
                    "%*d "  // nice
                    "%*d "  // num_threads
                    "%*d "  // itrealvalue
                    "%llu ",// starttime
                    &startTime);
        }
    }
    const QString cookie = QString::number(++cookieCounter);
    const PolkitSubject subject = {
        QStringLiteral("unix-process"),
        {
            { QStringLiteral("pid"), QVariant::fromValue(callerPid) },
            { QStringLiteral("start-time"), QVariant::fromValue(startTime)}
        }
    };

    QHash<QString, QString> details;
    if (!promptText.message().isEmpty()) {
        details.insert(QStringLiteral("polkit.message"), promptText.message());
    }

    QDBusPendingCall call = QDBusConnection::systemBus().asyncCall(
                createPolkitMethodCall(QStringLiteral("CheckAuthorization"), {
                    QVariant::fromValue(subject),
                    QStringLiteral("org.sailfishos.secrets.authentication"),
                    QVariant::fromValue(details),
                    QVariant::fromValue<uint>(1),
                    cookie }), 2 * 60 * 1000);

    PolkitResponse * const response = new PolkitResponse(call, callerPid, requestId, cookie, this);
    m_polkitResponses.insert(cookie, response);

    connect(response, &QDBusPendingCallWatcher::finished, this, [=](QDBusPendingCallWatcher *watcher) {
        watcher->deleteLater();

        m_polkitResponses.remove(cookie);

        Result result;

        if (response->isError()) {
            const QDBusError error = response->error();

            switch (error.type()) {
            case QDBusError::NoReply:
                response->cancel();
                break;
            default:
                break;
            }

            result = Result(Result::InteractionViewError, error.message());
        } else if (QDBusReply<PolkitAuthorizationResult>(*watcher).value().isAuthorized) {
            result = Result(Result::Succeeded);
        } else {
            if (QDBusReply<PolkitAuthorizationResult>(*watcher).value()
                    .details.value(QStringLiteral("polkit.dismissed"))
                    .compare(QStringLiteral("true"), Qt::CaseInsensitive) == 0) {
                result = Result(Result::InteractionViewUserCanceledError,
                                QLatin1String("The user canceled the authentication dialog"));
            } else if (!QDBusReply<PolkitAuthorizationResult>(*watcher).value().details.keys().isEmpty()) {
                result = Result(Result::IncorrectAuthenticationCodeError,
                                QStringLiteral("Password Agent was unable to verify the authenticity of the user"));
            } else {
                // The calling application was not started by the lipstick user session
                // so polkit cannot work for it (as the lipstick-security-ui is for that session).
                // Instead, use devicelock API directly.
                qCDebug(lcPasswordAgent) << "No polkit agent available for caller's session, falling back to device-lock";
                this->startDeviceLockAuthentication(callerPid, requestId, promptText);
                return;
            }
        }

        authenticationCompleted(response->callerPid, response->requestId, result);
    });

    return Result(Result::Pending);
}

void PasswordAgentPlugin::startDeviceLockAuthentication(
        uint callerPid,
        qint64 requestId,
        const Sailfish::Secrets::InteractionParameters::PromptText &promptText)
{
    QTimer *timeout = new QTimer(this);
    timeout->setInterval(120000); // 2 minutes
    timeout->setSingleShot(true);
    connect(timeout, &QTimer::timeout, timeout, [this, timeout, callerPid, requestId] {
        authenticationCompleted(callerPid, requestId,
                                Result(Result::AuthenticationTimeoutError,
                                       QStringLiteral("Device lock authentication timed out")));
        timeout->deleteLater();
    });
    timeout->start();

    NemoDeviceLock::Authenticator::Methods methods = NemoDeviceLock::Authenticator::Methods()
                                                   | NemoDeviceLock::Authenticator::Confirmation;
    NemoDeviceLock::Authenticator *authenticator = new NemoDeviceLock::Authenticator(timeout);

    // the authenticator is ready.  connect to its signals and request permission.
    connect(authenticator, &NemoDeviceLock::Authenticator::permissionGranted,
            authenticator, [this, timeout, authenticator, callerPid, requestId]
                           (NemoDeviceLock::Authenticator::Method) {
        this->authenticationCompleted(callerPid, requestId,
                                      Result(Result::Succeeded));
        timeout->deleteLater();
    });

    connect(authenticator, &NemoDeviceLock::Authenticator::aborted,
            authenticator, [this, timeout, authenticator, callerPid, requestId] {
        this->authenticationCompleted(callerPid, requestId,
                                      Result(Result::InteractionViewUserCanceledError,
                                             QLatin1String("The user canceled the authentication dialog")));
        timeout->deleteLater();
    });

    authenticator->requestPermission(
            promptText.message(),
            { { QStringLiteral("authenticatingPid"), QVariant::fromValue(callerPid) } },
            methods);
}

static const QPair<InteractionParameters::Prompt, QString> promptKeys[] = {
    { InteractionParameters::Instruction, QStringLiteral("enterCurrentPasswordText") },
    { InteractionParameters::NewInstruction, QStringLiteral("enterNewPasswordText") },
    { InteractionParameters::RepeatInstruction, QStringLiteral("repeatNewPasswordText") },
    { InteractionParameters::Accept, QStringLiteral("acceptText") },
    { InteractionParameters::Cancel, QStringLiteral("cancelText") },
};

template<typename T, int N> static constexpr int lengthOf(const T (&)[N]) { return N; }

Result PasswordAgentPlugin::beginUserInputInteraction(
        uint callerPid,
        qint64 requestId,
        const InteractionParameters &interactionParameters,
        const QString &interactionServiceAddress)
{
    Agent * const agent = m_sessionAgent.data();

    if (!agent) {
        return Result(Result::InteractionViewError, QStringLiteral("No password agent is registered"));
    }

    const QString cookie = QString::number(++cookieCounter);
    const InteractionParameters::PromptText promptText = interactionParameters.promptText();

    int echo = 0; // no mask
    if (interactionParameters.echoMode() == InteractionParameters::NoEcho) {
        echo = 1; // mask
    } else if (interactionParameters.echoMode() == InteractionParameters::PasswordEcho) {
        echo = 2; // delayed mask
    }

    int allowedCharacters = 2; // alpha-numeric
    if (interactionParameters.inputType() == InteractionParameters::NumericInput) {
        allowedCharacters = 0; // numberic
    }

    QVariantMap properties = {
        { QStringLiteral("applicationPid"), callerPid },
        { QStringLiteral("echo"), echo },
        { QStringLiteral("allowedCharacters"), allowedCharacters },
    };

    for (auto it = promptText.begin(); it != promptText.end(); ++it) {
        for (int i = 0; i < lengthOf(promptKeys); ++i) {
            if (promptKeys[i].first == it.key()) {
                properties.insert(promptKeys[i].second, it.value());
                break;
            }
        }
    }

    qCDebug(lcPasswordAgent) << "Begin password authentication"
                             << callerPid << requestId
                             << interactionParameters.applicationId()
                             << "for operation" << interactionParameters.operation()
                             << "on secret" << interactionParameters.secretName()
                             << "in collection" << interactionParameters.collectionName()
                             << interactionServiceAddress;

    const bool newPassword = (interactionParameters.operation()
                              == InteractionParameters::CreatePassword
                              /* Keep old behaviour, before CreatePassword operation
                                 was introduced. */
                              || promptText.contains(InteractionParameters::RepeatInstruction));

    // SecretManager connection timeout is fixed at 3 minutes.
    // Keep the timeout of the password dialog below this
    // threshold to avoid having the dialog stay on screen
    // while the request has already timeouted.
    QDBusPendingCall call = agent->asyncCall(newPassword
                    ? QStringLiteral("CreatePassword")
                    : QStringLiteral("QueryPassword"), {
                QVariant::fromValue(cookie),
                QVariant::fromValue(promptText.message()),
                QVariant::fromValue(properties) }, 2 * 60 * 1000 + 30 * 1000);

    PasswordResponse * const response = new PasswordResponse(
                call,
                callerPid,
                requestId,
                interactionParameters,
                interactionServiceAddress,
                cookie,
                this);
    agent->responses.insert(cookie, response);

    connect(response, &QDBusPendingCallWatcher::finished, this, [=](QDBusPendingCallWatcher *watcher) {
        watcher->deleteLater();

        agent->responses.remove(cookie);

        Result result;

        if (response->isError()) {
            const QDBusError error = response->error();

            switch (error.type()) {
            case QDBusError::NoReply:
                agent->cancel(cookie);
                break;
            default:
                break;
            }

            if (error.type() == QDBusError::Other && error.message().isEmpty()) {
                result = Result(Result::InteractionViewUserCanceledError,
                                QLatin1String("The user canceled the input dialog"));
            } else {
                result = Result(Result::InteractionViewError, error.message());
            }
        } else if (newPassword) {
            QDBusReply<QString> reply = *response;
            response->password = reply.value().toUtf8();
        }

        emit userInputInteractionCompleted(
                    response->callerPid,
                    response->requestId,
                    response->parameters,
                    response->address,
                    result,
                    response->password);
    });

    return Result(Result::Pending);
}

void PasswordAgentPlugin::addConnection(const QDBusConnection &connection)
{
    QDBusConnection(connection).registerObject(
                QStringLiteral("/org/sailfishos/Security/PasswordAuthority"),
                QStringLiteral("org.sailfishos.Security.PasswordAuthority"),
                this,
                QDBusConnection::ExportAllSlots);
}

void PasswordAgentPlugin::removeConnection(const QString &name)
{
    if (m_sessionAgent && m_sessionAgent->connection.name() == name) {
        destroyAgent(m_sessionAgent.take());
    }
}

void PasswordAgentPlugin::RegisterSessionAgent(const QDBusObjectPath &agent)
{
    if (m_sessionAgent) {
        QDBusContext::sendErrorReply(
                    QStringLiteral("org.sailfishos.Security.Error.ExistingAgent"), QString());
        return;
    }

    m_sessionAgent.reset(new Agent(
                QDBusContext::connection(), QDBusContext::message().service(), agent.path()));
}

void PasswordAgentPlugin::UnregisterSessionAgent(const QDBusObjectPath &agent)
{
    if (m_sessionAgent
            && m_sessionAgent->connection.name() == QDBusContext::connection().name()
            && m_sessionAgent->service == QDBusContext::message().service()
            && m_sessionAgent->path == agent.path()) {
        destroyAgent(m_sessionAgent.take());
    }
}

void PasswordAgentPlugin::ValidatePassword(const QString &cookie, const QString &password)
{
    if (!m_sessionAgent
            || m_sessionAgent->connection.name() != QDBusContext::connection().name()
            || m_sessionAgent->service != QDBusContext::message().service()) {
        QDBusContext::sendErrorReply(QDBusError::AccessDenied, QString());
    } else if (PasswordResponse *response = m_sessionAgent->responses.value(cookie)) {
        response->password = password.toUtf8();
    } else {
        QDBusContext::sendErrorReply(
                    QStringLiteral("org.sailfishos.Security.Error.InvalidCookie"), QString());
    }
}

void PasswordAgentPlugin::destroyAgent(Agent *agent)
{
    const Result result(Result::InteractionViewError, QStringLiteral("Password agent exited"));
    for (PasswordResponse *response : agent->responses) {
        emit userInputInteractionCompleted(
                    response->callerPid,
                    response->requestId,
                    response->parameters,
                    response->address,
                    result,
                    QByteArray());
    }
    delete agent;
}

void PasswordAgentPlugin::disconnected()
{
    const QString name = QDBusContext::connection().name();

    removeConnection(QDBusContext::connection().name());

    QDBusConnection::disconnectFromPeer(name);
}

} // namespace Plugins

} // namespace Daemon

} // namespace Secrets

} // namespace Sailfish
