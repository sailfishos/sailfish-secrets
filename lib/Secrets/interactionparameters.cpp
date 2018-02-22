/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Secrets/interactionparameters.h"
#include "Secrets/interactionparameters_p.h"

using namespace Sailfish::Secrets;

InteractionParametersPrivate::InteractionParametersPrivate()
{
}

InteractionParametersPrivate::InteractionParametersPrivate(const InteractionParametersPrivate &other)
    : QSharedData(other)
    , m_secretName(other.m_secretName)
    , m_collectionName(other.m_collectionName)
    , m_applicationId(other.m_applicationId)
    , m_operation(other.m_operation)
    , m_authenticationPluginName(other.m_authenticationPluginName)
    , m_promptText(other.m_promptText)
    , m_promptTrId(other.m_promptTrId)
    , m_inputType(other.m_inputType)
    , m_echoMode(other.m_echoMode)
{
}

InteractionParametersPrivate::~InteractionParametersPrivate()
{
}

/*!
 * \class InteractionParameters
 * \brief Encapsulates parameters related to requesting input from the user
 *
 * This class encapsulates a variety of parameters which will affect the
 * look and feel, as well as functionality, of a prompt to be shown to
 * the user of the device.
 *
 * Usually, this will be used when requesting some secret data from the
 * user to be stored securely.  In that case, the application may set
 * the promptText(), inputType(), and echoMode() for the prompt, and
 * optionally specify an authenticationPluginName() to be used for the request,
 * and the passphrase or PIN will be requested from the user.  The other
 * parameters will be supplied automatically to the authentication plugin
 * by the secrets service on behalf of the application, and thus setting
 * the other parameters will have no effect.  Please see the documentation
 * for \l{Sailfish::Secrets::StoreSecretRequest} for more information.
 */

/*!
 * \brief Constructs a new InteractionParameters instance
 */
InteractionParameters::InteractionParameters()
    : d_ptr(new InteractionParametersPrivate)
{
}

/*!
 * \brief Destroys the InteractionParameters instance
 */
InteractionParameters::~InteractionParameters()
{
}

/*!
 * \brief Constructs a copy of the \a other InteractionParameters instance
 */
InteractionParameters::InteractionParameters(const InteractionParameters &other)
    : d_ptr(other.d_ptr)
{
}

/*!
 * \brief Assigns this InteractionParameters to be equal to the \a other
 */
InteractionParameters& InteractionParameters::operator=(const InteractionParameters &other)
{
    d_ptr = other.d_ptr;
    return *this;
}

/*!
 * \brief Returns true if every parameter specified in this object is identical to that of the \a other object
 */
bool InteractionParameters::operator==(const InteractionParameters &other) const
{
    return secretName() == other.secretName()
            && collectionName() == other.collectionName()
            && applicationId() == other.applicationId()
            && operation() == other.operation()
            && authenticationPluginName() == other.authenticationPluginName()
            && promptText() == other.promptText()
            && promptTrId() == other.promptTrId()
            && inputType() == other.inputType()
            && echoMode() == other.echoMode();
}

/*!
 * \brief Returns true if the required user input type is well-specified
 */
bool InteractionParameters::isValid() const
{
    return inputType() != InteractionParameters::UnknownInput;
}

/*!
 * \brief Returns the name of the secret associated with the user input request
 */
QString InteractionParameters::secretName() const
{
    return d_ptr->m_secretName;
}

/*!
 * \brief Sets the name of the secret associated with the user input request to \a name
 *
 * Note that in general, this parameter will be supplied by the secrets service,
 * so any value set by the client application here will have no effect.
 */
void InteractionParameters::setSecretName(const QString &name)
{
    if (d_ptr->m_secretName != name) {
        d_ptr->m_secretName = name;
    }
}

/*!
 * \brief Returns the name of the collection in which the secret is stored, which is associated with the user input request
 */
QString InteractionParameters::collectionName() const
{
    return d_ptr->m_collectionName;
}

/*!
 * \brief Sets the name of the collection in which the secret is stored, which is associated with the user input request to \a name
 *
 * Note that in general, this parameter will be supplied by the secrets service,
 * so any value set by the client application here will have no effect.
 */
void InteractionParameters::setCollectionName(const QString &name)
{
    if (d_ptr->m_collectionName != name) {
        d_ptr->m_collectionName = name;
    }
}

/*!
 * \brief Returns the identifier of the client application making the request
 */
QString InteractionParameters::applicationId() const
{
    return d_ptr->m_applicationId;
}

/*!
 * \brief Sets the identifier of the client application making the request to \a id
 *
 * Note that in general, this parameter will be supplied by the secrets service,
 * so any value set by the client application here will have no effect.
 */
void InteractionParameters::setApplicationId(const QString &id)
{
    if (d_ptr->m_applicationId != id) {
        d_ptr->m_applicationId = id;
    }
}

/*!
 * \brief Returns the type of operation which will be performed with the user input once received
 */
InteractionParameters::Operation InteractionParameters::operation() const
{
    return d_ptr->m_operation;
}

/*!
 * \brief Sets the type of operation which will be performed with the user input once received to \a op
 *
 * Note that in general, this parameter will be supplied by the secrets service,
 * so any value set by the client application here will have no effect.
 */
void InteractionParameters::setOperation(Operation op)
{
    if (d_ptr->m_operation != op) {
        d_ptr->m_operation = op;
    }
}

/*!
 * \brief Returns the name of the authentication plugin which will provide the user input flow
 */
QString InteractionParameters::authenticationPluginName() const
{
    return d_ptr->m_authenticationPluginName;
}

/*!
 * \brief Sets the name of the authentication plugin which will provide the user input flow to \a pluginName
 *
 * If no authentication plugin name is specified, the default system authentication
 * plugin for the specified inputType() will be used.
 */
void InteractionParameters::setAuthenticationPluginName(const QString &pluginName)
{
    if (d_ptr->m_authenticationPluginName != pluginName) {
        d_ptr->m_authenticationPluginName = pluginName;
    }
}

/*!
 * \brief Returns the application-specified prompt text to be displayed as part of the user input flow
 */
QString InteractionParameters::promptText() const
{
    return d_ptr->m_promptText;
}

/*!
 * \brief Sets the application-specified prompt text to be displayed as part of the user input flow to \a prompt
 */
void InteractionParameters::setPromptText(const QString &prompt)
{
    if (d_ptr->m_promptText != prompt) {
        d_ptr->m_promptText = prompt;
    }
}

/*!
 * \brief Returns the translation id of the system-dialog prompt text to be displayed as part of the user input flow
 */
QString InteractionParameters::promptTrId() const
{
    return d_ptr->m_promptTrId;
}

/*!
 * \brief Sets the translation id of the system-dialog prompt text to be displayed as part of the user input flow to \a trId
 *
 * Note that this field will be supplied by the secrets service for system-mediated user interaction flows,
 * so any value set by client applications will have no effect.
 */
void InteractionParameters::setPromptTrId(const QString &trId)
{
    if (d_ptr->m_promptTrId != trId) {
        d_ptr->m_promptTrId = trId;
    }
}

/*!
 * \brief Returns the type of input required from the user
 */
InteractionParameters::InputType InteractionParameters::inputType() const
{
    return d_ptr->m_inputType;
}

/*!
 * \brief Sets the type of input required from the user to \a type
 */
void InteractionParameters::setInputType(InteractionParameters::InputType type)
{
    if (d_ptr->m_inputType != type) {
        d_ptr->m_inputType = type;
    }
}

/*!
 * \brief Returns the echo mode which should apply as the user provides the input
 */
InteractionParameters::EchoMode InteractionParameters::echoMode() const
{
    return d_ptr->m_echoMode;
}

/*!
 * \brief Sets the echo mode which should apply as the user provides the input to \a mode
 */
void InteractionParameters::setEchoMode(InteractionParameters::EchoMode mode)
{
    if (d_ptr->m_echoMode != mode) {
        d_ptr->m_echoMode = mode;
    }
}
