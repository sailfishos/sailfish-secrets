#ifndef SF_SECRETS_INTERACTION_REQUEST_PRIVATE_H
#define SF_SECRETS_INTERACTION_REQUEST_PRIVATE_H

#include <glib-object.h>
#include <gio/gio.h>
#include "sf-secrets.h"

void _sf_secrets_interaction_request_set(SfSecretsInteractionRequest *request,
        GDBusMethodInvocation *invocation,
        const gchar *secret_name,
        const gchar *collection_name,
        const gchar *plugin_name,
        const gchar *application_id,
        SfSecretsOperation operation,
        const gchar *authentication_plugin_name,
        GHashTable *prompt_text,
        SfSecretsInputType input_type,
        SfSecretsEchoMode echo_mode);

#endif /* SF_SECRETS_INTERACTION_REQUEST_PRIVATE_H */
