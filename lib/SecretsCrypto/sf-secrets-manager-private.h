#ifndef SF_SECRETS_MANAGER_PRIVATE_H
#define SF_SECRETS_MANAGER_PRIVATE_H

#include "sf-secrets-manager.h"
#include "sf-secrets.h"

GDBusProxy *_sf_secrets_manager_get_dbus_proxy(SfSecretsManager *manager);
gboolean _sf_secrets_manager_check_reply(GVariant *response, GError **error, GVariantIter *iter);
void _sf_secrets_manager_get_interaction_mode(SfSecretsManager *manager,
		SfSecretsUserInteractionMode *mode,
		const gchar **user_interaction_service_address);
void _sf_secrets_manager_result_only_ready(GObject *source_object, GAsyncResult *res, gpointer user_data);

#endif /* SF_SECRETS_MANAGER_PRIVATE_H */
