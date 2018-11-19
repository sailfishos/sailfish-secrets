#ifndef SF_SECRETS_MANAGER_PRIVATE_H
#define SF_SECRETS_MANAGER_PRIVATE_H

GDBusProxy *_sf_secrets_manager_get_dbus_proxy(SfSecretsManager *manager);
gboolean _sf_secrets_manager_check_reply(GVariant *response, GError **error, GVariantIter *iter);

#endif /* SF_SECRETS_MANAGER_PRIVATE_H */
