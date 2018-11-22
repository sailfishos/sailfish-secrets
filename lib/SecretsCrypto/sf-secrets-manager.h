#ifndef SF_SECRETS_MANAGER_H
#define SF_SECRETS_MANAGER_H

#define SF_TYPE_SECRETS_MANAGER (sf_secrets_manager_get_type())
#define SF_SECRETS_MANAGER(o) (G_TYPE_CHECK_INSTANCE_CAST((o), SF_TYPE_SECRETS_MANAGER, SfSecretsManager))
#define SF_IS_SECRETS_MANAGER(o) (G_TYPE_CHECK_INSTANCE_TYPE((o), SF_TYPE_SECRETS_MANAGER))

#include <glib-object.h>
#include <gio/gio.h>

#include <sf-secrets.h>
#include <sf-secrets-collection.h>

typedef struct SfSecretsManager_ SfSecretsManager;
typedef struct SfSecretsManagerClass_ SfSecretsManagerClass;

struct SfSecretsManager_ {
	GObject parent;
};

struct SfSecretsManagerClass_ {
	GObjectClass parent_class;
};

GType sf_secrets_manager_get_type(void);
void sf_secrets_manager_new(GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
SfSecretsManager *sf_secrets_manager_new_finish(GAsyncResult *res, GError **error);

void sf_secrets_manager_get_health_info(SfSecretsManager *manager,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
gboolean sf_secrets_manager_get_health_info_finish(GAsyncResult *res, GError **error);

void sf_secrets_manager_get_collection(SfSecretsManager *manager,
		const gchar *plugin_name,
		const gchar *name,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
SfSecretsCollection *sf_secrets_manager_get_collection_finish(GAsyncResult *res,
		GError **error);

void sf_secrets_manager_create_collection(SfSecretsManager *manager,
		const gchar *plugin_name,
		const gchar *encryption_plugin_name,
		const gchar *authentication_plugin_name,
		const gchar *name,
		SfSecretsDeviceUnlockSemantic unlock_semantic,
		SfSecretsAccessControlMode access_control_mode,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
SfSecretsCollection *sf_secrets_manager_create_collection_finish(GAsyncResult *res,
		GError **error);

void sf_secrets_manager_ensure_collection(SfSecretsManager *manager,
		const gchar *plugin_name,
		const gchar *encryption_plugin_name,
		const gchar *authentication_plugin_name,
		const gchar *name,
		SfSecretsDeviceUnlockSemantic unlock_semantic,
		SfSecretsAccessControlMode access_control_mode,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
SfSecretsCollection *sf_secrets_manager_ensure_collection_finish(GAsyncResult *res,
		GError **error);

SfSecretsCollection *sf_secrets_manager_get_default_collection(SfSecretsManager *manager,
		const gchar *plugin_name,
		const gchar *encryption_plugin_name,
		const gchar *authentication_plugin_name,
		SfSecretsDeviceUnlockSemantic unlock_semantic,
		SfSecretsAccessControlMode access_control_mode);

#endif /* SF_SECRETS_MANAGER_H */
