#ifndef SF_SECRETS_MANAGER_H
#define SF_SECRETS_MANAGER_H

#define SF_TYPE_SECRETS_MANAGER (sf_secrets_manager_get_type())
#define SF_SECRETS_MANAGER(o) (G_TYPE_CHECK_INSTANCE_CAST((o), SF_TYPE_SECRETS_MANAGER, SfSecretsManager))
#define SF_IS_SECRETS_MANAGER(o) (G_TYPE_CHECK_INSTANCE_TYPE((o), SF_TYPE_SECRETS_MANAGER))

#include <glib-object.h>
#include <gio/gio.h>

#include <sf-secrets.h>
#include <sf-secrets-secret.h>

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
gboolean sf_secrets_manager_get_health_info_finish(GAsyncResult *res,
		gboolean *is_healthy,
		SfSecretsHealth *salt_data_health,
		SfSecretsHealth *master_lock_health,
		GError **error);

/* userInput */
void sf_secrets_manager_collection_names(SfSecretsManager *manager,
		const gchar *plugin_name,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
gchar **sf_secrets_manager_collection_names_finish(GAsyncResult *res,
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
gboolean sf_secrets_manager_create_collection_finish(GAsyncResult *res,
		GError **error);

void sf_secrets_manager_delete_collection(SfSecretsManager *manager,
		const gchar *plugin_name,
		const gchar *collection_name,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
gboolean sf_secrets_manager_delete_collcetion_finish(GAsyncResult *res,
		GError **error);

void sf_secrets_manager_set_secret(SfSecretsManager *manager,
		SfSecretsSecret *secret,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
void sf_secrets_manager_set_secret_standalone(SfSecretsManager *manager,
		SfSecretsSecret *secret,
		const gchar *encryption_plugin_name,
		const gchar *authentication_plugin,
		SfSecretsDeviceUnlockSemantic unlock_semantic,
		SfSecretsAccessControlMode access_control_mode,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
gboolean sf_secrets_collection_set_secret_finish(GAsyncResult *res, GError **error);

void sf_secrets_manager_get_secret(SfSecretsManager *manager,
		const gchar *secret_name,
		const gchar *collection_name,
		const gchar *storage_plugin,
		GCancellable *cancellable,
		GAsyncReadyCallback cb,
		gpointer user_data);
SfSecretsSecret *sf_secrets_manager_get_secret_finish(GAsyncResult *res,
		GError **error);

void sf_secrets_manager_find_secrets_va(SfSecretsManager *manager,
		const gchar *collection_name,
		const gchar *plugin_name,
		SfSecretsFilterOperator op,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data,
		const gchar *first_filter_name,
		va_list args);
void sf_secrets_manager_find_secrets_ht(SfSecretsManager *manager,
		const gchar *collection_name,
		const gchar *plugin_name,
		GHashTable *filters,
		SfSecretsFilterOperator op,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
void sf_secrets_manager_find_secrets(SfSecretsManager *manager,
		const gchar *collection_name,
		const gchar *plugin_name,
		SfSecretsFilterOperator op,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data,
		const gchar *first_filter_name,
		...);
gchar **sf_secrets_manager_find_secrets_finish(GAsyncResult *res, GError **error);

void sf_secrets_manager_delete_secret_by_name(SfSecretsManager *manager,
		const gchar *name,
		const gchar *collection_name,
		const gchar *plugin_name,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
void sf_secrets_manager_delete_secret(SfSecretsManager *manager,
		SfSecretsSecret *secret,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
gboolean sf_secrets_manager_delete_secret_finish(GAsyncResult *res,
		GError **error);

void sf_secrets_manager_query_lock_status(SfSecretsManager *manager,
		SfSecretsLockCodeTargetType target_type,
		const gchar *target,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
SfSecretsLockStatus sf_secrets_manager_query_lock_status_finish(GAsyncResult *res,
		GError **error);

void sf_secrets_manager_modify_lock_code(SfSecretsManager *manager,
		SfSecretsLockCodeTargetType target_type,
		const gchar *target,
		const gchar *authentication_plugin_name,
		SfSecretsInputType input_type,
		SfSecretsEchoMode echo_mode,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
gboolean sf_secrets_manager_modify_lock_code_finish(GAsyncResult *res,
		GError **error);

void sf_secrets_manager_provide_lock_code(SfSecretsManager *manager,
		SfSecretsLockCodeTargetType target_type,
		const gchar *target,
		const gchar *authentication_plugin_name,
		SfSecretsInputType input_type,
		SfSecretsEchoMode echo_mode,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
gboolean sf_secrets_manager_provide_lock_code_finish(GAsyncResult *res,
		GError **error);

void sf_secrets_manager_forget_lock_code(SfSecretsManager *manager,
		SfSecretsLockCodeTargetType target_type,
		const gchar *target,
		const gchar *authentication_plugin_name,
		SfSecretsInputType input_type,
		SfSecretsEchoMode echo_mode,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
gboolean sf_secrets_manager_forget_lock_code_finish(GAsyncResult *res,
		GError **error);

#endif /* SF_SECRETS_MANAGER_H */
