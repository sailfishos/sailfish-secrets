#ifndef SF_CRYPTO_MANAGER_H
#define SF_CRYPTO_MANAGER_H

#define SF_TYPE_CRYPTO_MANAGER (sf_crypto_manager_get_type())
#define SF_CRYPTO_MANAGER(o) (G_TYPE_CHECK_INSTANCE_CAST((o), SF_TYPE_CRYPTO_MANAGER, SfCryptoManager))
#define SF_IS_CRYPTO_MANAGER(o) (G_TYPE_CHECK_INSTANCE_TYPE((o), SF_TYPE_CRYPTO_MANAGER))

#include "sf-crypto.h"
#include "sf-crypto-key.h"

#include <glib-object.h>
#include <gio/gio.h>

typedef struct SfCryptoManager_ SfCryptoManager;
typedef struct SfCryptoManagerClass_ SfCryptoManagerClass;

struct SfCryptoManager_ {
	GObject parent;
};

struct SfCryptoManagerClass_ {
	GObjectClass parent_class;
};

struct SfCryptoKpgParams_ {
	SfCryptoKeyPairType type;
	GHashTable *custom_params;
	GHashTable *type_params;
};
typedef struct SfCryptoKpgParams_ SfCryptoKpgParams;

struct SfCryptoSkdfParams_ {
	GBytes *input_data;
	GBytes *salt;
	SfCryptoKdf function;
	SfCryptoMac mac;
	SfCryptoAlgorithm algorithm;
	SfCryptoDigest digest;
	gint64 memory_size;
	gint32 iterations;
	gint32 parallelism;
	gint32 key_size;
	GHashTable *custom_params;
};
typedef struct SfCryptoSkdfParams_ SfCryptoSkdfParams;

GType sf_crypto_manager_get_type(void);
void sf_crypto_manager_new(GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
SfCryptoManager *sf_crypto_manager_new_finish(GAsyncResult *res, GError **error);

void sf_crypto_manager_get_plugin_info(SfCryptoManager *manager,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
gboolean sf_crypto_manager_get_plugin_info_finish(GAsyncResult *res,
		GSList **crypto_plugins,
		GSList **storage_plugins,
		GError **error);

void sf_crypto_manager_generate_random_data(SfCryptoManager *manager,
		guint64 amount,
		const gchar *engine_name,
		GHashTable *custom_parameters,
		const gchar *provider_name,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
GBytes *sf_crypto_manager_generate_random_data_finish(GAsyncResult *res, GError **error);

void sf_crypto_manager_seed_random_data_generator(SfCryptoManager *manager,
		GBytes *seed_data,
		gdouble entropy_estimate,
		const gchar *engine_name,
		GHashTable *custom_params,
		const gchar *crypto_provider,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
gboolean sf_crypto_manager_seed_random_data_generator_finish(GAsyncResult *res, GError **error);

void sf_crypto_manager_generate_initialization_vector(SfCryptoManager *manager,
		SfCryptoAlgorithm algorithm,
		SfCryptoBlockMode block_mode,
		gint key_size,
		GHashTable *custom_params,
		const gchar *crypto_provider,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
GBytes *sf_crypto_manager_generate_initialization_vector_finish(GAsyncResult *res, GError **error);

void sf_crypto_manager_generate_key(SfCryptoManager *manager,
		SfCryptoKey *key_template,
		SfCryptoKpgParams *kpg_params,
		SfCryptoSkdfParams *skdf_params,
		GHashTable *custom_params,
		const gchar *crypto_provider,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
SfCryptoKey *sf_crypto_manager_generate_key_finish(GAsyncResult *res, GError **error);

void sf_crypto_manager_generate_stored_key(SfCryptoManager *manager,
		SfCryptoKey *key_template,
		SfCryptoKpgParams *kpg_params,
		SfCryptoSkdfParams *skdf_params,
		const gchar *authentication_plugin,
		SfCryptoInputType input_type,
		SfCryptoEchoMode echo_mode,
		GHashTable *custom_params,
		const gchar *crypto_provider,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
SfCryptoKey *sf_crypto_manager_generate_stored_key_finish(GAsyncResult *res, GError **error);

void sf_crypto_manager_import_key(SfCryptoManager *manager,
		GBytes *data,
		const gchar *authentication_plugin,
		SfCryptoInputType input_type,
		SfCryptoEchoMode echo_mode,
		GHashTable *custom_params,
		const gchar *crypto_provider,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
SfCryptoKey *sf_crypto_manager_import_key_finish(GAsyncResult *res, GError **error);

void sf_crypto_manager_import_stored_key(SfCryptoManager *manager,
		GBytes *data,
		SfCryptoKey *key_template,
		const gchar *authentication_plugin,
		SfCryptoInputType input_type,
		SfCryptoEchoMode echo_mode,
		GHashTable *custom_params,
		const gchar *crypto_provider,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
SfCryptoKey *sf_crypto_manager_import_stored_key_finish(GAsyncResult *res, GError **error);

void sf_crypto_manager_stored_key(SfCryptoManager *manager,
		const gchar *name,
		const gchar *collection_name,
		const gchar *plugin_name,
		SfCryptoKeyConstraint components,
		GHashTable *custom_params,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
SfCryptoKey *sf_crypto_manager_stored_key_finish(GAsyncResult *res, GError **error);

void sf_crypto_manager_delete_stored_key(SfCryptoManager *manager,
		const gchar *name,
		const gchar *collection_name,
		const gchar *plugin_name,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
gboolean sf_crypto_manager_delete_stored_key_finish(GAsyncResult *res, GError **error);

void sf_crypto_manager_stored_key_names(SfCryptoManager *manager,
		const gchar *plugin_name,
		const gchar *collection_name,
		GHashTable *custom_params,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
gchar **sf_crypto_manager_stored_key_names_finish(GAsyncResult *res, GError **error);

void sf_crypto_manager_sign(SfCryptoManager *manager,
		GBytes *data,
		SfCryptoKey *key,
		SfCryptoSignaturePadding padding,
		SfCryptoDigest digest,
		GHashTable *custom_params,
		const gchar *crypto_provider,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
GBytes *sf_crypto_manager_sign_finish(GAsyncResult *res, GError **error);

void sf_crypto_manager_verify(SfCryptoManager *manager,
		GBytes *signature,
		GBytes *data,
		SfCryptoKey *key,
		SfCryptoSignaturePadding padding,
		SfCryptoDigest digest,
		GHashTable *custom_params,
		const gchar *crypto_provider,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
SfCryptoVerificationStatus sf_crypto_manager_verify_finish(GAsyncResult *res, GError **error);

void sf_crypto_manager_encrypt(SfCryptoManager *manager,
		GBytes *data,
		GBytes *iv,
		SfCryptoKey *key,
		SfCryptoBlockMode block_mode,
		SfCryptoEncryptionPadding padding,
		GBytes *authentication_data,
		GHashTable *custom_params,
		const gchar *crypto_provider,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
GBytes *sf_crypto_manager_encrypt_finish(GAsyncResult *res, GBytes **tag, GError **error);

void sf_crypto_manager_decrypt(SfCryptoManager *manager,
		GBytes *data,
		GBytes *iv,
		SfCryptoKey *key,
		SfCryptoBlockMode block_mode,
		SfCryptoEncryptionPadding padding,
		GBytes *authentication_data,
		GBytes *authentication_tag,
		GHashTable *custom_params,
		const gchar *crypto_provider,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
GBytes *sf_crypto_manager_decrypt_finish(GAsyncResult *res, SfCryptoVerificationStatus *status, GError **error);

void sf_crypto_manager_calculate_digest(SfCryptoManager *manager,
		GBytes *data,
		SfCryptoSignaturePadding padding,
		SfCryptoDigest digest,
		GHashTable *custom_params, /* gchar * => GVariant * */
		const gchar *crypto_provider,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
GBytes *sf_crypto_manager_calculate_digest_finish(GAsyncResult *res, GError **error);

/*
void sf_crypto_manager_query_lock_status(SfCryptoManager *manager,
		SfCryptoLockCodeTargetType target_type,
		const gchar *target,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
SfCryptoLockStatus sf_crypto_manager_query_lock_status_finish(GAsyncResult *res,
		GError **error);

void sf_crypto_manager_modify_lock_code(SfCryptoManager *manager,
		SfCryptoLockCodeTargetType target_type,
		const gchar *target,
		const gchar *authentication_plugin_name,
		SfCryptoInputType input_type,
		SfCryptoEchoMode echo_mode,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
gboolean sf_crypto_manager_modify_lock_code_finish(GAsyncResult *res,
		GError **error);

void sf_crypto_manager_provide_lock_code(SfCryptoManager *manager,
		SfCryptoLockCodeTargetType target_type,
		const gchar *target,
		const gchar *authentication_plugin_name,
		SfCryptoInputType input_type,
		SfCryptoEchoMode echo_mode,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
gboolean sf_crypto_manager_provide_lock_code_finish(GAsyncResult *res,
		GError **error);

void sf_crypto_manager_forget_lock_code(SfCryptoManager *manager,
		SfCryptoLockCodeTargetType target_type,
		const gchar *target,
		const gchar *authentication_plugin_name,
		SfCryptoInputType input_type,
		SfCryptoEchoMode echo_mode,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
gboolean sf_crypto_manager_forget_lock_code_finish(GAsyncResult *res,
		GError **error);

		*/
#endif /* SF_CRYPTO_MANAGER_H */
