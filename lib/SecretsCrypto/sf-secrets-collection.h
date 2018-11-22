#ifndef SF_SECRETS_COLLECTION_H
#define SF_SECRETS_COLLECTION_H

#include <glib-object.h>
#include <gio/gio.h>

#include <sf-secrets-secret.h>

#define SF_TYPE_SECRETS_COLLECTION (sf_secrets_collection_get_type())
#define SF_SECRETS_COLLECTION(o) (G_TYPE_CHECK_INSTANCE_CAST((o), SF_TYPE_SECRETS_COLLECTION, SfSecretsCollection))
#define SF_IS_SECRETS_COLLECTION(o) (G_TYPE_CHECK_INSTANCE_TYPE((o), SF_TYPE_SECRETS_COLLECTION))

typedef struct SfSecretsCollection_ SfSecretsCollection;
typedef struct SfSecretsCollectionClass_ SfSecretsCollectionClass;
typedef enum SfSecretsCollectionFlags_ SfSecretsCollectionFlags;

enum SfSecretsCollectionFlags_ {
	SF_SECRETS_COLLECTION_FLAGS_MODE_GET = 0 << 0,
	SF_SECRETS_COLLECTION_FLAGS_MODE_CREATE = 1 << 0,
	SF_SECRETS_COLLECTION_FLAGS_MODE_ENSURE = 2 << 0,
	SF_SECRETS_COLLECTION_FLAGS_MODE_DEFAULT = 3 << 0,
	SF_SECRETS_COLLECTION_FLAGS_MODE_MASK = 3 << 0,
};

struct SfSecretsCollection_ {
	GObject parent;
};

struct SfSecretsCollectionClass_ {
	GObjectClass parent_class;
};

GType sf_secrets_collection_get_type(void);

const gchar *sf_secrets_collection_get_plugin_name(SfSecretsCollection *collection);
const gchar *sf_secrets_collection_get_encryption_plugin_name(SfSecretsCollection *collection);
const gchar *sf_secrets_collection_get_name(SfSecretsCollection *collection);

void sf_secrets_collection_get_secret(SfSecretsCollection *collection,
		const gchar *identifier,
		GCancellable *cancellable,
		GAsyncReadyCallback cb,
		gpointer user_data);
SfSecretsSecret *sf_secrets_collection_get_secret_finish(GAsyncResult *res,
		GError **error);

void sf_secrets_collection_set_secret(SfSecretsCollection *collection,
		SfSecretsSecret *secret,
		GCancellable *cancellable,
		GAsyncReadyCallback cb,
		gpointer user_data);
gboolean sf_secrets_collection_set_secret_finish(GAsyncResult *res, GError **error);

void sf_secrets_collection_delete_secret(SfSecretsCollection *collection,
		SfSecretsSecret *secret,
		GCancellable *cancellable,
		GAsyncReadyCallback cb,
		gpointer user_data);
gboolean sf_secrets_collection_delete_secret_finish(GAsyncResult *res, GError **error);

void sf_secrets_collection_delete_secret_by_name(SfSecretsCollection *collection,
		const gchar *identifier,
		GCancellable *cancellable,
		GAsyncReadyCallback cb,
		gpointer user_data);
gboolean sf_secrets_collection_delete_secret_by_name_finish(GAsyncResult *res, GError **error);

#endif /* SF_SECRETS_COLLECTION_H */
