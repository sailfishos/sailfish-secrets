#include "sf-secrets-secret.h"
#include "sf-secrets-manager.h"

enum SfSecretSecretProperties {
	PROP_MANAGER = 1,
	PROP_PLUGIN_NAME,
	PROP_COLLECTION_NAME,
	PROP_NAME,
	PROP_FILTER_FIELDS,
	PROP_DATA
};

typedef struct SfSecretsSecretPrivate_ SfSecretsSecretPrivate;

struct SfSecretsSecretPrivate_
{
	SfSecretsManager *manager;
	gchar *collection_name;
	gchar *plugin_name;
	gchar *name;
	GHashTable *filter_fields;
	GBytes *data;
};

G_DEFINE_TYPE_WITH_CODE(SfSecretsSecret, sf_secrets_secret, G_TYPE_INITIALLY_UNOWNED,
		G_ADD_PRIVATE(SfSecretsSecret))

static void _sf_secrets_secret_finalize(GObject *object)
{
	SfSecretsSecret *secret = SF_SECRETS_SECRET(object);
	SfSecretsSecretPrivate *priv = sf_secrets_secret_get_instance_private(secret);

	if (priv->filter_fields)
		g_hash_table_unref(priv->filter_fields);

	if (priv->manager)
		g_object_unref(priv->manager);

	if (priv->data)
		g_bytes_unref(priv->data);

	if (priv->name)
		g_free(priv->name);
	if (priv->collection_name)
		g_free(priv->collection_name);
	if (priv->plugin_name)
		g_free(priv->plugin_name);
}

static void _sf_secrets_secret_get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
	SfSecretsSecret *secret = SF_SECRETS_SECRET(object);
	SfSecretsSecretPrivate *priv = sf_secrets_secret_get_instance_private(secret);

	(void)pspec;

	switch (prop_id) {
		case PROP_MANAGER:
			g_value_set_object(value, priv->manager);
			break;

		case PROP_COLLECTION_NAME:
			g_value_set_string(value, priv->collection_name);
			break;

		case PROP_NAME:
			g_value_set_string(value, priv->name);
			break;

		case PROP_PLUGIN_NAME:
			g_value_set_string(value, priv->plugin_name);
			break;

		case PROP_FILTER_FIELDS:
			g_value_set_boxed(value, priv->filter_fields);
			break;

		case PROP_DATA:
			g_value_set_boxed(value, priv->data);
			break;

		default:
			break;
	}
}

static void _sf_secrets_secret_set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
	SfSecretsSecret *secret = SF_SECRETS_SECRET(object);
	SfSecretsSecretPrivate *priv = sf_secrets_secret_get_instance_private(secret);

	(void)pspec;

	switch (prop_id) {
		case PROP_MANAGER:
			if (priv->manager)
				g_object_unref(priv->manager);
			priv->manager = g_value_dup_object(value);
			break;

		case PROP_PLUGIN_NAME:
			if (priv->plugin_name)
				g_free(priv->plugin_name);
			priv->plugin_name = g_value_dup_object(value);
			break;

		case PROP_COLLECTION_NAME:
			if (priv->collection_name)
				g_free(priv->collection_name);
			priv->collection_name = g_value_dup_object(value);
			break;

		case PROP_NAME:
			if (priv->name)
				g_free(priv->name);
			priv->name = g_value_dup_string(value);
			break;

		case PROP_FILTER_FIELDS:
			if (priv->filter_fields)
				g_hash_table_unref(priv->filter_fields);
			priv->filter_fields = g_value_dup_boxed(value);
			break;

		case PROP_DATA:
			if (priv->data)
				g_bytes_unref(priv->data);
			priv->data = g_value_dup_boxed(value);
			break;


		default:
			break;
	}
}

static void sf_secrets_secret_class_init(SfSecretsSecretClass *secret_class)
{
	G_OBJECT_CLASS(secret_class)->finalize = _sf_secrets_secret_finalize;
	G_OBJECT_CLASS(secret_class)->set_property = _sf_secrets_secret_set_property;
	G_OBJECT_CLASS(secret_class)->get_property = _sf_secrets_secret_get_property;

	g_object_class_install_property(G_OBJECT_CLASS(secret_class),
			PROP_MANAGER,
			g_param_spec_object("manager",
				"manager",
				"Secrets Manager",
				SF_TYPE_SECRETS_MANAGER,
				G_PARAM_READWRITE |
				G_PARAM_CONSTRUCT_ONLY |
				G_PARAM_STATIC_STRINGS));

	g_object_class_install_property(G_OBJECT_CLASS(secret_class),
			PROP_COLLECTION_NAME,
			g_param_spec_string("collection-name",
				"collection-name",
				"Collection name",
				NULL,
				G_PARAM_READWRITE |
				G_PARAM_STATIC_STRINGS));

	g_object_class_install_property(G_OBJECT_CLASS(secret_class),
			PROP_PLUGIN_NAME,
			g_param_spec_string("plugin-name",
				"plugin-name",
				"Storage plugin name",
				NULL,
				G_PARAM_READWRITE |
				G_PARAM_STATIC_STRINGS));

	g_object_class_install_property(G_OBJECT_CLASS(secret_class),
			PROP_NAME,
			g_param_spec_string("name",
				"name",
				"Secret name",
				NULL,
				G_PARAM_READWRITE |
				G_PARAM_STATIC_STRINGS));

	g_object_class_install_property(G_OBJECT_CLASS(secret_class),
			PROP_FILTER_FIELDS,
			g_param_spec_boxed("filter-fields",
				"filter-fields",
				"Fields for filtering",
				G_TYPE_HASH_TABLE,
				G_PARAM_READWRITE |
				G_PARAM_STATIC_STRINGS));

	g_object_class_install_property(G_OBJECT_CLASS(secret_class),
			PROP_DATA,
			g_param_spec_boxed("data",
				"data",
				"Secret data",
				G_TYPE_BYTES,
				G_PARAM_READWRITE |
				G_PARAM_STATIC_STRINGS));
}

static void sf_secrets_secret_init(SfSecretsSecret *secret)
{
	(void)secret;
}

void sf_secrets_secret_set_filter_field(SfSecretsSecret *secret, const gchar *key, const gchar *value)
{
	SfSecretsSecretPrivate *priv = sf_secrets_secret_get_instance_private(secret);

	if (!priv->filter_fields) {
		if (!value)
			return;
		priv->filter_fields = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	}

	if (!value)
		g_hash_table_remove(priv->filter_fields, key);
	else
		g_hash_table_replace(priv->filter_fields, g_strdup(key), g_strdup(value));
}

const gchar *sf_secrets_secret_get_filter_field(SfSecretsSecret *secret, const gchar *key)
{
	SfSecretsSecretPrivate *priv = sf_secrets_secret_get_instance_private(secret);

	if (!priv->filter_fields)
		return NULL;
	return g_hash_table_lookup(priv->filter_fields, key);
}

const gchar *sf_secrets_secret_get_name(SfSecretsSecret *secret)
{
	SfSecretsSecretPrivate *priv = sf_secrets_secret_get_instance_private(secret);

	return priv->name;
}
const gchar *sf_secrets_secret_get_collection_name(SfSecretsSecret *secret)
{
	SfSecretsSecretPrivate *priv = sf_secrets_secret_get_instance_private(secret);

	return priv->collection_name;
}
const gchar *sf_secrets_secret_get_plugin_name(SfSecretsSecret *secret)
{
	SfSecretsSecretPrivate *priv = sf_secrets_secret_get_instance_private(secret);

	return priv->plugin_name;
}
