#include "sf-secrets-secret.h"
#include "sf-secrets-manager.h"
#include "sf-secrets-collection.h"

enum SfSecretSecretProperties {
	PROP_MANAGER = 1,
	PROP_COLLECTION,
	PROP_PLUGIN_NAME,
	PROP_IDENTIFIER,
	PROP_FILTER_FIELDS,
	PROP_DATA
};

typedef struct SfSecretsSecretPrivate_ SfSecretsSecretPrivate;

struct SfSecretsSecretPrivate_
{
	SfSecretsManager *manager;
	SfSecretsCollection *collection;
	gchar *plugin_name;
	gchar *identifier;
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

		case PROP_COLLECTION:
			g_value_set_object(value, priv->collection);
			break;

		case PROP_PLUGIN_NAME:
			g_value_set_string(value, priv->plugin_name);
			break;

		case PROP_IDENTIFIER:
			g_value_set_string(value, priv->identifier);
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

		case PROP_COLLECTION:
			if (priv->collection)
				g_object_unref(priv->collection);
			priv->collection = g_value_dup_object(value);
			break;

		case PROP_PLUGIN_NAME:
			if (priv->plugin_name)
				g_free(priv->plugin_name);
			priv->plugin_name = g_value_dup_string(value);
			break;

		case PROP_IDENTIFIER:
			if (priv->identifier)
				g_free(priv->identifier);
			priv->identifier = g_value_dup_string(value);
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
			PROP_PLUGIN_NAME,
			g_param_spec_string("plugin-name",
				"plugin-name",
				"Backend plugin name",
				NULL,
				G_PARAM_READWRITE |
				G_PARAM_CONSTRUCT_ONLY |
				G_PARAM_STATIC_STRINGS));

	g_object_class_install_property(G_OBJECT_CLASS(secret_class),
			PROP_IDENTIFIER,
			g_param_spec_string("identifier",
				"identifier",
				"Secret identifier",
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

const gchar *sf_secrets_secret_get_identifier(SfSecretsSecret *secret)
{
	SfSecretsSecretPrivate *priv = sf_secrets_secret_get_instance_private(secret);

	return priv->identifier;
}
