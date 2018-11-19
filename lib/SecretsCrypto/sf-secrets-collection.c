#include "sf-secrets-collection.h"
#include "sf-secrets-manager-private.h"

enum SfSecretCollectionProperties {
	PROP_MANAGER = 1,
	PROP_PLUGIN_NAME,
	PROP_ENCRYPTION_PLUGIN_NAME,
	PROP_NAME,
	PROP_FLAGS,
};

typedef struct SfSecretsCollectionPrivate_ SfSecretsCollectionPrivate;

struct SfSecretsCollectionPrivate_
{
	SfSecretsManager *manager;
	gchar *plugin_name;
	gchar *encryption_plugin_name;
	gchar *name;
	SfSecretsCollectionFlags flags;
};

static void _async_initable_iface_init (GAsyncInitableIface *async_initable_iface);
static void _async_initable_init_async (GAsyncInitable *initable,
		gint io_priority,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data);
static gboolean _async_initable_init_finish (GAsyncInitable *initable,
		GAsyncResult *res,
		GError **error);

G_DEFINE_TYPE_WITH_CODE(SfSecretsCollection, sf_secrets_collection, G_TYPE_OBJECT,
		G_ADD_PRIVATE(SfSecretsCollection)
		G_IMPLEMENT_INTERFACE(G_TYPE_ASYNC_INITABLE, _async_initable_iface_init))

static void _sf_secrets_collection_get_collection_names_ready(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	SfSecretsCollection *collection = g_task_get_source_object(user_data);
	SfSecretsCollectionPrivate *priv = sf_secrets_collection_get_instance_private(collection);
	GTask *task = user_data;
	GError *error = NULL;
	GVariant *response = g_dbus_proxy_call_finish(G_DBUS_PROXY(source_object),
			res, &error);
	GVariantIter iter;
	GVariant *dict;
	const gchar *key;
	gboolean found = FALSE;

	if (error) {
		g_task_return_error(task, error);
		return;
	}

	if (!_sf_secrets_manager_check_reply(response, &error, &iter)) {
		g_task_return_error(task, error);
		g_variant_unref(response);
		return;
	}

	dict = g_variant_iter_next_value(&iter);
	g_variant_iter_init(&iter, dict);
	while (g_variant_iter_loop(&iter, "{&sb}", &key, NULL)) {
		if (!g_strcmp0(key, priv->name)) {
			found = TRUE;
			break;
		}
	}

	if (!found) {
		if (priv->flags & SF_SECRETS_COLLECTION_CREATE) {
			g_task_return_new_error(task,
					g_quark_from_static_string("SfSecrets"),
						501,
						"Collection creation not implemented");
			return;
		} else {
			g_task_return_new_error(task,
					g_quark_from_static_string("SfSecrets"),
						404,
						"Collection %s not found",
						priv->name);
			return;
		}
	}

	g_task_return_boolean(task, TRUE);
}

static void _async_initable_init_async (GAsyncInitable *initable,
		gint io_priority,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data)
{
	GTask *task = g_task_new(initable, cancellable, callback, user_data);
	SfSecretsCollection *collection = SF_SECRETS_COLLECTION(initable);
	SfSecretsCollectionPrivate *priv = sf_secrets_collection_get_instance_private(collection);
	GDBusProxy *proxy;

	g_task_set_priority(task, io_priority);

	if (!priv->manager) {
		g_task_return_new_error(
				task,
				g_quark_from_static_string("SfSecrets"),
				1337,
				"No manager");
		return;
	}

	proxy = _sf_secrets_manager_get_dbus_proxy(priv->manager);

	g_dbus_proxy_call(proxy,
			"collectionNames",
			g_variant_new("(s)", priv->plugin_name),
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			cancellable,
			_sf_secrets_collection_get_collection_names_ready,
			task);
}

static gboolean _async_initable_init_finish (GAsyncInitable *initable,
		GAsyncResult *res,
		GError **error)
{
	(void)initable;
	return g_task_propagate_boolean(G_TASK(res), error);
}

static void sf_secrets_collection_init(SfSecretsCollection *collection)
{
	(void)collection;
}

static void _sf_secrets_collection_finalize(GObject *object)
{
	SfSecretsCollection *collection = SF_SECRETS_COLLECTION(object);
	SfSecretsCollectionPrivate *priv = sf_secrets_collection_get_instance_private(collection);

	if (priv->manager)
		g_object_unref(priv->manager);
	if (priv->plugin_name)
		g_free(priv->plugin_name);
	if (priv->name)
		g_free(priv->name);
}

static void _sf_secrets_collection_get_property(GObject *object, guint property_id, GValue *value, GParamSpec *spec)
{
	SfSecretsCollection *collection = SF_SECRETS_COLLECTION(object);
	SfSecretsCollectionPrivate *priv = sf_secrets_collection_get_instance_private(collection);

	(void)spec;

	switch (property_id) {
		case PROP_MANAGER:
			g_value_set_object(value, priv->manager);
			break;
		case PROP_PLUGIN_NAME:
			g_value_set_string(value, priv->plugin_name);
			break;
		case PROP_ENCRYPTION_PLUGIN_NAME:
			g_value_set_string(value, priv->encryption_plugin_name);
			break;
		case PROP_NAME:
			g_value_set_string(value, priv->name);
			break;
		case PROP_FLAGS:
			g_value_set_uint(value, priv->flags);
			break;
		default:
			g_warning("Unknown property %u", property_id);
			break;
	}
}

static void _sf_secrets_collection_set_property(GObject *object, guint property_id, const GValue *value, GParamSpec *spec)
{
	SfSecretsCollection *collection = SF_SECRETS_COLLECTION(object);
	SfSecretsCollectionPrivate *priv = sf_secrets_collection_get_instance_private(collection);

	(void)spec;

	switch (property_id) {
		case PROP_MANAGER:
			if (priv->manager)
				g_object_unref(priv->manager);
			priv->manager = g_value_dup_object(value);
			break;
		case PROP_PLUGIN_NAME:
			if (priv->plugin_name)
				g_free(priv->plugin_name);
			priv->plugin_name = g_value_dup_string(value);
			break;
		case PROP_ENCRYPTION_PLUGIN_NAME:
			if (priv->encryption_plugin_name)
				g_free(priv->encryption_plugin_name);
			priv->encryption_plugin_name = g_value_dup_string(value);
			break;
		case PROP_NAME:
			if (priv->name)
				g_free(priv->name);
			priv->name = g_value_dup_string(value);
			break;
		case PROP_FLAGS:
			priv->flags = g_value_get_uint(value);
			break;
		default:
			g_warning("Unknown property %u", property_id);
			break;
	}
}

void sf_secrets_collection_class_init(SfSecretsCollectionClass *collection_class)
{
	G_OBJECT_CLASS(collection_class)->finalize = _sf_secrets_collection_finalize;
	G_OBJECT_CLASS(collection_class)->set_property = _sf_secrets_collection_set_property;
	G_OBJECT_CLASS(collection_class)->get_property = _sf_secrets_collection_get_property;

	g_object_class_install_property(G_OBJECT_CLASS(collection_class),
			PROP_MANAGER,
			g_param_spec_object("manager",
				"manager",
				"Secrets Manager",
				SF_TYPE_SECRETS_MANAGER,
				G_PARAM_READWRITE |
				G_PARAM_CONSTRUCT_ONLY |
				G_PARAM_STATIC_STRINGS));

	g_object_class_install_property(G_OBJECT_CLASS(collection_class),
			PROP_PLUGIN_NAME,
			g_param_spec_string("plugin-name",
				"plugin-name",
				"Backend plugin name",
				NULL,
				G_PARAM_READWRITE |
				G_PARAM_CONSTRUCT_ONLY |
				G_PARAM_STATIC_STRINGS));

	g_object_class_install_property(G_OBJECT_CLASS(collection_class),
			PROP_ENCRYPTION_PLUGIN_NAME,
			g_param_spec_string("encryption-plugin-name",
				"encryption-plugin-name",
				"Encryption plugin name",
				NULL,
				G_PARAM_READWRITE |
				G_PARAM_CONSTRUCT_ONLY |
				G_PARAM_STATIC_STRINGS));

	g_object_class_install_property(G_OBJECT_CLASS(collection_class),
			PROP_NAME,
			g_param_spec_string("name",
				"name",
				"Collection name",
				NULL,
				G_PARAM_READWRITE |
				G_PARAM_CONSTRUCT_ONLY |
				G_PARAM_STATIC_STRINGS));

	g_object_class_install_property(G_OBJECT_CLASS(collection_class),
			PROP_FLAGS,
			g_param_spec_uint("flags",
				"flags",
				"Collection flags",
				0,
				1,
				0,
				G_PARAM_READWRITE |
				G_PARAM_CONSTRUCT_ONLY |
				G_PARAM_STATIC_STRINGS));

}

void sf_secrets_collection_new(SfSecretsManager *manager,
		const gchar *plugin_name,
		const gchar *encryption_plugin_name,
		const gchar *name,
		SfSecretsCollectionFlags flags,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data)
{
	g_async_initable_new_async(SF_TYPE_SECRETS_COLLECTION,
			G_PRIORITY_DEFAULT,
			cancellable,
			callback,
			user_data,
			"manager", manager,
			"plugin-name", plugin_name,
			"encryption-plugin-name", encryption_plugin_name,
			"name", name,
			"flags", flags,
			NULL);
}

SfSecretsCollection *sf_secrets_collection_new_finish(GAsyncResult *res,
		GError **error)
{
	GObject *src_obj = g_async_result_get_source_object(res);
	GObject *obj = g_async_initable_new_finish(G_ASYNC_INITABLE(src_obj),
			res, error);
	g_object_unref(src_obj);

	return SF_SECRETS_COLLECTION(obj);
}

static void _async_initable_iface_init (GAsyncInitableIface *async_initable_iface)
{
	async_initable_iface->init_async = _async_initable_init_async;
	async_initable_iface->init_finish = _async_initable_init_finish;
}
