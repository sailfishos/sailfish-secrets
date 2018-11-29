#include "sf-secrets-collection.h"
#include "sf-secrets-manager-private.h"
#include "sf-secrets.h"

#include <stdarg.h>

enum SfSecretCollectionProperties {
	PROP_MANAGER = 1,
	PROP_PLUGIN_NAME,
	PROP_ENCRYPTION_PLUGIN_NAME,
	PROP_AUTHENTICATION_PLUGIN_NAME,
	PROP_NAME,
	PROP_FLAGS,
	PROP_ACCESS_CONTROL_MODE,
	PROP_DEVICE_UNLOCK_SEMANTIC
};

typedef struct SfSecretsCollectionPrivate_ SfSecretsCollectionPrivate;

struct SfSecretsCollectionPrivate_
{
	SfSecretsManager *manager;
	gchar *plugin_name;
	gchar *encryption_plugin_name;
	gchar *name;
	gchar *authentication_plugin_name;
	SfSecretsCollectionFlags flags;
	SfSecretsAccessControlMode access_control_mode;
	SfSecretsDeviceUnlockSemantic device_unlock_semantic;
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

static void _sf_secrets_collection_create_collection_ready(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	GTask *task = user_data;
	GError *error;
	GVariant *response = g_dbus_proxy_call_finish(G_DBUS_PROXY(source_object),
			res, &error);

	if (error) {
		g_task_return_error(task, error);
		g_object_unref(task);
		return;
	}

	if (!_sf_secrets_manager_check_reply(response, &error, NULL)) {
		g_task_return_error(task, error);
		g_object_unref(task);
		g_variant_unref(response);
		return;
	}

	g_variant_unref(response);
	g_task_return_boolean(task, TRUE);
	g_object_unref(task);
}

static void _sf_secrets_collection_create(SfSecretsCollection *collection,
		GTask *task)
{
	SfSecretsCollectionPrivate *priv = sf_secrets_collection_get_instance_private(collection);
	GDBusProxy *proxy = _sf_secrets_manager_get_dbus_proxy(priv->manager);
	GVariant *args;

	if (priv->authentication_plugin_name && *priv->authentication_plugin_name) {
		const gchar *interaction_service_address;
		SfSecretsUserInteractionMode mode;
		_sf_secrets_manager_get_interaction_mode(priv->manager, &mode, &interaction_service_address);
		args = g_variant_new("(ssss(i)(i)(i)s)",
				priv->name,
				priv->plugin_name,
				priv->encryption_plugin_name,
				priv->authentication_plugin_name,
				priv->device_unlock_semantic,
				priv->access_control_mode,
				mode,
				interaction_service_address);
	} else {
		args = g_variant_new("(ssss(i)(i))",
				priv->name,
				priv->plugin_name,
				priv->encryption_plugin_name,
				priv->device_unlock_semantic,
				priv->access_control_mode);
	}

	g_dbus_proxy_call(proxy,
			"createCollection",
			args,
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			g_task_get_cancellable(task),
			_sf_secrets_collection_create_collection_ready,
			task);
	g_object_unref(proxy);
}

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
		g_object_unref(task);
		return;
	}

	if (!_sf_secrets_manager_check_reply(response, &error, &iter)) {
		g_task_return_error(task, error);
		g_object_unref(task);
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
		if ((priv->flags & SF_SECRETS_COLLECTION_FLAGS_MODE_MASK) == SF_SECRETS_COLLECTION_FLAGS_MODE_ENSURE) {
			_sf_secrets_collection_create(collection, task);
			return;
		} else {
			g_task_return_new_error(task,
					g_quark_from_static_string("SfSecrets"),
						SF_SECRETS_ERROR_INVALID_COLLECTION,
						"Collection %s not found",
						priv->name);
			g_object_unref(task);
			return;
		}
	}

	g_task_return_boolean(task, TRUE);
	g_variant_unref(response);
	g_object_unref(task);
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
				SF_SECRETS_ERROR_UNKNOWN,
				"No manager defined");
		g_object_unref(task);
		return;
	}

	proxy = _sf_secrets_manager_get_dbus_proxy(priv->manager);

	if ((priv->flags & SF_SECRETS_COLLECTION_FLAGS_MODE_MASK) == SF_SECRETS_COLLECTION_FLAGS_MODE_CREATE) {
		_sf_secrets_collection_create(SF_SECRETS_COLLECTION(initable), task);
	} else {
		g_dbus_proxy_call(proxy,
				"collectionNames",
				g_variant_new("(s)", priv->plugin_name),
				G_DBUS_CALL_FLAGS_NONE,
				-1,
				cancellable,
				_sf_secrets_collection_get_collection_names_ready,
				task);
	}
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
		case PROP_AUTHENTICATION_PLUGIN_NAME:
			g_value_set_string(value, priv->authentication_plugin_name);
			break;
		case PROP_NAME:
			g_value_set_string(value, priv->name);
			break;
		case PROP_FLAGS:
			g_value_set_uint(value, priv->flags);
			break;
		case PROP_ACCESS_CONTROL_MODE:
			g_value_set_uint(value, priv->access_control_mode);
			break;
		case PROP_DEVICE_UNLOCK_SEMANTIC:
			g_value_set_uint(value, priv->device_unlock_semantic);
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
		case PROP_AUTHENTICATION_PLUGIN_NAME:
			if (priv->authentication_plugin_name)
				g_free(priv->authentication_plugin_name);
			priv->authentication_plugin_name = g_value_dup_string(value);
			break;
		case PROP_NAME:
			if (priv->name)
				g_free(priv->name);
			priv->name = g_value_dup_string(value);
			break;
		case PROP_FLAGS:
			priv->flags = g_value_get_uint(value);
			break;
		case PROP_ACCESS_CONTROL_MODE:
			priv->access_control_mode = g_value_get_uint(value);
			break;
		case PROP_DEVICE_UNLOCK_SEMANTIC:
			priv->device_unlock_semantic = g_value_get_uint(value);
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
			PROP_AUTHENTICATION_PLUGIN_NAME,
			g_param_spec_string("authentication-plugin-name",
				"authentication-plugin-name",
				"Authentication plugin name",
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

	g_object_class_install_property(G_OBJECT_CLASS(collection_class),
			PROP_ACCESS_CONTROL_MODE,
			g_param_spec_uint("access-control-mode",
				"access-control-mode",
				"Collection access control mode",
				SF_SECRETS_ACCESS_CONTROL_MODE_OWNER_ONLY,
				SF_SECRETS_ACCESS_CONTROL_MODE_NONE,
				0,
				G_PARAM_READWRITE |
				G_PARAM_CONSTRUCT_ONLY |
				G_PARAM_STATIC_STRINGS));

	g_object_class_install_property(G_OBJECT_CLASS(collection_class),
			PROP_DEVICE_UNLOCK_SEMANTIC,
			g_param_spec_uint("device-unlock-semantic",
				"device-unlock-semantic",
				"Collection device unlock semantic",
				SF_SECRETS_DEVICE_UNLOCK_SEMANTIC_KEEP_UNLOCKED,
				SF_SECRETS_DEVICE_UNLOCK_SEMANTIC_RELOCK,
				0,
				G_PARAM_READWRITE |
				G_PARAM_CONSTRUCT_ONLY |
				G_PARAM_STATIC_STRINGS));
}

static void _async_initable_iface_init (GAsyncInitableIface *async_initable_iface)
{
	async_initable_iface->init_async = _async_initable_init_async;
	async_initable_iface->init_finish = _async_initable_init_finish;
}

static void _sf_secrets_collection_get_secret_ready(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	GTask *task = user_data;
	SfSecretsCollection *collection = g_task_get_source_object(task);
	SfSecretsCollectionPrivate *priv = sf_secrets_collection_get_instance_private(collection);
	GError *error;
	GVariant *response = g_dbus_proxy_call_finish(G_DBUS_PROXY(source_object),
			res, &error);
	GVariantIter iter;
	GVariantIter secret_iter;
	GVariantIter *dict_iter;
	GVariant *array;
	GVariant *secret_variant;
	GBytes *secret_bytes;
	gsize secret_len;
	gconstpointer secret_data;
	SfSecretsSecret *secret;
	const gchar *identifier;

	if (error) {
		g_task_return_error(task, error);
		g_object_unref(task);
		return;
	}

	if (!_sf_secrets_manager_check_reply(response, &error, &iter)) {
		g_task_return_error(task, error);
		g_object_unref(task);
		g_variant_unref(response);
		return;
	}

	secret_variant = g_variant_iter_next_value(&iter);
	g_variant_iter_init(&secret_iter, secret_variant);

	if (!g_variant_iter_next(&secret_iter, "(&sss)", &identifier, NULL, NULL)) {
		g_variant_unref(secret_variant);
		g_task_return_new_error(task,
				g_quark_from_static_string("SfSecrets"),
				SF_SECRETS_ERROR_DAEMON,
				"Unable to parse daemon response");
		g_object_unref(task);
	}

	if (!(array = g_variant_iter_next_value(&secret_iter))) {
		g_variant_unref(array);
		g_variant_unref(secret_variant);
		g_task_return_new_error(task,
				g_quark_from_static_string("SfSecrets"),
				SF_SECRETS_ERROR_DAEMON,
				"Unable to parse daemon response");
		g_object_unref(task);
	}

	secret_data = g_variant_get_fixed_array(array, &secret_len, sizeof(guchar));
	secret_bytes = g_bytes_new(secret_data, secret_len);

	secret = g_object_new(SF_TYPE_SECRETS_SECRET,
			"manager", priv->manager,
			"collection", collection,
			"identifier", identifier,
			"data", secret_bytes,
			NULL);

	if (g_variant_iter_next(&secret_iter, "a{sv}", &dict_iter)) {
		const gchar *key;
		GVariant *value;

		while (g_variant_iter_loop(dict_iter, "{&sv}", &key, &value)) {
			if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING))
				sf_secrets_secret_set_filter_field(secret, key, g_variant_get_string(value, NULL));
		}
	}

	g_variant_unref(secret_variant);
	g_variant_unref(array);
	g_variant_unref(response);
	g_bytes_unref(secret_bytes);

	g_task_return_pointer(task, secret, g_object_unref);
	g_object_unref(task);
}

void sf_secrets_collection_get_secret(SfSecretsCollection *collection,
		const gchar *identifier,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data)
{
	SfSecretsCollectionPrivate *priv = sf_secrets_collection_get_instance_private(collection);
	GTask *task = g_task_new(collection, cancellable, callback, user_data);
	GDBusProxy *proxy = _sf_secrets_manager_get_dbus_proxy(priv->manager);
	const gchar *interaction_service_address;
	SfSecretsUserInteractionMode mode;

	_sf_secrets_manager_get_interaction_mode(priv->manager, &mode, &interaction_service_address);

	g_dbus_proxy_call(proxy,
			"getSecret",
			g_variant_new("((sss)(i)s)",
				priv->plugin_name,
				priv->name ?: "",
				identifier,
				mode,
				interaction_service_address),
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			g_task_get_cancellable(task),
			_sf_secrets_collection_get_secret_ready,
			task);

	g_object_unref(proxy);

}

SfSecretsSecret *sf_secrets_collection_get_secret_finish(GAsyncResult *res,
		GError **error)
{
	return g_task_propagate_pointer(G_TASK(res), error);
}

static void _sf_secrets_collection_set_secret_ready(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	_sf_secrets_manager_result_only_ready(source_object, res, user_data);
}

void sf_secrets_collection_set_secret(SfSecretsCollection *collection,
		SfSecretsSecret *secret,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data)
{
	SfSecretsCollectionPrivate *priv = sf_secrets_collection_get_instance_private(collection);
	GDBusProxy *proxy = _sf_secrets_manager_get_dbus_proxy(priv->manager);
	GTask *task = g_task_new(collection, cancellable, callback, user_data);
	GBytes *data;
	GVariant *args;
	GVariant *secret_data;
	GHashTable *filter_hash;
	GVariantDict filter_dict;
	GVariant *filters;
	const gchar *interaction_service_address;
	SfSecretsUserInteractionMode mode;

	_sf_secrets_manager_get_interaction_mode(priv->manager, &mode, &interaction_service_address);

	g_task_set_task_data(task, secret, g_object_unref);
	g_object_set(secret, "collection", collection, NULL);
	g_object_get(secret,
		"data", &data,
		"filters", &filter_hash, NULL);

	g_variant_dict_init(&filter_dict, NULL);

	if (filter_hash) {
		GHashTableIter iter;
		gpointer key, value;
		g_hash_table_iter_init(&iter, filter_hash);
		while (g_hash_table_iter_next(&iter, &key, &value))
			g_variant_dict_insert(&filter_dict, key, "s", value);
	}

	filters = g_variant_dict_end(&filter_dict);

	secret_data = g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE,
			g_bytes_get_data(data, NULL),
			g_bytes_get_size(data) / sizeof(guchar),
			sizeof(guchar));
	g_bytes_unref(data);

	if (priv->name) {
		args = g_variant_new("(((sss)@ay@a{sv})(ssss(i)s@a{is}(i)(i))(i)s)",
				priv->plugin_name,
				priv->name,
				sf_secrets_secret_get_identifier(secret),
				secret_data,
				filters,
				"", "", "", "", 0, "", g_variant_new_array(G_VARIANT_TYPE("{is}"), NULL, 0), 0, 0,
				mode, interaction_service_address);
	} else if (priv->authentication_plugin_name && *priv->authentication_plugin_name) {
		args = g_variant_new("(((sss)@ay@a{sv})(ssss(i)s@a{is}(i)(i))(i)(i)(i)s",
				priv->plugin_name,
				priv->encryption_plugin_name,
				priv->authentication_plugin_name,
				"",
				sf_secrets_secret_get_identifier(secret),
				secret_data,
				filters,
				"", "", "", "", 0, "", g_variant_new_array(G_VARIANT_TYPE("{is}"), NULL, 0), 0, 0,
				priv->device_unlock_semantic,
				priv->access_control_mode,
				mode, interaction_service_address);
	} else {
		args = g_variant_new("(((sss)@ay@a{sv})(ssss(i)s@a{is}(i)(i))(i)(i)(i)s",
				priv->plugin_name,
				priv->encryption_plugin_name,
				"",
				sf_secrets_secret_get_identifier(secret),
				secret_data,
				filters,
				"", "", "", "", 0, "", g_variant_new_array(G_VARIANT_TYPE("{is}"), NULL, 0), 0, 0,
				priv->device_unlock_semantic,
				priv->access_control_mode,
				mode, interaction_service_address);
	}

	g_dbus_proxy_call(proxy,
			"setSecret",
			args,
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			g_task_get_cancellable(task),
			_sf_secrets_collection_set_secret_ready,
			task);
}

gboolean sf_secrets_collection_set_secret_finish(GAsyncResult *res, GError **error)
{
	return g_task_propagate_boolean(G_TASK(res), error);
}

static void _sf_secrets_collection_delete_secret_ready(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	_sf_secrets_manager_result_only_ready(source_object, res, user_data);
}

void sf_secrets_collection_delete_secret(SfSecretsCollection *collection,
		SfSecretsSecret *secret,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data)
{
	sf_secrets_collection_delete_secret_by_name(collection,
			sf_secrets_secret_get_identifier(secret),
			cancellable,
			callback,
			user_data);
}

void sf_secrets_collection_delete_secret_by_name(SfSecretsCollection *collection,
		const gchar *secret_name,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data)
{
	GTask *task = g_task_new(collection, cancellable, callback, user_data);
	SfSecretsCollectionPrivate *priv = sf_secrets_collection_get_instance_private(collection);
	GDBusProxy *proxy;
	const gchar *interaction_service_address;
	SfSecretsUserInteractionMode mode;

	_sf_secrets_manager_get_interaction_mode(priv->manager, &mode, &interaction_service_address);

	if (!priv->manager) {
		g_task_return_new_error(
				task,
				g_quark_from_static_string("SfSecrets"),
				SF_SECRETS_ERROR_UNKNOWN,
				"No manager defined");
		g_object_unref(task);
		return;
	}

	proxy = _sf_secrets_manager_get_dbus_proxy(priv->manager);

	g_dbus_proxy_call(proxy,
			"collectionNames",
			g_variant_new("((sss)(i)s)",
				priv->plugin_name,
				priv->name ?: "",
				secret_name,
				mode,
				interaction_service_address),
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			cancellable,
			_sf_secrets_collection_delete_secret_ready,
			task);
	g_object_unref(proxy);
}

gboolean sf_secrets_collection_delete_secret_finish(GAsyncResult *res, GError **error)
{
	return g_task_propagate_boolean(G_TASK(res), error);
}

static void _sf_secrets_collection_find_secrets_ready(GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	GTask *task = user_data;
	GError *error = NULL;
	GVariant *response = g_dbus_proxy_call_finish(G_DBUS_PROXY(source_object),
			res, &error);
	GArray *secret_names;
	GVariantIter iter;
	GVariant *secrets;
	GVariantIter secret_iter;
	gchar *secret_name;

	if (error) {
		g_task_return_error(task, error);
		g_object_unref(task);
		return;
	}

	if (!_sf_secrets_manager_check_reply(response, &error, &iter)) {
		g_task_return_error(task, error);
		g_object_unref(task);
		g_variant_unref(response);
		return;
	}

	secret_names = g_array_new(TRUE, FALSE, sizeof(gchar *));
	secrets = g_variant_iter_next_value(&iter);

	g_variant_iter_init(&secret_iter, secrets);
	while (g_variant_iter_loop(&secret_iter, "(s&s&s)",
				&secret_name,
				NULL,
				NULL))
		g_array_append_val(secret_names, secret_name);
	g_variant_unref(secrets);
	g_variant_unref(response);

	g_task_return_pointer(task, g_array_free(secret_names, FALSE), (GDestroyNotify)g_strfreev);
	g_object_unref(task);
}

void sf_secrets_collection_find_secrets(SfSecretsCollection *collection,
		SfSecretsFilterOperator op,
		GCancellable *cancellable,
		GAsyncReadyCallback callback,
		gpointer user_data,
		const gchar *first_filter_name,
		...)
{
	GTask *task = g_task_new(collection, cancellable, callback, user_data);
	SfSecretsCollectionPrivate *priv = sf_secrets_collection_get_instance_private(collection);
	GDBusProxy *proxy = _sf_secrets_manager_get_dbus_proxy(priv->manager);
	va_list args;
	GVariantBuilder filters;
	const gchar *interaction_service_address;
	SfSecretsUserInteractionMode mode;

	va_start(args, first_filter_name);
	_sf_secrets_manager_get_interaction_mode(priv->manager, &mode, &interaction_service_address);

	g_variant_builder_init(&filters, G_VARIANT_TYPE("a{ss}"));
	while (first_filter_name) {
		const gchar *filter_arg = va_arg(args, const gchar *);
		g_variant_builder_add(&filters, "{ss}", first_filter_name, filter_arg);
		first_filter_name = va_arg(args, const gchar *);
	}

	g_dbus_proxy_call(proxy,
			"findSecrets",
			g_variant_new("(ssa{ss}(i)(i)s)",
				priv->name,
				priv->plugin_name,
				&filters,
				(gint)op,
				mode,
				interaction_service_address),
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			cancellable,
			_sf_secrets_collection_find_secrets_ready,
			task);
	g_object_unref(proxy);
}

gchar **sf_secrets_collection_find_secrets_finish(GAsyncResult *res, GError **error)
{
	return g_task_propagate_pointer(G_TASK(res), error);
}
