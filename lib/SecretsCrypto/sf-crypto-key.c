#include "sf-crypto-key.h"
#include "sf-crypto-key-private.h"
#include "sf-crypto-manager.h"
#include "sf-common-private.h"

enum SfCryptoKeyProperties {
	PROP_NAME = 1,
	PROP_COLLECTION_NAME,
	PROP_PLUGIN_NAME,
	PROP_ORIGIN,
	PROP_ALGORITHM,
	PROP_OPERATIONS,
	PROP_CONSTRAINTS,
	PROP_KEY_SIZE,
	PROP_PUBLIC_KEY,
	PROP_PRIVATE_KEY,
	PROP_SECRET_KEY,
	PROP_CUSTOM_PARAMS,
	PROP_FILTER_DATA,
	PROP_COUNT = PROP_FILTER_DATA
};

typedef struct SfCryptoKeyPrivate_ SfCryptoKeyPrivate;

struct SfCryptoKeyPrivate_
{
	gchar *name;
	gchar *collection_name;
	gchar *plugin_name;
	SfCryptoKeyOrigin origin;
	SfCryptoAlgorithm algorithm;
	SfCryptoOperation operations;
	SfCryptoKeyConstraint constraints;
	gint key_size;
	GBytes *public_key;
	GBytes *private_key;
	GBytes *secret_key;
	GPtrArray *custom_params;
	GHashTable *filter_data;
};

G_DEFINE_TYPE_WITH_CODE(SfCryptoKey, sf_crypto_key, G_TYPE_INITIALLY_UNOWNED,
		G_ADD_PRIVATE(SfCryptoKey))

static void _sf_crypto_key_finalize(GObject *object)
{
	SfCryptoKey *key = SF_CRYPTO_KEY(object);
	SfCryptoKeyPrivate *priv = sf_crypto_key_get_instance_private(key);

	if (priv->name)
		g_free(priv->name);
	if (priv->collection_name)
		g_free(priv->collection_name);
	if (priv->plugin_name)
		g_free(priv->plugin_name);
	if (priv->public_key)
		g_bytes_unref(priv->public_key);
	if (priv->private_key)
		g_bytes_unref(priv->private_key);
	if (priv->secret_key)
		g_bytes_unref(priv->secret_key);
	if (priv->custom_params)
		g_ptr_array_unref(priv->custom_params);
	if (priv->filter_data)
		g_hash_table_unref(priv->filter_data);
}

static void _sf_crypto_key_get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
	SfCryptoKey *key = SF_CRYPTO_KEY(object);
	SfCryptoKeyPrivate *priv = sf_crypto_key_get_instance_private(key);

	(void)pspec;

	switch (prop_id) {
		case PROP_NAME:
			g_value_set_string(value, priv->name);
			break;

		case PROP_COLLECTION_NAME:
			g_value_set_string(value, priv->collection_name);
			break;

		case PROP_PLUGIN_NAME:
			g_value_set_string(value, priv->plugin_name);
			break;

		case PROP_ORIGIN:
			g_value_set_int(value, priv->origin);
			break;

		case PROP_ALGORITHM:
			g_value_set_int(value, priv->algorithm);
			break;

		case PROP_OPERATIONS:
			g_value_set_int(value, priv->operations);
			break;

		case PROP_CONSTRAINTS:
			g_value_set_int(value, priv->constraints);
			break;

		case PROP_KEY_SIZE:
			g_value_set_int(value, priv->key_size);
			break;

		case PROP_PUBLIC_KEY:
			g_value_set_boxed(value, priv->public_key);
			break;

		case PROP_PRIVATE_KEY:
			g_value_set_boxed(value, priv->private_key);
			break;

		case PROP_SECRET_KEY:
			g_value_set_boxed(value, priv->secret_key);
			break;

		case PROP_CUSTOM_PARAMS:
			g_value_set_boxed(value, priv->custom_params);
			break;

		case PROP_FILTER_DATA:
			g_value_set_boxed(value, priv->filter_data);
			break;

		default:
			break;
	}
}

static void _sf_crypto_key_set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
	SfCryptoKey *key = SF_CRYPTO_KEY(object);
	SfCryptoKeyPrivate *priv = sf_crypto_key_get_instance_private(key);

	(void)pspec;

	switch (prop_id) {
		case PROP_NAME:
			if (priv->name)
				g_free(priv->name);
			priv->name = g_value_dup_string(value);
			break;

		case PROP_COLLECTION_NAME:
			if (priv->collection_name)
				g_free(priv->collection_name);
			priv->collection_name = g_value_dup_string(value);
			break;

		case PROP_PLUGIN_NAME:
			if (priv->plugin_name)
				g_free(priv->plugin_name);
			priv->plugin_name = g_value_dup_string(value);
			break;

		case PROP_ORIGIN:
			priv->origin = g_value_get_int(value);
			break;

		case PROP_ALGORITHM:
			priv->algorithm = g_value_get_int(value);
			break;

		case PROP_OPERATIONS:
			priv->operations = g_value_get_int(value);
			break;

		case PROP_CONSTRAINTS:
			priv->constraints = g_value_get_int(value);
			break;

		case PROP_KEY_SIZE:
			priv->key_size = g_value_get_int(value);
			break;

		case PROP_PUBLIC_KEY:
			if (priv->public_key)
				g_bytes_unref(priv->public_key);
			priv->public_key = g_value_dup_boxed(value);
			break;

		case PROP_PRIVATE_KEY:
			if (priv->private_key)
				g_bytes_unref(priv->private_key);
			priv->private_key = g_value_dup_boxed(value);
			break;

		case PROP_SECRET_KEY:
			if (priv->secret_key)
				g_bytes_unref(priv->secret_key);
			priv->secret_key = g_value_dup_boxed(value);
			break;

		case PROP_CUSTOM_PARAMS:
			if (priv->custom_params)
				g_ptr_array_unref(priv->custom_params);
			priv->custom_params = g_value_dup_boxed(value);
			break;

		case PROP_FILTER_DATA:
			if (priv->filter_data)
				g_hash_table_unref(priv->filter_data);
			priv->filter_data = g_value_dup_boxed(value);
			break;

		default:
			break;
	}
}

static void sf_crypto_key_class_init(SfCryptoKeyClass *key_class)
{
	G_OBJECT_CLASS(key_class)->finalize = _sf_crypto_key_finalize;
	G_OBJECT_CLASS(key_class)->set_property = _sf_crypto_key_set_property;
	G_OBJECT_CLASS(key_class)->get_property = _sf_crypto_key_get_property;

	g_object_class_install_property(G_OBJECT_CLASS(key_class),
			PROP_NAME,
			g_param_spec_string("name",
				"name",
				"name",
				NULL,
				G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
	g_object_class_install_property(G_OBJECT_CLASS(key_class),
			PROP_COLLECTION_NAME,
			g_param_spec_string("collection-name",
				"collection-name",
				"collection-name",
				NULL,
				G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
	g_object_class_install_property(G_OBJECT_CLASS(key_class),
			PROP_PLUGIN_NAME,
			g_param_spec_string("plugin-name",
				"plugin-name",
				"plugin-name",
				NULL,
				G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
	g_object_class_install_property(G_OBJECT_CLASS(key_class),
			PROP_ORIGIN,
			g_param_spec_int("origin",
				"origin",
				"origin",
				SF_CRYPTO_KEY_ORIGIN_UNKNOWN,
				SF_CRYPTO_KEY_ORIGIN_SECURE_DEVICE,
				SF_CRYPTO_KEY_ORIGIN_UNKNOWN,
				G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
	g_object_class_install_property(G_OBJECT_CLASS(key_class),
			PROP_ALGORITHM,
			g_param_spec_int("algorithm",
				"algorithm",
				"algorithm",
				SF_CRYPTO_ALGORITHM_UNKNOWN,
				SF_CRYPTO_ALGORITHM_LAST,
				SF_CRYPTO_ALGORITHM_UNKNOWN,
				G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
	g_object_class_install_property(G_OBJECT_CLASS(key_class),
			PROP_OPERATIONS,
			g_param_spec_int("operations",
				"operations",
				"operations",
				SF_CRYPTO_OPERATION_UNKNOWN,
				(SF_CRYPTO_OPERATION_DERIVE_KEY << 1) - 1,
				SF_CRYPTO_OPERATION_UNKNOWN,
				G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
	g_object_class_install_property(G_OBJECT_CLASS(key_class),
			PROP_CONSTRAINTS,
			g_param_spec_int("constraints",
				"constraints",
				"constraints",
				SF_CRYPTO_KEY_CONSTRAINT_NO_DATA,
				(SF_CRYPTO_KEY_CONSTRAINT_SECRET_KEY_DATA << 1) - 1,
				SF_CRYPTO_KEY_CONSTRAINT_META_DATA |
				SF_CRYPTO_KEY_CONSTRAINT_PUBLIC_KEY_DATA,
				G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
	g_object_class_install_property(G_OBJECT_CLASS(key_class),
			PROP_KEY_SIZE,
			g_param_spec_int("key-size",
				"key-size",
				"key-size",
				0,
				G_MAXINT,
				0,
				G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
	g_object_class_install_property(G_OBJECT_CLASS(key_class),
			PROP_PUBLIC_KEY,
			g_param_spec_boxed("public-key",
				"public-key",
				"public-key",
				G_TYPE_BYTES,
				G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
	g_object_class_install_property(G_OBJECT_CLASS(key_class),
			PROP_PRIVATE_KEY,
			g_param_spec_boxed("private-key",
				"private-key",
				"private-key",
				G_TYPE_BYTES,
				G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
	g_object_class_install_property(G_OBJECT_CLASS(key_class),
			PROP_SECRET_KEY,
			g_param_spec_boxed("secret-key",
				"secret-key",
				"secret-key",
				G_TYPE_BYTES,
				G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
	g_object_class_install_property(G_OBJECT_CLASS(key_class),
			PROP_CUSTOM_PARAMS,
			g_param_spec_boxed("custom-params",
				"custom-params",
				"custom-params",
				G_TYPE_PTR_ARRAY,
				G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
	g_object_class_install_property(G_OBJECT_CLASS(key_class),
			PROP_FILTER_DATA,
			g_param_spec_boxed("filter-data",
				"filter-data",
				"filter-data",
				G_TYPE_HASH_TABLE,
				G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
}

static void sf_crypto_key_init(SfCryptoKey *key)
{
	SfCryptoKeyPrivate *priv = sf_crypto_key_get_instance_private(key);

	priv->constraints = SF_CRYPTO_KEY_CONSTRAINT_META_DATA |
		SF_CRYPTO_KEY_CONSTRAINT_PUBLIC_KEY_DATA;
}

void sf_crypto_key_set_filter_field(SfCryptoKey *key, const gchar *field, const gchar *value)
{
	SfCryptoKeyPrivate *priv = sf_crypto_key_get_instance_private(key);

	if (!priv->filter_data) {
		if (!value)
			return;
		priv->filter_data = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	}

	if (!value)
		g_hash_table_remove(priv->filter_data, field);
	else
		g_hash_table_replace(priv->filter_data, g_strdup(field), g_strdup(value));
}

void sf_crypto_key_take_custom_param(SfCryptoKey *key, GBytes *custom_param)
{
	SfCryptoKeyPrivate *priv = sf_crypto_key_get_instance_private(key);

	if (!priv->custom_params)
		priv->custom_params = g_ptr_array_new_with_free_func((GDestroyNotify)g_bytes_unref);
	g_ptr_array_add(priv->custom_params, custom_param);
}

void sf_crypto_key_add_custom_param(SfCryptoKey *key, GBytes *custom_param)
{
	sf_crypto_key_take_custom_param(key, g_bytes_ref(custom_param));
}

void sf_crypto_key_add_custom_param_data(SfCryptoKey *key, gconstpointer data, size_t data_size)
{
	sf_crypto_key_take_custom_param(key, g_bytes_new(data, data_size));
}

const gchar *sf_crypto_key_get_filter_field(SfCryptoKey *key, const gchar *field)
{
	SfCryptoKeyPrivate *priv = sf_crypto_key_get_instance_private(key);

	if (!priv->filter_data)
		return NULL;
	return g_hash_table_lookup(priv->filter_data, field);
}

static GVariant *_sf_variant_new_array_bytes_or_empty(GPtrArray *array)
{
	GVariantBuilder bldr;
	size_t i;

	if (!array || array->len == 0)
		return g_variant_new_array(G_VARIANT_TYPE("ay"), NULL, 0);

	g_variant_builder_init(&bldr, G_VARIANT_TYPE("aay"));
	for (i = 0; i < array->len; i++)
		g_variant_builder_add_value(&bldr, _sf_variant_new_bytes_or_empty(g_ptr_array_index(array, i)));
	return g_variant_builder_end(&bldr);
}

static GPtrArray *_sf_array_bytes_from_variant_or_null(GVariant *variant)
{
	GVariantIter iter;
	GVariant *item;
	GPtrArray *res;

	g_variant_iter_init(&iter, variant);

	if (!(item = g_variant_iter_next_value(&iter)))
		return NULL;
	res = g_ptr_array_new_with_free_func((GDestroyNotify)g_bytes_unref);
	do {
		g_ptr_array_add(res, _sf_bytes_new_from_variant_or_null(item));

		g_variant_unref(item);
	} while ((item = g_variant_iter_next_value(&iter)));

	return res;
}

/*
static GHashTable *_sf_hash_table_new_from_variant(GVariant *variant)
{
	GHashTable *res;
	GVariantIter iter;
	GVariant *item;
	gchar *key;

	g_variant_iter_init(&iter, variant);

	if (!g_variant_iter_next(&iter, "{sv}", &key, &item))
		return NULL;

	res = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, g_variant_unref);

	do {
		g_hash_table_replace(res, key, item);
	} while (g_variant_iter_next(&iter, "{sv}", &key, &item));

	return res;
}
*/

GVariant *_sf_crypto_key_to_variant(SfCryptoKey *key)
{
	SfCryptoKeyPrivate *priv = sf_crypto_key_get_instance_private(key);

	return g_variant_new("((sss)iiiiiayayaya(ay)a{sv})",
			priv->name ?: "",
			priv->collection_name ?: "",
			priv->plugin_name ?: "",
			(gint32)priv->origin,
			(gint32)priv->algorithm,
			(gint32)priv->operations,
			(gint32)priv->constraints,
			(gint32)priv->key_size,
			_sf_variant_new_bytes_or_empty(priv->public_key),
			_sf_variant_new_bytes_or_empty(priv->private_key),
			_sf_variant_new_bytes_or_empty(priv->secret_key),
			_sf_variant_new_array_bytes_or_empty(priv->custom_params),
			_sf_variant_new_variant_map_string_or_empty(priv->filter_data));
}

SfCryptoKey *_sf_crypto_key_from_variant(GVariant *variant)
{
	SfCryptoKey *result;

	const gchar *name;
	const gchar *collection_name;
	const gchar *plugin_name;
	gint32 origin;
	gint32 algorithm;
	gint32 operations;
	gint32 constraints;
	gint32 key_size;
	GVariant *public_key;
	GVariant *private_key;
	GVariant *secret_key;
	GVariant *custom_params;
	GVariant *filter_data;

	GBytes *pubkey;
	GBytes *privkey;
	GBytes *seckey;
	GPtrArray *custparm;
	GHashTable *filter_ht;

	g_variant_get(variant,
			"(&s&s&s)iiiii@ay@ay@ay@aay@a{sv})",
			&name,
			&collection_name,
			&plugin_name,
			&origin,
			&algorithm,
			&operations,
			&constraints,
			&key_size,
			&public_key,
			&secret_key,
			&private_key,
			&custom_params,
			&filter_data);

	pubkey = _sf_bytes_new_from_variant_or_null(public_key);
	privkey = _sf_bytes_new_from_variant_or_null(public_key);
	seckey = _sf_bytes_new_from_variant_or_null(public_key);
	custparm = _sf_array_bytes_from_variant_or_null(custom_params);
	filter_ht = _sf_hash_table_new_string_from_variant(filter_data);

	g_variant_unref(public_key);
	g_variant_unref(private_key);
	g_variant_unref(secret_key);
	g_variant_unref(custom_params);
	g_variant_unref(filter_data);

	result = g_object_new(SF_TYPE_CRYPTO_KEY,
			"name", name,
			"collection-name", collection_name,
			"plugin-name", plugin_name,
			"origin", origin,
			"algorithm", algorithm,
			"operations", operations,
			"constraints", constraints,
			"key-size", key_size,
			"public-key", pubkey,
			"secret-key", seckey,
			"private-key", privkey,
			"custom-params", custparm,
			"filter-data", filter_ht,
			NULL);

	g_bytes_unref(pubkey);
	g_bytes_unref(seckey);
	g_bytes_unref(privkey);
	g_ptr_array_unref(custparm);
	g_hash_table_unref(filter_ht);

	return result;
}

gpointer sf_crypto_key_serialize(SfCryptoKey *key, gsize *len)
{
#if G_BYTE_ORDER != G_BIG_ENDIAN && G_BYTE_ORDER != G_LITTLE_ENDIAN
#warning Unsupported byte order
	if (len)
		*len = 0;
	return NULL;
#else
	GVariant *key_as_variant = _sf_crypto_key_to_variant(key);
	gsize vlen = g_variant_get_size(key_as_variant);
	guchar *res = g_malloc(vlen + 1);

	res[0] = G_BYTE_ORDER & 255;
	memcpy(&res[1], g_variant_get_data(key_as_variant), vlen);

	g_variant_unref(key_as_variant);

	if (len)
		*len = vlen + 1;

	return res;
#endif
}

SfCryptoKey *sf_crypto_key_deserialize(gconstpointer data, gsize len)
{
	SfCryptoKey *ret;
	GVariant *key_as_variant;

	if (len < 1)
		return NULL;
	
	key_as_variant = g_variant_new_from_data(
			G_VARIANT_TYPE(SF_CRYPTO_KEY_VARIANT_STRING),
			g_memdup(data + 1, len - 1),
			len - 1,
			FALSE,
			(GDestroyNotify)g_free,
			NULL);

	if ((G_BYTE_ORDER & 255) != *(const guchar *)data) {
		GVariant *t = g_variant_byteswap(key_as_variant);
		g_variant_unref(key_as_variant);
		key_as_variant = t;
	}

	ret = _sf_crypto_key_from_variant(key_as_variant);
	g_variant_unref(key_as_variant);

	return ret;
}

const gchar *sf_crypto_key_get_name(SfCryptoKey *key)
{
	SfCryptoKeyPrivate *priv = sf_crypto_key_get_instance_private(key);
	return priv->name;
}

void sf_crypto_key_set_name(SfCryptoKey *key, const gchar *name)
{
	GValue v = { 0 };
	g_value_init(&v, G_TYPE_STRING);
	g_value_set_static_string(&v, name);
	G_OBJECT_GET_CLASS(key)->set_property(G_OBJECT(key), PROP_NAME, &v, NULL);
	g_value_unset(&v);
}

const gchar *sf_crypto_key_get_collection_name(SfCryptoKey *key)
{
	SfCryptoKeyPrivate *priv = sf_crypto_key_get_instance_private(key);
	return priv->collection_name;
}

void sf_crypto_key_set_collection_name(SfCryptoKey *key, const gchar *collection_name)
{
	GValue v = { 0 };
	g_value_init(&v, G_TYPE_STRING);
	g_value_set_static_string(&v, collection_name);
	G_OBJECT_GET_CLASS(key)->set_property(G_OBJECT(key), PROP_COLLECTION_NAME, &v, NULL);
	g_value_unset(&v);
}

const gchar *sf_crypto_key_get_plugin_name(SfCryptoKey *key)
{
	SfCryptoKeyPrivate *priv = sf_crypto_key_get_instance_private(key);
	return priv->plugin_name;
}

void sf_crypto_key_set_plugin_name(SfCryptoKey *key, const gchar *plugin_name)
{
	GValue v = { 0 };
	g_value_init(&v, G_TYPE_STRING);
	g_value_set_static_string(&v, plugin_name);
	G_OBJECT_GET_CLASS(key)->set_property(G_OBJECT(key), PROP_PLUGIN_NAME, &v, NULL);
	g_value_unset(&v);
}

SfCryptoKeyOrigin sf_crypto_key_get_origin(SfCryptoKey *key)
{
	SfCryptoKeyPrivate *priv = sf_crypto_key_get_instance_private(key);
	return priv->origin;
}

void sf_crypto_key_set_origin(SfCryptoKey *key, SfCryptoKeyOrigin origin)
{
	GValue v = { 0 };
	g_value_init(&v, G_TYPE_INT);
	g_value_set_int(&v, origin);
	G_OBJECT_GET_CLASS(key)->set_property(G_OBJECT(key), PROP_ORIGIN, &v, NULL);
	g_value_unset(&v);
}

SfCryptoAlgorithm sf_crypto_key_get_algorithm(SfCryptoKey *key)
{
	SfCryptoKeyPrivate *priv = sf_crypto_key_get_instance_private(key);
	return priv->algorithm;
}

void sf_crypto_key_set_algorithm(SfCryptoKey *key, SfCryptoAlgorithm algorithm)
{
	GValue v = { 0 };
	g_value_init(&v, G_TYPE_INT);
	g_value_set_int(&v, algorithm);
	G_OBJECT_GET_CLASS(key)->set_property(G_OBJECT(key), PROP_ALGORITHM, &v, NULL);
	g_value_unset(&v);
}

SfCryptoOperation sf_crypto_key_get_operations(SfCryptoKey *key)
{
	SfCryptoKeyPrivate *priv = sf_crypto_key_get_instance_private(key);
	return priv->operations;
}

void sf_crypto_key_set_operations(SfCryptoKey *key, SfCryptoOperation operations)
{
	GValue v = { 0 };
	g_value_init(&v, G_TYPE_INT);
	g_value_set_int(&v, operations);
	G_OBJECT_GET_CLASS(key)->set_property(G_OBJECT(key), PROP_OPERATIONS, &v, NULL);
	g_value_unset(&v);
}

SfCryptoKeyConstraint sf_crypto_key_get_constraints(SfCryptoKey *key)
{
	SfCryptoKeyPrivate *priv = sf_crypto_key_get_instance_private(key);
	return priv->constraints;
}

void sf_crypto_key_set_constraints(SfCryptoKey *key, SfCryptoKeyConstraint constraints)
{
	GValue v = { 0 };
	g_value_init(&v, G_TYPE_INT);
	g_value_set_int(&v, constraints);
	G_OBJECT_GET_CLASS(key)->set_property(G_OBJECT(key), PROP_CONSTRAINTS, &v, NULL);
	g_value_unset(&v);
}

int sf_crypto_key_get_key_size(SfCryptoKey *key)
{
	SfCryptoKeyPrivate *priv = sf_crypto_key_get_instance_private(key);
	return priv->key_size;
}

void sf_crypto_key_set_key_size(SfCryptoKey *key, int key_size)
{
	GValue v = { 0 };
	g_value_init(&v, G_TYPE_INT);
	g_value_set_int(&v, key_size);
	G_OBJECT_GET_CLASS(key)->set_property(G_OBJECT(key), PROP_KEY_SIZE, &v, NULL);
	g_value_unset(&v);
}

GBytes *sf_crypto_key_get_public_key(SfCryptoKey *key)
{
	SfCryptoKeyPrivate *priv = sf_crypto_key_get_instance_private(key);
	return priv->public_key;
}

void sf_crypto_key_set_public_key(SfCryptoKey *key, GBytes *public_key)
{
	GValue v = { 0 };
	g_value_init(&v, G_TYPE_BYTES);
	g_value_set_boxed(&v, public_key);
	G_OBJECT_GET_CLASS(key)->set_property(G_OBJECT(key), PROP_PUBLIC_KEY, &v, NULL);
	g_value_unset(&v);
}

GBytes *sf_crypto_key_get_private_key(SfCryptoKey *key)
{
	SfCryptoKeyPrivate *priv = sf_crypto_key_get_instance_private(key);
	return priv->private_key;
}

void sf_crypto_key_set_private_key(SfCryptoKey *key, GBytes *private_key)
{
	GValue v = { 0 };
	g_value_init(&v, G_TYPE_BYTES);
	g_value_set_boxed(&v, private_key);
	G_OBJECT_GET_CLASS(key)->set_property(G_OBJECT(key), PROP_PRIVATE_KEY, &v, NULL);
	g_value_unset(&v);
}

GBytes *sf_crypto_key_get_secret_key(SfCryptoKey *key)
{
	SfCryptoKeyPrivate *priv = sf_crypto_key_get_instance_private(key);
	return priv->secret_key;
}

void sf_crypto_key_set_secret_key(SfCryptoKey *key, GBytes *secret_key)
{
	GValue v = { 0 };
	g_value_init(&v, G_TYPE_BYTES);
	g_value_set_boxed(&v, secret_key);
	G_OBJECT_GET_CLASS(key)->set_property(G_OBJECT(key), PROP_SECRET_KEY, &v, NULL);
	g_value_unset(&v);
}

GPtrArray *sf_crypto_key_get_custom_params(SfCryptoKey *key)
{
	SfCryptoKeyPrivate *priv = sf_crypto_key_get_instance_private(key);
	return priv->custom_params;
}

void sf_crypto_key_set_custom_params(SfCryptoKey *key, GPtrArray *custom_params)
{
	GValue v = { 0 };
	g_value_init(&v, G_TYPE_PTR_ARRAY);
	g_value_set_boxed(&v, custom_params);
	G_OBJECT_GET_CLASS(key)->set_property(G_OBJECT(key), PROP_CUSTOM_PARAMS, &v, NULL);
	g_value_unset(&v);
}

GHashTable *sf_crypto_key_get_filter_data(SfCryptoKey *key)
{
	SfCryptoKeyPrivate *priv = sf_crypto_key_get_instance_private(key);
	return priv->filter_data;
}

void sf_crypto_key_set_filter_data(SfCryptoKey *key, GHashTable *filter_data)
{
	GValue v = { 0 };
	g_value_init(&v, G_TYPE_HASH_TABLE);
	g_value_set_boxed(&v, filter_data);
	G_OBJECT_GET_CLASS(key)->set_property(G_OBJECT(key), PROP_FILTER_DATA, &v, NULL);
	g_value_unset(&v);
}
