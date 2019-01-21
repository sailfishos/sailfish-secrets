#include "sf-secrets-interaction-request.h"
#include "sf-secrets-interaction-request-private.h"
#include "sf-secrets.h"
#include "sf-common-private.h"
#include <gio/gio.h>

typedef struct SfSecretsInteractionRequestPrivate_ SfSecretsInteractionRequestPrivate;

struct SfSecretsInteractionRequest_ {
    GObject parent_instance;
};

struct SfSecretsInteractionRequestClass_ {
    GObjectClass parent_class;
};

struct SfSecretsInteractionRequestPrivate_ {
    gchar *id;
    GDBusMethodInvocation *invocation;
    gchar *secret_name;
    gchar *collection_name;
    gchar *plugin_name;
    gchar *application_id;
    SfSecretsOperation operation;
    gchar *authentication_plugin_name;
    GHashTable *prompt_text;
    SfSecretsInputType input_type;
    SfSecretsEchoMode echo_mode;
    gboolean return_id;
};

enum sf_secrets_interaction_request_props {
    PROP_0,
    PROP_ID,
    PROP_INVOCATION,
    PROP_SECRET_NAME,
    PROP_COLLECTION_NAME,
    PROP_PLUGIN_NAME,
    PROP_APPLICATION_ID,
    PROP_OPERATION,
    PROP_AUTHENTICATION_PLUGIN_NAME,
    PROP_PROMPT_TEXT,
    PROP_INPUT_TYPE,
    PROP_ECHO_MODE,
    N_PROPERTIES
};

static GParamSpec *sf_secrets_interaction_request_pspecs[N_PROPERTIES] = { 0 };

G_DEFINE_TYPE_WITH_CODE(SfSecretsInteractionRequest, sf_secrets_interaction_request, G_TYPE_OBJECT,
        G_ADD_PRIVATE(SfSecretsInteractionRequest))

static void _sf_secrets_interaction_request_finalize(GObject *object)
{
    SfSecretsInteractionRequest *request = SF_SECRETS_INTERACTION_REQUEST(object);
    SfSecretsInteractionRequestPrivate *priv = sf_secrets_interaction_request_get_instance_private(request);

    if (priv->invocation) {
        GError *error = g_error_new(SF_SECRETS_ERROR,
                SF_SECRETS_ERROR_INTERACTION_VIEW_USER_CANCELED,
                "Destroyed while operation in progress");
        sf_secrets_interaction_request_return_error(request, error);
        g_error_free(error);
        g_object_unref(priv->invocation);
    }
    if (priv->id)
        g_free(priv->id);
    if (priv->secret_name)
        g_free(priv->secret_name);
    if (priv->collection_name)
        g_free(priv->collection_name);
    if (priv->plugin_name)
        g_free(priv->plugin_name);
    if (priv->application_id)
        g_free(priv->application_id);
    if (priv->prompt_text)
        g_hash_table_unref(priv->prompt_text);
    if (priv->authentication_plugin_name)
        g_free(priv->authentication_plugin_name);
}

static void sf_secrets_interaction_request_init(SfSecretsInteractionRequest *request)
{
    SfSecretsInteractionRequestPrivate *priv = sf_secrets_interaction_request_get_instance_private(request);
    priv->return_id = TRUE;
}

void sf_secrets_interaction_request_return(SfSecretsInteractionRequest *request, GBytes *data)
{
    SfSecretsInteractionRequestPrivate *priv = sf_secrets_interaction_request_get_instance_private(request);

    if (G_UNLIKELY(!priv->invocation)) {
        g_warning("%s called in invalid state", __FUNCTION__);
        return;
    }

    if (priv->return_id) {
        g_dbus_method_invocation_return_value(priv->invocation,
                g_variant_new("(((iis)@ay)s)",
                    SF_SECRETS_RESULT_CODE_SUCCEEDED,
                    SF_SECRETS_ERROR_NO,
                    "",
                    _sf_variant_new_bytes_or_empty(data),
                    priv->id));
        priv->return_id = FALSE;
    } else {
        g_dbus_method_invocation_return_value(priv->invocation,
                g_variant_new("((iis)@ay)",
                    SF_SECRETS_RESULT_CODE_SUCCEEDED,
                    SF_SECRETS_ERROR_NO,
                    "",
                    _sf_variant_new_bytes_or_empty(data)));
    }
    g_object_unref(priv->invocation);
    priv->invocation = NULL;
}

void sf_secrets_interaction_request_return_error(SfSecretsInteractionRequest *request, const GError *error)
{
    SfSecretsInteractionRequestPrivate *priv = sf_secrets_interaction_request_get_instance_private(request);
    SfSecretsError err;

    if (G_UNLIKELY(!priv->invocation)) {
        g_warning("%s called in invalid state", __FUNCTION__);
        return;
    }

    if (G_UNLIKELY(error->domain != SF_SECRETS_ERROR)) {
        g_warning("%s called with error in unknown domain", __FUNCTION__);
        err = SF_SECRETS_ERROR_UNKNOWN;
    } else {
        err = error->code;
    }

    if (priv->return_id) {
        g_dbus_method_invocation_return_value(priv->invocation,
                g_variant_new("(((iis)@ay)s)",
                    SF_SECRETS_RESULT_CODE_FAILED,
                    err,
                    error->message,
                    g_variant_new_fixed_array(G_VARIANT_TYPE("y"), NULL, 0, sizeof(guchar)),
                    ""));
    } else {
        g_dbus_method_invocation_return_value(priv->invocation,
                g_variant_new("((iis)@ay)",
                    SF_SECRETS_RESULT_CODE_FAILED,
                    err,
                    error->message,
                    g_variant_new_fixed_array(G_VARIANT_TYPE("y"), NULL, 0, sizeof(guchar))));
    }
    g_object_unref(priv->invocation);
    priv->invocation = FALSE;
}

static void _sf_secrets_interaction_request_get_property(GObject *object,
        guint property_id,
        GValue *value,
        GParamSpec *pspec)
{
    SfSecretsInteractionRequest *request = SF_SECRETS_INTERACTION_REQUEST(object);
    SfSecretsInteractionRequestPrivate *priv = sf_secrets_interaction_request_get_instance_private(request);

    (void)pspec;

    switch (property_id) {
        case PROP_SECRET_NAME:
            g_value_set_string(value, priv->secret_name);
            break;

        case PROP_COLLECTION_NAME:
            g_value_set_string(value, priv->collection_name);
            break;

        case PROP_PLUGIN_NAME:
            g_value_set_string(value, priv->plugin_name);
            break;

        case PROP_APPLICATION_ID:
            g_value_set_string(value, priv->application_id);
            break;

        case PROP_OPERATION:
            g_value_set_int(value, priv->operation);
            break;

        case PROP_AUTHENTICATION_PLUGIN_NAME:
            g_value_set_string(value, priv->authentication_plugin_name);
            break;

        case PROP_PROMPT_TEXT:
            g_value_set_boxed(value, priv->prompt_text);
            break;

        case PROP_INPUT_TYPE:
            g_value_set_int(value, priv->input_type);
            break;

        case PROP_ECHO_MODE:
            g_value_set_int(value, priv->echo_mode);
            break;

        default:
            break;
    }
}
static void _sf_secrets_interaction_request_set_property(GObject *object,
        guint property_id,
        const GValue *value,
        GParamSpec *pspec)
{
    SfSecretsInteractionRequest *request = SF_SECRETS_INTERACTION_REQUEST(object);
    SfSecretsInteractionRequestPrivate *priv = sf_secrets_interaction_request_get_instance_private(request);

    (void)pspec;

    switch (property_id) {
        case PROP_ID:
            if (priv->id)
                g_free(priv->id);
            priv->id = g_value_dup_string(value);
            break;

        case PROP_INVOCATION:
            if (priv->invocation)
                g_object_unref(priv->invocation);
            priv->invocation = g_value_dup_object(value);
            break;

        case PROP_SECRET_NAME:
            if (priv->secret_name)
                g_free(priv->secret_name);
            priv->secret_name = g_value_dup_string(value);
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

        case PROP_APPLICATION_ID:
            if (priv->application_id)
                g_free(priv->application_id);
            priv->application_id = g_value_dup_string(value);
            break;

        case PROP_OPERATION:
            priv->operation = g_value_get_int(value);
            break;

        case PROP_AUTHENTICATION_PLUGIN_NAME:
            if (priv->authentication_plugin_name)
                g_free(priv->authentication_plugin_name);
            priv->authentication_plugin_name = g_value_dup_string(value);
            break;

        case PROP_PROMPT_TEXT:
            if (priv->prompt_text)
                g_hash_table_unref(priv->prompt_text);
            priv->prompt_text = g_value_dup_boxed(value);
            break;

        case PROP_INPUT_TYPE:
            priv->input_type = g_value_get_int(value);
            break;

        case PROP_ECHO_MODE:
            priv->echo_mode = g_value_get_int(value);
            break;

        default:
            break;
    }
}

static void sf_secrets_interaction_request_class_init(SfSecretsInteractionRequestClass *request_class)
{
    G_OBJECT_CLASS(request_class)->finalize = _sf_secrets_interaction_request_finalize;
    G_OBJECT_CLASS(request_class)->get_property = _sf_secrets_interaction_request_get_property;
    G_OBJECT_CLASS(request_class)->set_property = _sf_secrets_interaction_request_set_property;

    sf_secrets_interaction_request_pspecs[PROP_ID] = g_param_spec_string("id",
            "id",
            "id",
            NULL,
            G_PARAM_STATIC_STRINGS |
            G_PARAM_READWRITE |
            G_PARAM_CONSTRUCT_ONLY);
    sf_secrets_interaction_request_pspecs[PROP_INVOCATION] = g_param_spec_object("invocation",
            "invocation",
            "invocation",
            G_TYPE_DBUS_METHOD_INVOCATION,
            G_PARAM_STATIC_STRINGS |
            G_PARAM_WRITABLE |
            G_PARAM_CONSTRUCT_ONLY);
    sf_secrets_interaction_request_pspecs[PROP_SECRET_NAME] = g_param_spec_string("secret-name",
            "secret-name",
            "secret-name",
            NULL,
            G_PARAM_STATIC_STRINGS |
            G_PARAM_READWRITE |
            G_PARAM_CONSTRUCT_ONLY);
    sf_secrets_interaction_request_pspecs[PROP_COLLECTION_NAME] = g_param_spec_string("collection-name",
            "collection-name",
            "collection-name",
            NULL,
            G_PARAM_STATIC_STRINGS |
            G_PARAM_READWRITE |
            G_PARAM_CONSTRUCT_ONLY);
    sf_secrets_interaction_request_pspecs[PROP_PLUGIN_NAME] = g_param_spec_string("plugin-name",
            "plugin-name",
            "plugin-name",
            NULL,
            G_PARAM_STATIC_STRINGS |
            G_PARAM_READWRITE |
            G_PARAM_CONSTRUCT_ONLY);
    sf_secrets_interaction_request_pspecs[PROP_APPLICATION_ID] = g_param_spec_string("application-id",
            "application-id",
            "application-id",
            NULL,
            G_PARAM_STATIC_STRINGS |
            G_PARAM_READWRITE |
            G_PARAM_CONSTRUCT_ONLY);
    sf_secrets_interaction_request_pspecs[PROP_OPERATION] = g_param_spec_int("operation",
            "operation",
            "operation",
            0,
            G_MAXINT,
            0,
            G_PARAM_STATIC_STRINGS |
            G_PARAM_READWRITE |
            G_PARAM_CONSTRUCT_ONLY);
    sf_secrets_interaction_request_pspecs[PROP_AUTHENTICATION_PLUGIN_NAME] = g_param_spec_string("authentication-plugin-name",
            "authentication-plugin-name",
            "authentication-plugin-name",
            NULL,
            G_PARAM_STATIC_STRINGS |
            G_PARAM_READWRITE |
            G_PARAM_CONSTRUCT_ONLY);
    sf_secrets_interaction_request_pspecs[PROP_PROMPT_TEXT] = g_param_spec_boxed("prompt-text",
            "prompt-text",
            "prompt-text",
            G_TYPE_HASH_TABLE,
            G_PARAM_STATIC_STRINGS |
            G_PARAM_READWRITE |
            G_PARAM_CONSTRUCT_ONLY);
    sf_secrets_interaction_request_pspecs[PROP_INPUT_TYPE] = g_param_spec_int("input-type",
            "input-type",
            "input-type",
            0,
            G_MAXINT,
            0,
            G_PARAM_STATIC_STRINGS |
            G_PARAM_READWRITE |
            G_PARAM_CONSTRUCT_ONLY);
    sf_secrets_interaction_request_pspecs[PROP_ECHO_MODE] = g_param_spec_int("echo-mode",
            "echo-mode",
            "echo-mode",
            0,
            G_MAXINT,
            0,
            G_PARAM_STATIC_STRINGS |
            G_PARAM_READWRITE |
            G_PARAM_CONSTRUCT_ONLY);

    g_object_class_install_properties(G_OBJECT_CLASS(request_class),
            N_PROPERTIES, sf_secrets_interaction_request_pspecs);

    g_signal_new("continue",
            SF_TYPE_SECRETS_INTERACTION_REQUEST,
            G_SIGNAL_RUN_LAST,
            0,
            NULL, NULL,
            NULL, G_TYPE_NONE,
            0);
    g_signal_new("cancel",
            SF_TYPE_SECRETS_INTERACTION_REQUEST,
            G_SIGNAL_RUN_LAST,
            0,
            NULL, NULL,
            NULL, G_TYPE_NONE,
            0);
    g_signal_new("finish",
            SF_TYPE_SECRETS_INTERACTION_REQUEST,
            G_SIGNAL_RUN_LAST,
            0,
            NULL, NULL,
            NULL, G_TYPE_NONE,
            0);
}

const gchar *sf_secrets_interaction_request_get_secret_name(SfSecretsInteractionRequest *request)
{
    SfSecretsInteractionRequestPrivate *priv = sf_secrets_interaction_request_get_instance_private(request);
    return priv->secret_name;
}

const gchar *sf_secrets_interaction_request_get_collection_name(SfSecretsInteractionRequest *request)
{
    SfSecretsInteractionRequestPrivate *priv = sf_secrets_interaction_request_get_instance_private(request);
    return priv->collection_name;
}

const gchar *sf_secrets_interaction_request_get_plugin_name(SfSecretsInteractionRequest *request)
{
    SfSecretsInteractionRequestPrivate *priv = sf_secrets_interaction_request_get_instance_private(request);
    return priv->plugin_name;
}

const gchar *sf_secrets_interaction_request_get_application_id(SfSecretsInteractionRequest *request)
{
    SfSecretsInteractionRequestPrivate *priv = sf_secrets_interaction_request_get_instance_private(request);
    return priv->application_id;
}

SfSecretsOperation sf_secrets_interaction_request_get_operation(SfSecretsInteractionRequest *request)
{
    SfSecretsInteractionRequestPrivate *priv = sf_secrets_interaction_request_get_instance_private(request);
    return priv->operation;
}

const gchar *sf_secrets_interaction_request_get_authentication_plugin_name(SfSecretsInteractionRequest *request)
{
    SfSecretsInteractionRequestPrivate *priv = sf_secrets_interaction_request_get_instance_private(request);
    return priv->authentication_plugin_name;
}

const gchar *sf_secrets_interaction_request_get_prompt(SfSecretsInteractionRequest *request,
        SfSecretsPrompt prompt)
{
    SfSecretsInteractionRequestPrivate *priv = sf_secrets_interaction_request_get_instance_private(request);
    return g_hash_table_lookup(priv->prompt_text, GINT_TO_POINTER(prompt));
}

GHashTable *sf_secrets_interaction_request_get_prompt_text(SfSecretsInteractionRequest *request)
{
    SfSecretsInteractionRequestPrivate *priv = sf_secrets_interaction_request_get_instance_private(request);
    return g_hash_table_ref(priv->prompt_text);
}

SfSecretsInputType sf_secrets_interaction_request_get_input_type(SfSecretsInteractionRequest *request)
{
    SfSecretsInteractionRequestPrivate *priv = sf_secrets_interaction_request_get_instance_private(request);
    return priv->input_type;
}

SfSecretsEchoMode sf_secrets_interaction_request_get_echo_mode(SfSecretsInteractionRequest *request)
{
    SfSecretsInteractionRequestPrivate *priv = sf_secrets_interaction_request_get_instance_private(request);
    return priv->echo_mode;
}

static gboolean _sf_hash_table_equal(GHashTable *a, GHashTable *b, GEqualFunc value_equal)
{
    GHashTableIter i;
    gpointer key;
    gpointer value;

    if (a == b)
        return TRUE;
    if (!a || !b)
        return FALSE;
    if (g_hash_table_size(a) != g_hash_table_size(b))
        return FALSE;

    g_hash_table_iter_init(&i, a);
    while (g_hash_table_iter_next(&i, &key, &value)) {
        gpointer bval;
        if (!g_hash_table_lookup_extended(b, key, NULL, &bval) ||
                !value_equal(value, bval))
            return FALSE;
    }

    return TRUE;
}

void _sf_secrets_interaction_request_set(SfSecretsInteractionRequest *request,
        GDBusMethodInvocation *invocation,
        const gchar *secret_name,
        const gchar *collection_name,
        const gchar *plugin_name,
        const gchar *application_id,
        SfSecretsOperation operation,
        const gchar *authentication_plugin_name,
        GHashTable *prompt_text,
        SfSecretsInputType input_type,
        SfSecretsEchoMode echo_mode)
{
    SfSecretsInteractionRequestPrivate *priv = sf_secrets_interaction_request_get_instance_private(request);

    if (priv->invocation) {
        GError *error = g_error_new(SF_SECRETS_ERROR,
                SF_SECRETS_ERROR_INTERACTION_VIEW_USER_CANCELED,
                "Destroyed while operation in progress");
        sf_secrets_interaction_request_return_error(request, error);
        g_error_free(error);
        g_object_unref(priv->invocation);
    }
    priv->invocation = g_object_ref(invocation);

    if (g_strcmp0(secret_name, priv->secret_name)) {
        g_free(priv->secret_name);
        priv->secret_name = g_strdup(secret_name);
        g_object_notify_by_pspec(G_OBJECT(request), sf_secrets_interaction_request_pspecs[PROP_SECRET_NAME]);
    }
    if (g_strcmp0(collection_name, priv->collection_name)) {
        g_free(priv->collection_name);
        priv->collection_name = g_strdup(collection_name);
        g_object_notify_by_pspec(G_OBJECT(request), sf_secrets_interaction_request_pspecs[PROP_COLLECTION_NAME]);
    }
    if (g_strcmp0(plugin_name, priv->plugin_name)) {
        g_free(priv->plugin_name);
        priv->plugin_name = g_strdup(plugin_name);
        g_object_notify_by_pspec(G_OBJECT(request), sf_secrets_interaction_request_pspecs[PROP_PLUGIN_NAME]);
    }
    if (g_strcmp0(application_id, priv->application_id)) {
        g_free(priv->application_id);
        priv->application_id = g_strdup(application_id);
        g_object_notify_by_pspec(G_OBJECT(request), sf_secrets_interaction_request_pspecs[PROP_APPLICATION_ID]);
    }
    if (operation != priv->operation) {
        priv->operation = operation;
        g_object_notify_by_pspec(G_OBJECT(request), sf_secrets_interaction_request_pspecs[PROP_OPERATION]);
    }
    if (g_strcmp0(authentication_plugin_name, priv->authentication_plugin_name)) {
        g_free(priv->authentication_plugin_name);
        priv->authentication_plugin_name = g_strdup(authentication_plugin_name);
        g_object_notify_by_pspec(G_OBJECT(request),
                sf_secrets_interaction_request_pspecs[PROP_AUTHENTICATION_PLUGIN_NAME]);
    }

    if (!_sf_hash_table_equal(prompt_text, priv->prompt_text, g_str_equal)) {
        if (priv->prompt_text)
            g_hash_table_unref(priv->prompt_text);
        priv->prompt_text = g_hash_table_ref(prompt_text);
        g_object_notify_by_pspec(G_OBJECT(request), sf_secrets_interaction_request_pspecs[PROP_PROMPT_TEXT]);
    }

    if (input_type != priv->input_type) {
        priv->input_type = input_type;
        g_object_notify_by_pspec(G_OBJECT(request), sf_secrets_interaction_request_pspecs[PROP_INPUT_TYPE]);
    }
    if (echo_mode != priv->echo_mode) {
        priv->echo_mode = echo_mode;
        g_object_notify_by_pspec(G_OBJECT(request), sf_secrets_interaction_request_pspecs[PROP_ECHO_MODE]);
    }
}
