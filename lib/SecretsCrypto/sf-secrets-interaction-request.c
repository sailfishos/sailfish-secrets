#include "sf-secrets-interaction-request.h"
#include <gio/gio.h>

typedef struct SfSecretsInteractionRequestPrivate_ SfSecretsInteractionRequestPrivate;

struct SfSecretsInteractionRequest_ {
	GObject parent_instance;
};

struct SfSecretsInteractionRequestClass_ {
	GObjectClass parent_class;
};

enum SfSecretsInteractionRequestProperties {
	PROP_ID = 1,
};

struct SfSecretsInteractionRequestPrivate_ {
	gchar *id;
	GDBusMethodInvocation *invocation;
};

G_DEFINE_TYPE_WITH_CODE(SfSecretsInteractionRequest, sf_secrets_interaction_request, G_TYPE_OBJECT,
		G_ADD_PRIVATE(SfSecretsInteractionRequest))

static void _sf_secrets_interaction_request_finalize(GObject *object)
{
	SfSecretsInteractionRequest *request = SF_SECRETS_INTERACTION_REQUEST(object);
	SfSecretsInteractionRequestPrivate *priv = sf_secrets_interaction_request_get_instance_private(request);

	if (priv->invocation) {
		GError *error = g_error_new(g_quark_from_string("SfSecrets"),
				1337,
				"Jag är död");
		sf_secrets_interaction_request_return_error(request, error);
		g_error_free(error);
		g_object_unref(priv->invocation);
	}
	if (priv->id)
		g_free(priv->id);
}

static void _sf_secrets_interaction_request_set_property(GObject *object, guint property_id, const GValue *value, GParamSpec *spec)
{
	SfSecretsInteractionRequest *request = SF_SECRETS_INTERACTION_REQUEST(object);
	SfSecretsInteractionRequestPrivate *priv = sf_secrets_interaction_request_get_instance_private(request);

	(void)spec;

	switch (property_id) {
		case PROP_ID:
			if (priv->id)
				g_free(priv->id);
			priv->id = g_value_dup_string(value);
		default:
			break;
	}
}

static void _sf_secrets_interaction_request_get_property(GObject *object, guint property_id, GValue *value, GParamSpec *spec)
{
	SfSecretsInteractionRequest *request = SF_SECRETS_INTERACTION_REQUEST(object);
	SfSecretsInteractionRequestPrivate *priv = sf_secrets_interaction_request_get_instance_private(request);

	(void)spec;

	switch (property_id) {
		case PROP_ID:
			g_value_set_string(value, priv->id);
			break;
		default:
			break;
	}
}

static void sf_secrets_interaction_request_class_init(SfSecretsInteractionRequestClass *request_class)
{
	G_OBJECT_CLASS(request_class)->finalize = _sf_secrets_interaction_request_finalize;
	G_OBJECT_CLASS(request_class)->set_property = _sf_secrets_interaction_request_set_property;
	G_OBJECT_CLASS(request_class)->get_property = _sf_secrets_interaction_request_get_property;

	g_object_class_install_property(G_OBJECT_CLASS(request_class),
			PROP_ID,
			g_param_spec_string("id",
				"id",
				"Request id",
				NULL,
				G_PARAM_STATIC_STRINGS |
				G_PARAM_READWRITE |
				G_PARAM_CONSTRUCT_ONLY));
}

static void sf_secrets_interaction_request_init(SfSecretsInteractionRequest *request)
{
	(void)request;
}

void sf_secrets_interaction_request_return_error(SfSecretsInteractionRequest *request, const GError *error)
{
	SfSecretsInteractionRequestPrivate *priv = sf_secrets_interaction_request_get_instance_private(request);

	(void)priv;
	(void)error;
}
