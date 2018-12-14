#ifndef SF_SECRETS_INTERACTION_REQUEST_H
#define SF_SECRETS_INTERACTION_REQUEST_H

#include <glib-object.h>

#define SF_TYPE_SECRETS_INTERACTION_REQUEST (sf_secrets_interaction_request_get_type())
#define SF_SECRETS_INTERACTION_REQUEST(o) \
    (G_TYPE_CHECK_INSTANCE_CAST((o), SF_TYPE_SECRETS_INTERACTION_REQUEST, SfSecretsInteractionRequest))
#define SF_IS_SECRETS_INTERACTION_REQUEST(o) (G_TYPE_CHECK_INSTANCE_TYPE((o), SF_TYPE_SECRETS_INTERACTION_REQUEST))

typedef struct SfSecretsInteractionRequest_ SfSecretsInteractionRequest;
typedef struct SfSecretsInteractionRequestClass_ SfSecretsInteractionRequestClass;

GType sf_secrets_interaction_request_get_type(void);
void sf_secrets_interaction_request_return_error(SfSecretsInteractionRequest *request, const GError *error);
void sf_secrets_interaction_request_return(SfSecretsInteractionRequest *request, const GBytes *bytes);

#endif /* SF_SECRETS_INTERACTION_REQUEST_H */
