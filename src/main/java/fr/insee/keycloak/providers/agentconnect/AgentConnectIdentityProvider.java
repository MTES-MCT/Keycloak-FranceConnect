package fr.insee.keycloak.providers.agentconnect;

import fr.insee.keycloak.providers.common.AbstractBaseIdentityProvider;
import fr.insee.keycloak.providers.common.Utils;
import jakarta.ws.rs.core.UriBuilder;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.models.KeycloakSession;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

final class AgentConnectIdentityProvider
    extends AbstractBaseIdentityProvider<AgentConnectIdentityProviderConfig> {

  static final String MFA_INSUFFICIENT_ACR_MESSAGE_KEY = "agentconnectMfaRequired";

  private static final List<String> ACCEPTED_MFA_ACR_VALUES = List.of(
      "eidas2",
      "eidas3",
      "https://proconnect.gouv.fr/assurance/self-asserted-2fa",
      "https://proconnect.gouv.fr/assurance/consistency-checked-2fa"
  );

  private static final Set<String> ACCEPTED_MFA_ACR_VALUES_SET = Set.copyOf(ACCEPTED_MFA_ACR_VALUES);

  AgentConnectIdentityProvider(KeycloakSession session, AgentConnectIdentityProviderConfig config) {
    super(session, config, Utils.getJsonWebKeySetFrom(config.getJwksUrl(), session));
  }

  @Override
  protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
    var config = getConfig();
    UriBuilder uriBuilder;

    if (config.isMfaEnabled()) {
      var baseUri = super.createAuthorizationUrl(request).build().toString();
      var encodedClaims = URLEncoder.encode(buildMfaClaimsParam(), StandardCharsets.UTF_8);
      uriBuilder = UriBuilder.fromUri(URI.create(baseUri + "&claims=" + encodedClaims));
    } else {
      request
          .getAuthenticationSession()
          .setClientNote(OAuth2Constants.ACR_VALUES, config.getEidasLevel().toString());
      uriBuilder = super.createAuthorizationUrl(request);
    }

    logger.debugv("AgentConnect Authorization Url: {0}", uriBuilder.build().toString());

    return uriBuilder;
  }

  @Override
  protected void validateAcrClaim(String acrClaim) {
    if (getConfig().isMfaEnabled()) {
      if (!ACCEPTED_MFA_ACR_VALUES_SET.contains(acrClaim)) {
        throw new IdentityBrokerException(MFA_INSUFFICIENT_ACR_MESSAGE_KEY);
      }
    } else {
      super.validateAcrClaim(acrClaim);
    }
  }

  private static String buildMfaClaimsParam() {
    return "{\"id_token\":{\"acr\":{\"essential\":true,\"values\":"
        + ACCEPTED_MFA_ACR_VALUES.stream()
            .map(acrValue -> "\"" + acrValue + "\"")
            .collect(Collectors.joining(",", "[", "]"))
        + "}}}";
  }
}
