package fr.insee.keycloak.providers.franceconnect;

import fr.insee.keycloak.providers.common.AbstractBaseProviderConfig;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;

import java.util.ArrayList;
import java.util.List;

import static fr.insee.keycloak.providers.common.Utils.createHardcodedAttributeMapper;
import static fr.insee.keycloak.providers.common.Utils.createUserAttributeMapper;
import static fr.insee.keycloak.providers.franceconnect.FranceConnectIdentityProviderFactory.DEFAULT_FC_ENVIRONMENT;

final class FranceConnectIdentityProviderConfig extends AbstractBaseProviderConfig {

  List<IdentityProviderMapperModel> fcProviderMapper = new ArrayList<>();

  FranceConnectIdentityProviderConfig(IdentityProviderModel identityProviderModel) {
    super(identityProviderModel);
    fcProviderMapper.add(createUserAttributeMapper(identityProviderModel.getProviderId(), "lastName", "family_name", "lastName"));
    fcProviderMapper.add(createUserAttributeMapper(identityProviderModel.getProviderId(), "firstName", "given_name", "firstName"));
    fcProviderMapper.add(createUserAttributeMapper(identityProviderModel.getProviderId(), "email", "email", "email"));
    fcProviderMapper.add(createHardcodedAttributeMapper(identityProviderModel.getProviderId(), "provider", "provider", "FC"));
  }

  FranceConnectIdentityProviderConfig() {
    super();
  }

  @Override
  protected String getEnvironmentProperty(String key) {
    var franceConnectEnvironment =
        FCEnvironment.getOrDefault(
            getConfig().get(FCEnvironment.ENVIRONMENT_PROPERTY_NAME), DEFAULT_FC_ENVIRONMENT);

    return franceConnectEnvironment.getProperty(key);
  }

  @Override
  protected List<IdentityProviderMapperModel> getDefaultMappers() {
    return this.fcProviderMapper;
  }
}
