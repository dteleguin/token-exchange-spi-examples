package pro.carretti.keycloak.examples.tokenexchange;

import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oidc.TokenExchangeProvider;
import org.keycloak.protocol.oidc.TokenExchangeProviderFactory;

public class CrossRealmTokenExchangeProviderFactory implements TokenExchangeProviderFactory {

    private static final String PROVIDER_ID = "cross-realm-example";

    @Override
    public TokenExchangeProvider create(KeycloakSession session) {
        return new CrossRealmTokenExchangeProvider();
    }

    @Override
    public void init(Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public int order() {
        return 200;
    }

}
