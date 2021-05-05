package pro.carretti.keycloak.examples.tokenexchange;

import java.util.Map;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.jboss.logging.Logger;

import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenExchangeContext;
import org.keycloak.protocol.oidc.TokenExchangeProvider;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.resources.Cors;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

public class CrossRealmTokenExchangeProvider implements TokenExchangeProvider {

    private static final Logger LOG = Logger.getLogger(CrossRealmTokenExchangeProvider.class);
    
    private static final String ROLE_IMPERSONATION = "x-impersonation";
    private static final String SCOPE_IMPERSONATION = "x-impersonation";
    private static final String GROUP_IMPERSONATION = "X-Impersonation";
    private static final String CLAIM_ACT = "act";

    @Override
    public boolean supports(TokenExchangeContext context) {
        
        // Context objects
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        TokenExchangeContext.Params params = context.getParams();

        // Request parameters
        String subjectToken = params.getSubjectToken();

        JsonWebToken jwt;

        try {
            JWSInput jws = new JWSInput(subjectToken);
            jwt = jws.readJsonContent(JsonWebToken.class);
        } catch (JWSInputException e) {
            return false;
        }

        String baseUri = session.getContext().getUri().getBaseUri().toASCIIString();
        String issuer = jwt.getIssuer();
        String realmName = issuer.substring(issuer.lastIndexOf('/') + 1);        
        
        return issuer.startsWith(baseUri) && !realmName.equals(realm.getName());
        
    }

    @Override
    public Response exchange(TokenExchangeContext context) {

        // Context objects
        EventBuilder event = context.getEvent();
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        ClientConnection clientConnection = context.getClientConnection();
        HttpHeaders headers = context.getHeaders();
        TokenManager tokenManager = (TokenManager) context.getTokenManager();
        ClientModel client = context.getClient();
        Map<String, String> clientAuthAttributes = context.getClientAuthAttributes();
        Cors cors = (Cors) context.getCors();
        TokenExchangeContext.Params params = context.getParams();

        // Request parameters
        String subjectTokenType = params.getSubjectTokenType();
        String subjectToken = params.getSubjectToken();
        String requestedTokenType = params.getRequestedTokenType();
        String requestedSubject = context.getFormParams().getFirst(OAuth2Constants.REQUESTED_SUBJECT);
        String audience = params.getAudience();

        // Validate token

        JsonWebToken jwt;

        try {
            JWSInput jws = new JWSInput(subjectToken);
            jwt = jws.readJsonContent(JsonWebToken.class);
        } catch (JWSInputException e) {
            event.detail(Details.REASON, "unable to parse jwt subject_token");
            event.error(Errors.INVALID_TOKEN);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_TOKEN, "Invalid subject token", Response.Status.BAD_REQUEST);
        }

        String issuer = jwt.getIssuer();
        String realmName = issuer.substring(issuer.lastIndexOf('/') + 1);
        RealmModel realm0 = session.realms().getRealm(realmName);
        
        session.getContext().setRealm(realm0);
        AuthenticationManager.AuthResult authResult = AuthenticationManager.verifyIdentityToken(session, realm0, session.getContext().getUri(), clientConnection, true, true, null, false, subjectToken, headers);
        session.getContext().setRealm(realm);
        
        if (authResult == null) {
            event.detail(Details.REASON, "subject_token validation failure");
            event.error(Errors.INVALID_TOKEN);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_TOKEN, "Invalid token", Response.Status.BAD_REQUEST);
        }

        UserModel tokenUser = authResult.getUser();
        UserSessionModel tokenSession = authResult.getSession();
        AccessToken token = authResult.getToken();

        // Check roles & permissions for impersonation role

        String roleName = String.format("%s-%s", ROLE_IMPERSONATION, realm.getName());
        RoleModel role = realm0.getRole(roleName);
        
        if (role == null) {
            event.detail(Details.REASON, "Impersonation role does not exist: " + roleName);
            event.error(Errors.NOT_ALLOWED);
            throw new CorsErrorResponseException(cors, OAuthErrorException.ACCESS_DENIED, "User not allowed to impersonate", Response.Status.FORBIDDEN);            
        }

        if (!tokenUser.hasRole(role)) {
            event.detail(Details.REASON, "User not allowed to impersonate");
            event.error(Errors.NOT_ALLOWED);
            throw new CorsErrorResponseException(cors, OAuthErrorException.ACCESS_DENIED, "User not allowed to impersonate", Response.Status.FORBIDDEN);
        }

        // Impersonatee

        UserModel user = session.users().getUserByUsername(requestedSubject, realm);
        
        if (user == null) {
            event.detail(Details.REASON, "requested_subject validation failure");
            event.error(Errors.INVALID_TOKEN);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_TOKEN, "Invalid requested subject", Response.Status.BAD_REQUEST);
        }
        
        GroupModel group = realm
                .searchForGroupByNameStream(GROUP_IMPERSONATION, 0, 1)
                .findFirst()
                .orElse(null);
        
        if (group == null) {
            event.detail(Details.REASON, "Impersonation group does not exist: " + GROUP_IMPERSONATION);
            event.error(Errors.NOT_ALLOWED);
            throw new CorsErrorResponseException(cors, OAuthErrorException.ACCESS_DENIED, "User not allowed to impersonate", Response.Status.FORBIDDEN);            
        }        
        
        if (!user.isMemberOf(group)) {
            event.detail(Details.REASON, "User not allowed to be impersonated");
            event.error(Errors.NOT_ALLOWED);
            throw new CorsErrorResponseException(cors, OAuthErrorException.ACCESS_DENIED, "User not allowed to be impersonated", Response.Status.FORBIDDEN);
        }

        // Generate target token

        UserSessionModel userSession = session.sessions().createUserSession(realm, user, user.getUsername(), clientConnection.getRemoteAddr(), "impersonate", false, null, null);
        RootAuthenticationSessionModel rootAuthSession = new AuthenticationSessionManager(session).createAuthenticationSession(realm, false);
        AuthenticationSessionModel authSession = rootAuthSession.createAuthenticationSession(client);

        authSession.setAuthenticatedUser(user);
        authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        authSession.setClientNote(OIDCLoginProtocol.ISSUER, Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));
        authSession.setClientNote(OIDCLoginProtocol.SCOPE_PARAM, context.getParams().getScope());

        event.session(userSession);

        AuthenticationManager.setClientScopesInSession(authSession);
        ClientSessionContext clientSessionCtx = TokenManager.attachAuthenticationSession(session, userSession, authSession);

        updateUserSessionFromClientAuth(userSession, clientAuthAttributes);

        TokenManager.AccessTokenResponseBuilder responseBuilder = tokenManager.responseBuilder(realm, client, event, session, userSession, clientSessionCtx)
                .generateAccessToken();

        AccessToken newToken = responseBuilder.getAccessToken();
        
        // Inject impersonation scope into access token
        newToken.setScope(newToken.getScope() + " " + SCOPE_IMPERSONATION);

        // Inject impersonator info into access token
        AccessToken act = new AccessToken()
                .subject(token.getSubject())
                .issuer(token.getIssuer());
        act.setPreferredUsername(token.getPreferredUsername());
        
        newToken.setOtherClaims(CLAIM_ACT, act);

        AccessTokenResponse response = responseBuilder.build();

        event.detail(Details.AUDIENCE, audience);
        event.success();

        return cors.builder(Response.ok(response, MediaType.APPLICATION_JSON_TYPE)).build();

    }

    @Override
    public void close() {
    }

    private void updateUserSessionFromClientAuth(UserSessionModel userSession, Map<String, String> clientAuthAttributes) {
        for (Map.Entry<String, String> attr : clientAuthAttributes.entrySet()) {
            userSession.setNote(attr.getKey(), attr.getValue());
        }
    }

}
