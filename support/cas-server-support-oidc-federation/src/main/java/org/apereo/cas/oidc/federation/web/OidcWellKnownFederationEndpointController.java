package org.apereo.cas.oidc.federation.web;

import module java.base;
import org.apereo.cas.configuration.model.support.oidc.OidcProperties;
import org.apereo.cas.configuration.model.support.oidc.federation.OidcFederationRole;
import org.apereo.cas.oidc.OidcConstants;
import org.apereo.cas.oidc.discovery.OidcServerDiscoverySettings;
import org.apereo.cas.oidc.federation.OidcFederationEntityStatementService;
import org.apereo.cas.oidc.issuer.OidcIssuerService;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.util.OAuth20Utils;
import org.apereo.cas.web.AbstractController;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityType;
import com.nimbusds.openid.connect.sdk.federation.entities.FederationEntityMetadata;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.val;
import net.minidev.json.JSONObject;
import net.minidev.json.JSONValue;
import org.pac4j.jee.context.JEEContext;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import static org.apereo.cas.configuration.model.support.oidc.federation.OidcFederationRole.isTaOrIntermediate;

/**
 * This is {@link OidcWellKnownFederationEndpointController}.
 *
 * @author Misagh Moayyed
 * @since 7.3.0
 */
@Tag(name = "OpenID Connect")
@RequiredArgsConstructor
public class OidcWellKnownFederationEndpointController extends AbstractController {

    private final OidcIssuerService oidcIssuerService;
    private final OidcFederationEntityStatementService federationEntityStatementService;
    private final ObjectProvider<OidcServerDiscoverySettings> serverDiscoverySettings;
    private final OidcProperties oidcProperties;

    /**
     * Gets well known discovery federation configuration.
     *
     * @param request  the request
     * @param response the response
     * @return the well known discovery configuration
     */
    @GetMapping({
        '/' + OidcConstants.BASE_OIDC_URL + '/' + OidcConstants.WELL_KNOWN_OPENID_FEDERATION_URL,
        "/**/" + OidcConstants.WELL_KNOWN_OPENID_FEDERATION_URL
    })
    @Operation(summary = "Handle OIDC discovery federation request",
        description = "Handles requests for well-known OIDC discovery federation configuration")
    public ResponseEntity getWellKnownDiscoveryConfiguration(
        final HttpServletRequest request, final HttpServletResponse response) throws Exception {

        val webContext = new JEEContext(request, response);
        if (!oidcIssuerService.validateIssuer(webContext, List.of(OidcConstants.WELL_KNOWN_OPENID_FEDERATION_URL))) {
            val body = OAuth20Utils.getErrorResponseBody(OAuth20Constants.INVALID_REQUEST, "Invalid issuer");
            return new ResponseEntity<>(body, HttpStatus.BAD_REQUEST);
        }

        val role = oidcProperties.getFederation().getRole();
        val settings = serverDiscoverySettings.getIfAvailable();
        var issuer = oidcProperties.getCore().getIssuer();
        val metadata = new JSONObject();
        var authorityHints = (List<EntityID>) null;
        if (settings != null) {
            if (role != OidcFederationRole.OPENID_PROVIDER) {
                throw new IllegalArgumentException("Federation role [" + role + "] is not supported for OpenID Provider");
            }
            issuer = settings.getIssuer();

            authorityHints = oidcProperties.getFederation().getAuthorityHints().stream().map(EntityID::new).toList();

            val json = JSONValue.parse(settings.toJson());
            metadata.put(EntityType.OPENID_PROVIDER.getValue(), json);
        } else if (!isTaOrIntermediate(role)) {
            throw new IllegalArgumentException("Federation role [" + role + "] is not supported for Trust Anchor/Intermediate");
        }

        val fedMeta = new FederationEntityMetadata();
        fedMeta.setOrganizationName(oidcProperties.getFederation().getOrganization());
        fedMeta.setContacts(oidcProperties.getFederation().getContacts());
        if (role == OidcFederationRole.TRUST_ANCHOR) {
            fedMeta.setFederationFetchEndpointURI(new URI(issuer + OidcConstants.FETCH_FEDERATION_URL));
        }
        metadata.put(EntityType.FEDERATION_ENTITY.getValue(), fedMeta.toJSONObject());

        val entityStatement = federationEntityStatementService.createAndSign(issuer, issuer, metadata, authorityHints);
        return ResponseEntity.ok()
            .cacheControl(CacheControl.noStore().mustRevalidate())
            .header(HttpHeaders.ACCEPT, OidcConstants.ENTITY_STATEMENT_CONTENT_TYPE.toString())
            .contentType(OidcConstants.ENTITY_STATEMENT_CONTENT_TYPE)
            .body(entityStatement.getSignedStatement().serialize());
    }
}
