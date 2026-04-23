package org.apereo.cas.oidc.federation.web;

import module java.base;
import org.apereo.cas.configuration.model.support.oidc.OidcProperties;
import org.apereo.cas.oidc.OidcConstants;
import org.apereo.cas.oidc.federation.OidcFederationEntityStatementService;
import org.apereo.cas.oidc.federation.service.OidcFederationEntityService;
import org.apereo.cas.oidc.issuer.OidcIssuerService;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.util.OAuth20Utils;
import org.apereo.cas.web.AbstractController;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityType;
import com.nimbusds.openid.connect.sdk.federation.entities.FederationEntityMetadata;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.val;
import net.minidev.json.JSONObject;
import net.minidev.json.JSONValue;
import org.pac4j.jee.context.JEEContext;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * This is {@link OidcTrustAnchorFetchEndpointController}.
 *
 * @author Jerome LELEU
 * @since 8.0.0
 */
@Tag(name = "OpenID Connect")
@RequiredArgsConstructor
public class OidcTrustAnchorFetchEndpointController extends AbstractController {

    private final ServicesManager servicesManager;
    private final OidcIssuerService oidcIssuerService;
    private final OidcFederationEntityStatementService federationEntityStatementService;
    private final OidcProperties oidcProperties;

    /**
     * Gets the entity statement for the requested entity.
     *
     * @param sub the entityId
     * @param request  the request
     * @param response the response
     * @return the specific entity statement
     */
    @GetMapping('/' + OidcConstants.BASE_OIDC_URL + '/' + OidcConstants.FETCH_FEDERATION_URL)
    @Operation(summary = "Handle OIDC fetch federation request",
        description = "Handles requests for the fetch federation endpoint",
        parameters = {
            @Parameter(name = "sub", description = "entityId", required = true)
        })
    public ResponseEntity fetchEntityStatement(@RequestParam("sub") final String sub,
        final HttpServletRequest request, final HttpServletResponse response) throws Exception {

        val webContext = new JEEContext(request, response);
        if (!oidcIssuerService.validateIssuer(webContext, List.of(OidcConstants.FETCH_FEDERATION_URL))) {
            val body = OAuth20Utils.getErrorResponseBody(OAuth20Constants.INVALID_REQUEST, "Invalid issuer");
            return new ResponseEntity<>(body, HttpStatus.BAD_REQUEST);
        }

        val requestedService = searchService(sub);
        if (requestedService == null) {
            val body = OAuth20Utils.getErrorResponseBody(OAuth20Constants.INVALID_REQUEST, "Invalid entity");
            return new ResponseEntity<>(body, HttpStatus.BAD_REQUEST);
        }

        val issuer = oidcProperties.getCore().getIssuer();
        val metadata = (JSONObject) JSONValue.parse(requestedService.getMetadata().toString());
        val fedMeta = new FederationEntityMetadata();
        fedMeta.setOrganizationName(oidcProperties.getFederation().getOrganization());
        fedMeta.setContacts(oidcProperties.getFederation().getContacts());
        fedMeta.setFederationFetchEndpointURI(new URI(issuer + OidcConstants.FETCH_FEDERATION_URL));
        metadata.put(EntityType.FEDERATION_ENTITY.getValue(), fedMeta.toJSONObject());

        val entityStatement = federationEntityStatementService.createAndSign(issuer, sub, metadata, null);
        return ResponseEntity.ok()
            .cacheControl(CacheControl.noStore().mustRevalidate())
            .header(HttpHeaders.ACCEPT, OidcConstants.ENTITY_STATEMENT_CONTENT_TYPE.toString())
            .contentType(OidcConstants.ENTITY_STATEMENT_CONTENT_TYPE)
            .body(entityStatement.getSignedStatement().serialize());
    }

    protected OidcFederationEntityService searchService(final String sub) {
        val oidcServices = servicesManager.getAllServicesOfType(OidcFederationEntityService.class);
        for (val service : oidcServices) {
            if (service.getServiceId().equals(sub)) {
                return service;
            }
        }
        return null;
    }
}
