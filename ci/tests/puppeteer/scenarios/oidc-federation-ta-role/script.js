const cas = require("../../cas.js");
const assert = require("assert");

(async () => {

    const url = "https://localhost:8443/cas/oidc/.well-known/openid-federation";
    const jwt = await cas.doGet(url,
        (res) => res.data,
        (error) => {
            throw `Federation endpoint not available: ${error}`;
        });

    const decoded = await cas.decodeJwt(jwt);
    await cas.log(decoded);
    assert(decoded.iss !== undefined);
    assert(decoded.sub !== undefined);
    assert(decoded.exp !== undefined);
    assert(decoded.jwks !== undefined);

    const metadata = decoded.metadata;
    const federationEntity = metadata["federation_entity"];
    assert(federationEntity !== undefined);
    assert(metadata["openid_provider"] === undefined);
    assert(decoded["authority_hints"] === undefined);

    assert(federationEntity["organization_name"] === "ApereoTA");
    assert(federationEntity["federation_fetch_endpoint"] === "https://localhost:8443/cas/oidc/fetch");
    assert(federationEntity["contacts"] !== undefined);

})();
