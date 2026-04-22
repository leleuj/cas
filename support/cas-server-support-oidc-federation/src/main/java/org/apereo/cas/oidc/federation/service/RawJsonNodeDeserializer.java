package org.apereo.cas.oidc.federation.service;

import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.ValueDeserializer;

/**
 * This is {@link RawJsonNodeDeserializer}.
 *
 * @author Jerome LELEU
 * @since 8.0.0
 */
public class RawJsonNodeDeserializer extends ValueDeserializer<JsonNode> {

    private static final ObjectMapper CLEAN_MAPPER = new ObjectMapper();

    @Override
    public JsonNode deserialize(final JsonParser p, final DeserializationContext ctxt) throws JacksonException {
        return CLEAN_MAPPER.readTree(p);
    }
}
