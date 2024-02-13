package org.apereo.cas.web;

import org.apereo.cas.configuration.model.support.captcha.GoogleRecaptchaProperties;
import org.apereo.cas.util.CollectionUtils;
import org.apereo.cas.util.http.HttpExecutionRequest;
import lombok.val;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;

/**
 * This is {@link FriendlyCaptchaValidator}.
 *
 * @author Jerome LELEU
 * @since 7.1.0
 */
public class FriendlyCaptchaValidator extends BaseCaptchaValidator {

    /**
     * Recaptcha token as a request parameter.
     */
    public static final String REQUEST_PARAM_RECAPTCHA_TOKEN = "frc-captcha-solution";

    public FriendlyCaptchaValidator(final GoogleRecaptchaProperties recaptchaProperties) {
        super(recaptchaProperties);
    }

    @Override
    protected HttpExecutionRequest prepareRequest(final String recaptchaResponse, final String userAgent) throws Exception {
        val data = new HashMap<>();
        data.put("siteKey", getRecaptchaProperties().getSiteKey());
        data.put("secret", getRecaptchaProperties().getSecret());
        data.put("solution", recaptchaResponse);

        val json = MAPPER.writeValueAsString(data);

        return HttpExecutionRequest.builder()
                .method(HttpMethod.POST)
                .url(getRecaptchaProperties().getVerifyUrl())
                .headers(CollectionUtils.wrap("Content-Type", MediaType.APPLICATION_JSON_VALUE))
                .entity(json)
                .build();
    }

    @Override
    public String getRecaptchaResponse(final HttpServletRequest request) {
        return request.getParameter(REQUEST_PARAM_RECAPTCHA_TOKEN);
    }
}
