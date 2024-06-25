package org.apereo.cas;

import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.monitor.SystemMonitorHealthIndicator;
import org.apereo.cas.test.CasTestExtension;
import lombok.val;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.actuate.autoconfigure.metrics.MetricsAutoConfiguration;
import org.springframework.boot.actuate.autoconfigure.metrics.MetricsEndpointAutoConfiguration;
import org.springframework.boot.actuate.autoconfigure.metrics.export.simple.SimpleMetricsExportAutoConfiguration;
import org.springframework.boot.actuate.health.Status;
import org.springframework.boot.actuate.metrics.MetricsEndpoint;
import org.springframework.boot.autoconfigure.aop.AopAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.autoconfigure.RefreshAutoConfiguration;
import static org.junit.jupiter.api.Assertions.*;

/**
 * This is {@link SystemMonitorHealthIndicatorTests}.
 *
 * @author Misagh Moayyed
 * @since 6.2.0
 */
@SpringBootTest(classes = {
    MetricsAutoConfiguration.class,
    SimpleMetricsExportAutoConfiguration.class,
    MetricsEndpointAutoConfiguration.class,
    RefreshAutoConfiguration.class,
    WebMvcAutoConfiguration.class,
    AopAutoConfiguration.class
}, properties = {
    "management.endpoint.metrics.enabled=true",
    "management.endpoints.web.exposure.include=*",
    "management.metrics.export.simple.enabled=true",
    "management.endpoint.health.enabled=true"
})
@EnableConfigurationProperties(CasConfigurationProperties.class)
@Tag("Metrics")
@ExtendWith(CasTestExtension.class)
class SystemMonitorHealthIndicatorTests {

    @Autowired
    @Qualifier("metricsEndpoint")
    private ObjectProvider<MetricsEndpoint> metricsEndpoint;
    
    @Test
    void verifyObserveOk() throws Throwable {
        val monitor = new SystemMonitorHealthIndicator(metricsEndpoint, 10);
        val status = monitor.health().getStatus();
        assertEquals(Status.UP, status);
    }
}
