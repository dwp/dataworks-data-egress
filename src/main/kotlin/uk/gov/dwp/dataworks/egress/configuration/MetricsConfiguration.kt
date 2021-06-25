package uk.gov.dwp.dataworks.egress.configuration

import io.micrometer.core.instrument.Clock
import io.micrometer.core.instrument.Metrics
import io.micrometer.prometheus.PrometheusConfig
import io.micrometer.prometheus.PrometheusMeterRegistry
import io.prometheus.client.CollectorRegistry
import io.prometheus.client.Counter
import io.prometheus.client.Gauge
import io.prometheus.client.exporter.PushGateway
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import javax.annotation.PostConstruct

@Configuration
class MetricsConfiguration(private val pushgatewayHost: String, private val pushgatewayPort: Int) {

    @Bean
    fun pushGateway(): PushGateway = PushGateway("$pushgatewayHost:$pushgatewayPort")

    @Bean
    fun sentFilesSuccess() =
        counter("data_egress_s3_files_sent_success", "Count of sent s3 files sent successfully")

    @Bean
    fun sentFilesFailure() =
        counter("data_egress_s3_files_sent_failure", "Count of s3 files failed to send")

    private fun gauge(name: String, help: String, vararg labels: String): Gauge =
        with(Gauge.build()) {
            name(name)
            labelNames(*labels)
            help(help)
            register()
        }

    private fun counter(name: String, help: String, vararg labels: String): Counter =
        with(Counter.build()) {
            name(name)
            labelNames(*labels)
            help(help)
            register()
        }

    @PostConstruct
    fun init() {
        Metrics.globalRegistry.add(PrometheusMeterRegistry(PrometheusConfig.DEFAULT, CollectorRegistry.defaultRegistry, Clock.SYSTEM))
    }
}
