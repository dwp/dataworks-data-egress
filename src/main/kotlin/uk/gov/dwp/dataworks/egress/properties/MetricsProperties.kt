package uk.gov.dwp.dataworks.egress.properties

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import kotlin.time.ExperimentalTime

@Configuration
@ConfigurationProperties(prefix = "metrics")
@ExperimentalTime
class MetricsProperties(var pushgatewayHost: String = "pushgateway",
                        var pushgatewayPort: Int = 9091,
                        var applicationName: String = "data_egress",
                        var scrapeInterval: Int = 70_000,
                        var deleteMetrics: Boolean = true) {

    @Bean
    fun pushgatewayHost() = pushgatewayHost

    @Bean
    fun pushgatewayPort() = pushgatewayPort

//    @Bean
//    fun instanceName() = instanceName

    @Bean
    fun applicationName() = applicationName

    @Bean
    fun scrapeInterval() = scrapeInterval

    @Bean
    fun deleteMetrics() = deleteMetrics
}
