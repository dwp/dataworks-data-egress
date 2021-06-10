package uk.gov.dwp.dataworks.egress.properties

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
@ConfigurationProperties(prefix = "dks")
class DksProperties(var url: String = "") {

    @Bean
    fun dksUrl() = url
}
