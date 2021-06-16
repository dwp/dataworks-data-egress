package uk.gov.dwp.dataworks.egress.properties

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
@ConfigurationProperties(prefix = "security")
class SecurityProperties(var keystore: String = "",
                         var keystorePassword: String = "",
                         var keystoreAlias: String = "",
                         var keyPassword: String = "",
                         var truststore: String = "",
                         var truststorePassword: String = "",
                         var connectTimeout: Int = 300_000,
                         var connectionRequestTimeout: Int = 300_000,
                         var socketTimeout: Int = 300_000) {

    @Bean
    fun keystore() = keystore

    @Bean
    fun keystorePassword(): String = keystorePassword

    @Bean
    fun keystoreAlias(): String = keystoreAlias

    @Bean
    fun keyPassword(): String = keyPassword

    @Bean
    fun truststore(): String = truststore

    @Bean
    fun truststorePassword(): String = truststorePassword

    @Bean
    fun connectTimeout(): Int = connectTimeout

    @Bean
    fun connectionRequestTimeout(): Int = connectionRequestTimeout

    @Bean
    fun socketTimeout(): Int = socketTimeout
}
