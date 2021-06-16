package uk.gov.dwp.dataworks.egress.properties

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
@ConfigurationProperties(prefix = "cipher")
class CipherProperties(var transformation: String = "AES/CTR/NoPadding") {

    @Bean
    fun cipherTransformation() = transformation
}
