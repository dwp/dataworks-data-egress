package uk.gov.dwp.dataworks.egress

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Import
import org.springframework.context.annotation.PropertySource
import uk.gov.dwp.dataworks.egress.configuration.ContextConfiguration
import uk.gov.dwp.dataworks.egress.configuration.LocalstackConfiguration
import uk.gov.dwp.dataworks.egress.configuration.MetricsConfiguration
import uk.gov.dwp.dataworks.egress.properties.AwsProperties
import uk.gov.dwp.dataworks.egress.properties.MetricsProperties
import uk.gov.dwp.dataworks.egress.properties.SecurityProperties
import uk.gov.dwp.dataworks.egress.provider.impl.DksEncryptionMaterialsProvider
import uk.gov.dwp.dataworks.egress.provider.impl.SecureHttpClientProvider
import uk.gov.dwp.dataworks.egress.services.impl.CipherServiceImpl
import uk.gov.dwp.dataworks.egress.services.impl.DataKeyServiceImpl
import kotlin.time.ExperimentalTime

@ExperimentalTime
@Import(LocalstackConfiguration::class,
    ContextConfiguration::class,
    DksEncryptionMaterialsProvider::class,
    DataKeyServiceImpl::class,
    SecureHttpClientProvider::class,
    AwsProperties::class,
    SecurityProperties::class,
    CipherServiceImpl::class,
    MetricsProperties::class,
    MetricsConfiguration::class)
@Configuration
@PropertySource("classpath:integration.properties")
class TestConfiguration {
    @Bean
    fun keystore() = "dataworks-data-egress-integration-tests-keystore.jks"

    @Bean
    fun keystorePassword(): String = "changeit"

    @Bean
    fun keystoreAlias(): String = "cid"

    @Bean
    fun keyPassword(): String = "changeit"

    @Bean
    fun truststore(): String = "dataworks-data-egress-integration-tests-truststore.jks"

    @Bean
    fun truststorePassword(): String = "changeit"

    @Bean
    fun dksUrl(): String = "https://dks:8443"

    @Bean
    fun cipherTransformation() = "AES/CTR/NoPadding"

    @Bean
    fun pushgatewayPort() = 9091

    @Bean
    fun pushgatewayHost() = "pushgatewayHost"
}
