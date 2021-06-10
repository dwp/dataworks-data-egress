package uk.gov.dwp.dataworks.egress.configuration

import com.amazonaws.ClientConfiguration
import com.amazonaws.services.s3.AmazonS3EncryptionClientV2
import com.amazonaws.services.s3.AmazonS3EncryptionV2
import com.amazonaws.services.s3.model.CryptoConfigurationV2
import com.amazonaws.services.s3.model.CryptoMode
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Profile
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient
import software.amazon.awssdk.services.s3.S3AsyncClient
import software.amazon.awssdk.services.s3.S3Client
import software.amazon.awssdk.services.sqs.SqsAsyncClient
import java.time.Duration

@Configuration
@Profile("!LOCALSTACK")
class AwsConfiguration(private val encryptionMaterialsProvider: EncryptionMaterialsProvider) {

    @Bean
    fun decryptingS3Client(): AmazonS3EncryptionV2 =
        with (AmazonS3EncryptionClientV2.encryptionBuilder()) {
            withEncryptionMaterialsProvider(encryptionMaterialsProvider)
            withCryptoConfiguration(CryptoConfigurationV2().withCryptoMode(CryptoMode.AuthenticatedEncryption))
            withClientConfiguration(ClientConfiguration().apply {
                socketTimeout = 180000
            })
            build()
        }

    @Bean
    fun s3Client(): S3Client =
        with (S3Client.builder()) {
            overrideConfiguration(timeoutConfiguration())
            build()
        }



    @Bean
    fun s3AsyncClient(): S3AsyncClient =
        with (S3AsyncClient.builder()) {
            overrideConfiguration(timeoutConfiguration())
            build()
        }

    private fun timeoutConfiguration(): ClientOverrideConfiguration =
        with(ClientOverrideConfiguration.builder()) {
            apiCallTimeout(Duration.ofMinutes(30))
            apiCallAttemptTimeout(Duration.ofMinutes(30))
            build()
        }

    @Bean
    fun sqsClient(): SqsAsyncClient = SqsAsyncClient.create()

    @Bean
    fun dynamoDbClient(): DynamoDbAsyncClient = DynamoDbAsyncClient.create()
}
