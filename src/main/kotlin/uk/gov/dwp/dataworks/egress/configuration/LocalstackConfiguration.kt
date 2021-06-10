package uk.gov.dwp.dataworks.egress.configuration

import com.amazonaws.ClientConfiguration
import com.amazonaws.Protocol
import com.amazonaws.auth.AWSStaticCredentialsProvider
import com.amazonaws.auth.BasicAWSCredentials
import com.amazonaws.services.s3.AmazonS3EncryptionClientV2
import com.amazonaws.services.s3.AmazonS3EncryptionV2
import com.amazonaws.services.s3.model.CryptoConfigurationV2
import com.amazonaws.services.s3.model.CryptoMode
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Profile
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider
import software.amazon.awssdk.awscore.client.builder.AwsClientBuilder
import software.amazon.awssdk.regions.Region
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient
import software.amazon.awssdk.services.s3.S3AsyncClient
import software.amazon.awssdk.services.s3.S3Client
import software.amazon.awssdk.services.sqs.SqsAsyncClient
import java.net.URI
import com.amazonaws.client.builder.AwsClientBuilder as AwsClientBuilderV1

@Configuration
@Profile("LOCALSTACK")
class LocalstackConfiguration(private val encryptionMaterialsProvider: EncryptionMaterialsProvider) {

    @Bean
    fun decryptingS3Client(): AmazonS3EncryptionV2 =
            with (AmazonS3EncryptionClientV2.encryptionBuilder()) {
                withPathStyleAccessEnabled(true)
                disableChunkedEncoding()
                withEncryptionMaterialsProvider(encryptionMaterialsProvider)
                withCryptoConfiguration(CryptoConfigurationV2().withCryptoMode(CryptoMode.AuthenticatedEncryption))
                withEndpointConfiguration(AwsClientBuilderV1.EndpointConfiguration(localstackEndpoint, localstackSigningRegion))
                withClientConfiguration(ClientConfiguration().withProtocol(Protocol.HTTP))
                withCredentials(AWSStaticCredentialsProvider(BasicAWSCredentials(localstackAccessKeyId, localstackSecretAccessKey)))
                build()
            }


    @Bean
    fun sqsClient(): SqsAsyncClient = SqsAsyncClient.builder().localstack()

    @Bean
    fun s3AsyncClient(): S3AsyncClient = S3AsyncClient.builder().localstack()

    @Bean
    fun s3Client(): S3Client = S3Client.builder().localstack()

    @Bean
    fun dynamoDbClient(): DynamoDbAsyncClient = DynamoDbAsyncClient.builder().localstack()

    fun <B: AwsClientBuilder<B, C>?, C> AwsClientBuilder<B, C>.localstack(): C =
        run {
            region(Region.EU_WEST_2)
            endpointOverride(URI(localstackEndpoint))
            credentialsProvider(credentialsProvider())
            build()
        }

    private fun credentialsProvider() =
        StaticCredentialsProvider.create(AwsBasicCredentials.create(localstackAccessKeyId,localstackSecretAccessKey))

    companion object {
        private const val localstackSigningRegion = "eu-west-2"
        private const val localstackEndpoint = "http://localstack:4566/"
        private const val localstackAccessKeyId = "accessKeyId"
        private const val localstackSecretAccessKey = "secretAccessKey"
    }
}
