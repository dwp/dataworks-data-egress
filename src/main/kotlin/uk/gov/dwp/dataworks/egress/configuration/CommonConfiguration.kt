package uk.gov.dwp.dataworks.egress.configuration

import org.springframework.context.annotation.Bean
import org.springframework.stereotype.Component
import software.amazon.awssdk.services.s3.S3AsyncClient
import software.amazon.awssdk.services.ssm.SsmClient
import software.amazon.awssdk.services.sts.StsClient

@Component
class CommonConfiguration {

    @Bean
    fun assumedRoleS3ClientProvider(): suspend (String) -> S3AsyncClient {
        val stsClient = StsClient.create()
        return { roleArn: String ->
            with(S3AsyncClient.builder()) {
                credentialsProvider(StsUtility.credentialsProvider(stsClient, roleArn))
                build()
            }
        }
    }

    @Bean
    fun assumedRoleSsmClientProvider(): suspend (String) -> SsmClient {
        val stsClient = StsClient.create()
        return { roleArn: String ->
            with(SsmClient.builder()) {
                credentialsProvider(StsUtility.credentialsProvider(stsClient, roleArn))
                build()
            }
        }
    }
}
