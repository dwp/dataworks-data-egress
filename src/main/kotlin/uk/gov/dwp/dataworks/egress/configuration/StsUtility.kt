package uk.gov.dwp.dataworks.egress.configuration

import software.amazon.awssdk.services.sts.StsClient
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleCredentialsProvider
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest

object StsUtility {

    fun credentialsProvider(stsClient: StsClient, roleArn: String): StsAssumeRoleCredentialsProvider =
        with(StsAssumeRoleCredentialsProvider.builder()) {
            refreshRequest(assumeRoleRequest(roleArn))
            stsClient(stsClient)
            build()
        }

    private fun assumeRoleRequest(arn: String): AssumeRoleRequest =
        with(AssumeRoleRequest.builder()) {
            roleArn(arn)
            roleSessionName("data-egress")
            build()
        }
}
