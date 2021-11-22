package uk.gov.dwp.dataworks.egress.services.impl

import software.amazon.awssdk.services.s3.S3AsyncClient
import software.amazon.awssdk.services.s3.model.ObjectCannedACL
import software.amazon.awssdk.services.s3.model.PutObjectRequest
import uk.gov.dwp.dataworks.egress.domain.EgressSpecification
import java.io.File

open class EgressServiceImpl(
    private val s3AsyncClient: S3AsyncClient,
    private val assumedRoleS3ClientProvider: suspend (String) -> S3AsyncClient) {

    fun putObjectRequest(
        specification: EgressSpecification,
        key: String
    ): PutObjectRequest =
        with(PutObjectRequest.builder()) {
            bucket(specification.destinationBucket)
            acl(ObjectCannedACL.BUCKET_OWNER_FULL_CONTROL)
            key(targetKey(specification, key))
            build()
        }

    fun targetKey(
        specification: EgressSpecification,
        key: String
    ): String {
        val base = "${specification.destinationPrefix.replace(Regex("""/$"""), "")}/${File(key).name}"
            .replace(Regex("""^/"""), "")
            .replace(Regex("""\.enc$"""), if (specification.decrypt) "" else ".enc")

        return if (specification.compressionFormat?.isNotBlank() == true) {
            "${base}.${specification.compressionFormat}"
        } else {
            base
        }
    }

    suspend fun egressClient(specification: EgressSpecification): S3AsyncClient =
        if (specification.roleArn.isNullOrEmpty()) s3AsyncClient else  assumedRoleS3ClientProvider(specification.roleArn)

}
