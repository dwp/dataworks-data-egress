package uk.gov.dwp.dataworks.egress.services.impl

import com.nhaarman.mockitokotlin2.*
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.shouldBe
import software.amazon.awssdk.core.async.AsyncRequestBody
import software.amazon.awssdk.services.s3.S3AsyncClient
import software.amazon.awssdk.services.s3.model.PutObjectRequest
import software.amazon.awssdk.services.s3.model.PutObjectResponse
import uk.gov.dwp.dataworks.egress.domain.EgressSpecification
import java.io.File
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.CompletableFuture

class ControlFileServiceImplTest: StringSpec() {

    init {
        "Put control file without timestamp if not asked" {
            val (asyncS3Client, assumedRoleS3Client, controlFileService) = serviceAndItsClients()
            controlFileService.egressControlFile(egressed(), egressSpecification(CONTROL_FILE_PREFIX))
            verifyInteractions(assumedRoleS3Client, asyncS3Client, "$DESTINATION_PREFIX/$CONTROL_FILE_PREFIX")
        }

        "Put control file with timestamp if asked" {
            val (asyncS3Client, assumedRoleS3Client, controlFileService) = serviceAndItsClients()
            controlFileService.egressControlFile(egressed(), egressSpecification("$CONTROL_FILE_PREFIX-\$TODAYS_DATE"))
            verifyInteractions(assumedRoleS3Client, asyncS3Client, "$DESTINATION_PREFIX/$CONTROL_FILE_PREFIX-${SimpleDateFormat("yyyyMMdd").format(Date())}")
        }

        "Use assumed role if asked" {
            val (asyncS3Client, assumedRoleS3Client, controlFileService) = serviceAndItsClients()
            controlFileService.egressControlFile(egressed(), egressSpecification(CONTROL_FILE_PREFIX, ROLE_ARN))
            verifyInteractions(asyncS3Client, assumedRoleS3Client, "$DESTINATION_PREFIX/$CONTROL_FILE_PREFIX")
        }

        "Do not put control file if not asked" {
            val (asyncS3Client, assumedRoleS3Client, controlFileService) = serviceAndItsClients()
            controlFileService.egressControlFile(egressed(), egressSpecification())
            verifyZeroInteractions(asyncS3Client)
            verifyZeroInteractions(assumedRoleS3Client)
        }
    }

    private fun serviceAndItsClients(): Triple<S3AsyncClient, S3AsyncClient, ControlFileServiceImpl> {
        val asyncS3Client = s3AsyncClient()
        val assumedRoleS3Client = s3AsyncClient()
        val assumedRoleS3ClientProvider: suspend (String) -> S3AsyncClient = { assumedRoleS3Client }
        val controlFileService = ControlFileServiceImpl(asyncS3Client, assumedRoleS3ClientProvider)
        return Triple(asyncS3Client, assumedRoleS3Client, controlFileService)
    }

    private fun egressed(): List<String> = List(10) { "prefix1/prefix2/database.collection${it}.gz" }

    private fun s3AsyncClient(): S3AsyncClient {
        val asyncS3Client = mock<S3AsyncClient> {
            on {
                putObject(any<PutObjectRequest>(), any<AsyncRequestBody>())
            } doReturn CompletableFuture.completedFuture(PutObjectResponse.builder().build())
        }
        return asyncS3Client
    }

    private fun verifyInteractions(assumedRoleS3Client: S3AsyncClient,
                                   asyncS3Client: S3AsyncClient,
                                   expectedKey: String) {
        verifyZeroInteractions(assumedRoleS3Client)
        argumentCaptor<PutObjectRequest> {
            val bodyCaptor = argumentCaptor<AsyncRequestBody>()
            verify(asyncS3Client, times(1)).putObject(capture(), bodyCaptor.capture())

            firstValue.run {
                bucket() shouldBe DESTINATION_BUCKET
                key() shouldBe expectedKey
            }


            bodyCaptor.firstValue.contentLength().run {
                isPresent.shouldBeTrue()
                get() shouldBe egressed().map(::File).map(File::getName).sumOf(String::length) + 10
            }
        }
    }

    private fun egressSpecification(controlFilePrefix: String? = null, roleArn: String? = null): EgressSpecification =
        EgressSpecification(
            SOURCE_BUCKET,
            SOURCE_PREFIX,
            DESTINATION_BUCKET,
            DESTINATION_PREFIX,
            TRANSFER_TYPE,
            decrypt = false,
            rewrapDataKey = false,
            ENCRYPTING_KEY_PARAMETER,
            compress = false,
            compressionFormat = null,
            roleArn,
            PIPELINE_NAME,
            RECIPIENT,
            timestampOutput = false,
            controlFilePrefix)

    companion object {
        private const val SOURCE_BUCKET = "sourceBucket"
        private const val SOURCE_PREFIX = "sourcePrefix"
        private const val DESTINATION_BUCKET = "destinationBucket"
        private const val DESTINATION_PREFIX = "destinationPrefix"
        private const val TRANSFER_TYPE = "S3"
        private const val ROLE_ARN = "roleArn"
        private const val ENCRYPTING_KEY_PARAMETER = "encryptingKeySsmParmName"
        private const val PIPELINE_NAME = "pipelineName"
        private const val RECIPIENT = "recipient"
        private const val CONTROL_FILE_PREFIX = "controlFilePrefix"
    }
}
