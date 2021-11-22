package uk.gov.dwp.dataworks.egress.services.impl

import com.nhaarman.mockitokotlin2.*
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.shouldBe
import software.amazon.awssdk.core.ResponseBytes
import software.amazon.awssdk.core.async.AsyncRequestBody
import software.amazon.awssdk.core.async.AsyncResponseTransformer
import software.amazon.awssdk.services.s3.S3AsyncClient
import software.amazon.awssdk.services.s3.model.*
import software.amazon.awssdk.services.ssm.SsmClient
import software.amazon.awssdk.services.ssm.model.GetParameterRequest
import software.amazon.awssdk.services.ssm.model.GetParameterResponse
import software.amazon.awssdk.services.ssm.model.Parameter
import software.amazon.awssdk.services.ssm.model.ParameterType
import uk.gov.dwp.dataworks.egress.domain.DataKeyResult
import uk.gov.dwp.dataworks.egress.domain.EgressSpecification
import uk.gov.dwp.dataworks.egress.domain.EncryptionResult
import uk.gov.dwp.dataworks.egress.services.CipherService
import uk.gov.dwp.dataworks.egress.services.CompressionService
import uk.gov.dwp.dataworks.egress.services.DataKeyService
import java.io.File
import java.text.DecimalFormat
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.CompletableFuture

class ManifestFileServiceImplTest: StringSpec() {

    init {
            "Export manifest file as plain text if no manifestFileEncryption option provided" {
                val (asyncS3Client, assumedRoleS3Client, manifestFileService) = serviceAndItsClients()
                manifestFileService.egressManifestFile(egressSpecification(manifestFileName=MANIFEST_FILE_NAME))
                verifyInteractions(assumedRoleS3Client, asyncS3Client, "$DESTINATION_PREFIX/$MANIFEST_FILE_NAME.gz")
            }

            "Export encrypted manifest file when manifestFileEncryption option 'encrypted' provided" {
                val (asyncS3Client, assumedRoleS3Client, manifestFileService) = serviceAndItsClients()
                manifestFileService.egressManifestFile(egressSpecification(manifestFileName=MANIFEST_FILE_NAME, manifestFileEncryption="encrypted"))
                verifyInteractions(assumedRoleS3Client, asyncS3Client, "$DESTINATION_PREFIX/$MANIFEST_FILE_NAME.gz.enc")
            }

            "Export encrypted manifest file with re-wrapped data key when 're-wrapped' is set as manifestFileEncryption option" {
                val (asyncS3Client, assumedRoleS3Client, manifestFileService) = serviceAndItsClients()
                manifestFileService.egressManifestFile(
                    egressSpecification(manifestFileName=MANIFEST_FILE_NAME,
                                        manifestFileEncryption="re-wrapped", roleArn = ROLE_ARN))
                verifyInteractions(assumedRoleS3Client, asyncS3Client, "$DESTINATION_PREFIX/$MANIFEST_FILE_NAME.gz.enc", ROLE_ARN)

            }

            "Export encrypted manifest file with re-wrapped data key when 'rewrapped' is set as manifestFileEncryption option" {
                val (asyncS3Client, assumedRoleS3Client, manifestFileService) = serviceAndItsClients()
                manifestFileService.egressManifestFile(
                    egressSpecification(manifestFileName=MANIFEST_FILE_NAME,
                        manifestFileEncryption="re-wrapped", roleArn = ROLE_ARN))
                verifyInteractions(assumedRoleS3Client, asyncS3Client, "$DESTINATION_PREFIX/$MANIFEST_FILE_NAME.gz.enc", ROLE_ARN)

            }

            "Do not export manifest file if not asked" {
                val (asyncS3Client, assumedRoleS3Client, manifestFileService) = serviceAndItsClients()
                manifestFileService.egressManifestFile(egressSpecification())
                verifyZeroInteractions(asyncS3Client)
                verifyZeroInteractions(assumedRoleS3Client)
            }

            "Export manifest file using assumed role if asked" {
                val (asyncS3Client, assumedRoleS3Client, manifestFileService) = serviceAndItsClients()
                manifestFileService.egressManifestFile(egressSpecification(manifestFileName=MANIFEST_FILE_NAME, roleArn = ROLE_ARN))
                verifyInteractions(assumedRoleS3Client, asyncS3Client, "$DESTINATION_PREFIX/$MANIFEST_FILE_NAME.gz", ROLE_ARN)
            }

            "Do not assume role when role_arn is empty in specifications" {
                val (asyncS3Client, assumedRoleS3Client, manifestFileService) = serviceAndItsClients()
                manifestFileService.egressManifestFile(egressSpecification(manifestFileName=MANIFEST_FILE_NAME, roleArn = ""))
                verifyInteractions(assumedRoleS3Client, asyncS3Client, "$DESTINATION_PREFIX/$MANIFEST_FILE_NAME.gz", "")
            }

    }

    private fun serviceAndItsClients(): Triple<S3AsyncClient, S3AsyncClient, ManifestFileServiceImpl> {
        val asyncS3Client = s3AsyncClient()
        val assumedRoleS3Client = s3AsyncClient()

        val dataKeyResult = DataKeyResult("keyId", "plainTextKey", "cipher")
        val dataKeyService = mock<DataKeyService> {
            on { batchDataKey() } doReturn dataKeyResult
        }

        val cipherService = mock<CipherService> {
            on { decrypt(any(), any(), any()) } doReturn getManifestFileContents().toByteArray()
            on { encrypt(any(), any()) } doReturn EncryptionResult("123", getManifestFileContents().toByteArray())
        }
        val ssmClient = mock<SsmClient>()
        val assumedRoleSsmClient = mock<SsmClient>{
            on {
                getParameter(GetParameterRequest.builder().name(SSM_PARAM_NAME).build())
            } doReturn GetParameterResponse.builder().parameter(SSM_MOCK_PARAM).build()
        }
        val assumedRoleSsmClientProvider: suspend (String) -> SsmClient = { assumedRoleSsmClient }
        val assumedRoleS3ClientProvider: suspend (String) -> S3AsyncClient = { assumedRoleS3Client }
        val compressionService = mock<CompressionService>{
            on { compress(any(), any())} doReturn getManifestFileContents().toByteArray()
        }
        val manifestFileService = ManifestFileServiceImpl(asyncS3Client, dataKeyService, cipherService, compressionService, ssmClient,
            assumedRoleSsmClientProvider, assumedRoleS3ClientProvider)

        return Triple(asyncS3Client, assumedRoleS3Client, manifestFileService)
    }

    private fun s3AsyncClient(): S3AsyncClient {
        val listObjectsResponse = with(ListObjectsV2Response.builder()) {
            val objects = objectsSummaries()
            contents(objects)
            build()
        }

        val objectsWithContents = List(100) { index ->
            val resp = with(GetObjectResponse.builder()) {
                metadata(
                    mapOf(
                        ENCRYPTING_KEY_ID_METADATA_KEY to ENCRYPTING_KEY_ID_METADATA_VALUE,
                        INITIALISATION_VECTOR_METADATA_KEY to INITIALISATION_VECTOR_METADATA_VALUE,
                        CIPHERTEXT_METADATA_KEY to CIPHERTEXT_METADATA_VALUE,
                    )
                )
                build()
            }
            ResponseBytes.fromByteArray(resp, "OBJECT_BODY_$index".toByteArray())
        }.map { CompletableFuture.completedFuture(it) }


        val asyncS3Client = mock<S3AsyncClient> {
            on {
                listObjectsV2(any<ListObjectsV2Request>())
            } doReturn CompletableFuture.completedFuture(listObjectsResponse)

            on {
                getObject(
                    any<GetObjectRequest>(),
                    any<AsyncResponseTransformer<GetObjectResponse, ResponseBytes<GetObjectResponse>>>()
                )
            } doReturnConsecutively objectsWithContents

            on {
                putObject(any<PutObjectRequest>(), any<AsyncRequestBody>())
            } doReturn CompletableFuture.completedFuture(PutObjectResponse.builder().build())
        }


        return asyncS3Client
    }

    private fun verifyInteractions(assumedRoleS3Client: S3AsyncClient,
                                   asyncS3Client: S3AsyncClient,
                                   expectedKey: String,
                                   roleArn: String?=null) {

        argumentCaptor<ListObjectsV2Request> {
            verify(asyncS3Client, times(1)).listObjectsV2(any<ListObjectsV2Request>())        // When writing to destination bucket where role_arn is provided
        }

        argumentCaptor<PutObjectRequest> {
            val bodyCaptor = argumentCaptor<AsyncRequestBody>()
            if (roleArn.isNullOrEmpty())  verify(asyncS3Client, times(1)).putObject(capture(), bodyCaptor.capture())  else
            verify(assumedRoleS3Client, times(1)).putObject(capture(), bodyCaptor.capture())

            firstValue.run {
                bucket() shouldBe DESTINATION_BUCKET
                key() shouldBe expectedKey
            }

            bodyCaptor.firstValue.contentLength().run {
                isPresent.shouldBeTrue()
                get() shouldBe getManifestFileContents().length
            }
        }
    }

    private fun egressed(): List<String> = List(100) {
            DESTINATION_PREFIX+"/KEY_"+DecimalFormat("00").format(it).toString()+".gz "
    }

    private fun getManifestFileContents(): String{
        val objectSizesList = List(100) { OBJECT_SIZE }
        val manifestFileContents = egressed().zip(objectSizesList) { key, size -> "$key $size YYYYMMDD\n" }
            .toList()
            .joinToString(separator = "") { it }

        return manifestFileContents
    }


    private fun egressSpecification(manifestFileName: String? = null, manifestFileEncryption: String? = null, roleArn: String? = null): EgressSpecification =
        EgressSpecification(
            SOURCE_BUCKET,
            SOURCE_PREFIX,
            DESTINATION_BUCKET,
            DESTINATION_PREFIX,
            TRANSFER_TYPE,
            decrypt = false,
            rewrapDataKey = true,
            encryptingKeySsmParmName = SSM_PARAM_NAME,
            compress = false,
            compressionFormat = null,
            roleArn= roleArn,
            PIPELINE_NAME,
            RECIPIENT,
            timestampOutput = false,
            null,
            manifestFileName,
            manifestFileEncryption
        )

    private fun objectsSummaries(): List<S3Object> =
        List(100) { index ->
            with(S3Object.builder()) {
                key("KEY_"+DecimalFormat("00").format(index).toString()+".gz")
                size(OBJECT_SIZE)
                build()
            }
        }

    companion object {
        private const val OBJECT_SIZE = "ObjectSize".length.toLong()
        private const val TODAYS_YYYYMMDD_FORMATTED_DATE_PLACEHOLDER = "\$TODAYS_YYYYMMDD_FORMATTED_DATE"
        private const val SOURCE_BUCKET = "sourceBucket/"
        private const val SOURCE_PREFIX = "sourcePrefix"
        private const val DESTINATION_BUCKET = "destinationBucket"
        private const val DESTINATION_PREFIX = "destinationPrefix/"+ TODAYS_YYYYMMDD_FORMATTED_DATE_PLACEHOLDER
        private const val TRANSFER_TYPE = "S3"
        private const val ROLE_ARN = "roleArn"
        private const val PIPELINE_NAME = "pipelineName"
        private const val RECIPIENT = "recipient"
        private const val MANIFEST_FILE_NAME = "collection.a.b-manifest.csv"

        private const val ENCRYPTING_KEY_ID_METADATA_KEY = "datakeyencryptionkeyid"
        private const val INITIALISATION_VECTOR_METADATA_KEY = "iv"
        private const val CIPHERTEXT_METADATA_KEY = "ciphertext"

        private const val ENCRYPTING_KEY_ID_METADATA_VALUE = "KEY_ID"
        private const val INITIALISATION_VECTOR_METADATA_VALUE = "INITIALISATION_VECTOR"
        private const val CIPHERTEXT_METADATA_VALUE = "ENCRYPTED_KEY"

        private const val SSM_PARAM_NAME: String = "rtg_public"
        private const val SSM_MOCK_PARAM_VALUE: String = "{\n" +
                "  \"ValidFrom\": \"2021-07-14 14:35:30\",\n" +
                "  \"KeyId\": \"4f9fbf95-ee0e-4eab-b8e5-82d51eed57d1\",\n" +
                "  \"PublicKey\": \"MIICIjANBgkqhkiG9w0BAQEF==\",\n" +
                "  \"CustomerMasterKeySpec\": \"RSA_4096\",\n" +
                "  \"EncryptionAlgorithms\": [\n" +
                "    \"RSAES_OAEP_SHA_1\",\n" +
                "    \"RSAES_OAEP_SHA_256\"\n" +
                "  ]\n" +
                "}"
        private val SSM_MOCK_PARAM: Parameter = Parameter.builder()
            .name(SSM_PARAM_NAME)
            .type(ParameterType.STRING)
            .value(SSM_MOCK_PARAM_VALUE)
            .build()

    }
}
