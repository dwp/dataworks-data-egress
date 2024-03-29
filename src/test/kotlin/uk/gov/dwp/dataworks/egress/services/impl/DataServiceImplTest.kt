package uk.gov.dwp.dataworks.egress.services.impl

import com.amazonaws.services.s3.AmazonS3EncryptionV2
import com.amazonaws.services.s3.model.S3ObjectInputStream
import com.nhaarman.mockitokotlin2.*
import io.kotest.core.spec.style.WordSpec
import io.kotest.matchers.collections.shouldContainExactlyInAnyOrder
import io.kotest.matchers.types.shouldBeSameInstanceAs
import io.prometheus.client.Counter
import org.springframework.boot.test.mock.mockito.MockBean
import software.amazon.awssdk.core.ResponseBytes
import software.amazon.awssdk.core.ResponseInputStream
import software.amazon.awssdk.core.async.AsyncRequestBody
import software.amazon.awssdk.core.async.AsyncResponseTransformer
import software.amazon.awssdk.http.AbortableInputStream
import software.amazon.awssdk.services.s3.S3AsyncClient
import software.amazon.awssdk.services.s3.S3Client
import software.amazon.awssdk.services.s3.model.*
import software.amazon.awssdk.services.ssm.SsmClient
import software.amazon.awssdk.services.ssm.model.GetParameterRequest
import software.amazon.awssdk.services.ssm.model.GetParameterResponse
import software.amazon.awssdk.services.ssm.model.Parameter
import software.amazon.awssdk.services.ssm.model.ParameterType
import uk.gov.dwp.dataworks.egress.domain.EgressSpecification
import uk.gov.dwp.dataworks.egress.services.*
import java.io.ByteArrayInputStream
import java.io.File
import java.util.concurrent.CompletableFuture
import com.amazonaws.services.s3.model.S3Object as S3ObjectVersion1


class DataServiceImplTest : WordSpec() {

    @MockBean(name = "sentFilesSuccess")
    private var sentFilesSuccess: Counter = mock()

    @MockBean(name = "sentFilesFailure")
    private var sentFilesFailure: Counter = mock()

    init {
        "dataService" should {
            "decrypt, send control file" {
                val objects = objectsSummaries()
                val objectsWithContents = objectsWithContents()
                val s3AsyncClient = s3AsyncClient(objects, objectsWithContents)
                val objectsWithMetadata = objectsWithMetadata()

                val s3Client = mock<S3Client> {
                    on { getObject(any<GetObjectRequest>()) } doReturnConsecutively objectsWithMetadata
                }
                val ssmClient = mock<SsmClient>()

                val decryptedS3Object = mock<S3ObjectVersion1> {
                    on { objectContent } doReturn S3ObjectInputStream(
                        ByteArrayInputStream("OBJECT_CONTENT".toByteArray()),
                        null
                    )
                }
                val decryptingS3Client = mock<AmazonS3EncryptionV2> {
                    on { getObject(any()) } doReturn decryptedS3Object
                }

                val assumedRoleS3Client = mock<S3AsyncClient>()
                val assumedRoleSsmClient = mock<SsmClient>()
                val controlFileService = mock<ControlFileService>()
                val manifestFileService = mock<ManifestFileService>()
                val assumedRoleS3ClientProvider: suspend (String) -> S3AsyncClient = { assumedRoleS3Client }
                val assumedRoleSsmClientProvider: suspend (String) -> SsmClient = { assumedRoleSsmClient }
                val dataKeyService = mock<DataKeyService> {
                    on { decryptKey(any(), any()) } doReturn "DECRYPTED_KEY"
                }
                val cipherService = mock<CipherService> {
                    on { decrypt(any(), any(), any()) } doReturn "DECRYPTED_CONTENTS".toByteArray()
                }
                val compressionService = mock<CompressionService>()

                reset(sentFilesSuccess)
                reset(sentFilesFailure)

                val sentFilesSuccessChild = mock<Counter.Child>()
                given(sentFilesSuccess.labels(any(), any(), any(), any(), any())).willReturn(sentFilesSuccessChild)


                val dataService = DataServiceImpl(
                    s3AsyncClient,
                    s3Client,
                    ssmClient,
                    decryptingS3Client,
                    assumedRoleS3ClientProvider,
                    assumedRoleSsmClientProvider,
                    controlFileService,
                    manifestFileService,
                    dataKeyService,
                    cipherService,
                    compressionService,
                    sentFilesSuccess,
                    sentFilesFailure)

                val specification = EgressSpecification(
                    SOURCE_BUCKET, SOURCE_PREFIX,
                    DESTINATION_BUCKET, DESTINATION_PREFIX, S3_TRANSFER_TYPE,
                    decrypt = true, rewrapDataKey=false, encryptingKeySsmParmName="",
                    compress = false, compressionFormat = null, roleArn = null,
                    pipelineName = PIPELINE_NAME, recipient = RECIPIENT, controlFilePrefix = CONTROL_FILE_PREFIX)

                dataService.egressObjects(specification)
                verify(s3Client, times(100)).getObject(any<GetObjectRequest>())
                verifyNoMoreInteractions(s3Client)

                verify(s3AsyncClient, times(1)).listObjectsV2(any<ListObjectsV2Request>())
                verify(s3AsyncClient, times(67)).getObject(
                    any<GetObjectRequest>(),
                    any<AsyncResponseTransformer<GetObjectResponse, ResponseBytes<GetObjectResponse>>>()
                )

                verify(s3AsyncClient, times(100)).putObject(any<PutObjectRequest>(), any<AsyncRequestBody>())
                verifyNoMoreInteractions(s3AsyncClient)
                verify(dataKeyService, times(34)).decryptKey(any(), any())
                verifyNoMoreInteractions(dataKeyService)

                verify(cipherService, times(34)).decrypt(any(), any(), any())
                verifyNoMoreInteractions(cipherService)

                verify(decryptingS3Client, times(33)).getObject(any())
                verifyNoMoreInteractions(decryptingS3Client)
                verifyZeroInteractions(assumedRoleS3Client)
                verifyZeroInteractions(compressionService)

                verify(sentFilesSuccessChild, times(100)).inc()
                verifyZeroInteractions(sentFilesFailure)

                val specificationCaptor = argumentCaptor<EgressSpecification>()
                argumentCaptor<List<String>> {
                    verify(controlFileService, times(1)).egressControlFile(capture(), specificationCaptor.capture())
                    firstValue shouldContainExactlyInAnyOrder objectsSummaries().map(S3Object::key)
                        .map { "$DESTINATION_PREFIX/$it" }
                    specificationCaptor.firstValue shouldBeSameInstanceAs specification
                }

                verifyNoMoreInteractions(controlFileService)
           }


            "assume role and re-wrap data keys" {
                val objects = objectsSummaries()
               val listObjectsResponse = with(ListObjectsV2Response.builder()) {
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

                val s3AsyncClient = mock<S3AsyncClient> {
                    on {
                        listObjectsV2(any<ListObjectsV2Request>())
                    } doReturn CompletableFuture.completedFuture(listObjectsResponse)

                    on {
                        getObject(
                            any<GetObjectRequest>(),
                            any<AsyncResponseTransformer<GetObjectResponse, ResponseBytes<GetObjectResponse>>>()
                        )
                    } doReturnConsecutively objectsWithContents
                }

                val objectsWithMetadata = List(100) {
                    with(GetObjectResponse.builder()) {
                        metadata(mapOf(ENCRYPTING_KEY_ID_METADATA_KEY to ENCRYPTING_KEY_ID_METADATA_VALUE,
                            INITIALISATION_VECTOR_METADATA_KEY to INITIALISATION_VECTOR_METADATA_VALUE,
                            CIPHERTEXT_METADATA_KEY to CIPHERTEXT_METADATA_VALUE,
                            DATA_PRODUCT to "product",
                            DATA_PRODUCT_TYPE to "productType"))
                        build()
                    }
                }.map {
                    ResponseInputStream(it, AbortableInputStream.create(ByteArrayInputStream("CONTENTS".toByteArray())))
                }

                val s3Client = mock<S3Client> {
                    on { getObject(any<GetObjectRequest>()) } doReturnConsecutively objectsWithMetadata
                }

                val ssmClient = mock<SsmClient> ()
                val controlFileService = mock<ControlFileService>()
                val manifestFileService = mock<ManifestFileService>()

                val decryptingS3Client = mock<AmazonS3EncryptionV2>()
                val assumedRoleS3Client = mock<S3AsyncClient> {
                    on {
                        putObject(any<PutObjectRequest>(), any<AsyncRequestBody>())
                    } doReturn CompletableFuture.completedFuture(PutObjectResponse.builder().build())
                }
                val assumedRoleSsmClient = mock<SsmClient> {
                    on {
                        getParameter(GetParameterRequest.builder().name(SSM_PARAM_NAME).build())
                    } doReturn GetParameterResponse.builder().parameter(SSM_MOCK_PARAM).build()
                }
                val assumedRoleS3ClientProvider: suspend (String) -> S3AsyncClient = { assumedRoleS3Client }
                val assumedRoleSsmClientProvider: suspend (String) -> SsmClient = { assumedRoleSsmClient }
                val dataKeyService = mock<DataKeyService> {
                    on { decryptKey(any(), any()) } doReturn "DECRYPTED_KEY"
                }
                val cipherService = mock<CipherService> {
                    on { decrypt(any(), any(), any()) } doReturn "DECRYPTED_CONTENTS".toByteArray()
                    on { rsaEncrypt(any(), any()) } doReturn "RSA_ENCRYPTED"
                }

                val compressionService = mock<CompressionService> {
                    on { compress(any(), any()) } doReturn "COMPRESSED_CONTENTS".toByteArray()
                }
                reset(sentFilesSuccess)
                reset(sentFilesFailure)
                val sentFilesSuccessChild = mock<Counter.Child>()
                given(sentFilesSuccess.labels(any(), any(), any(), any(), any())).willReturn(sentFilesSuccessChild)
                val dataService = DataServiceImpl(
                    s3AsyncClient,
                    s3Client,
                    ssmClient,
                    decryptingS3Client,
                    assumedRoleS3ClientProvider,
                    assumedRoleSsmClientProvider,
                    controlFileService,
                    manifestFileService,
                    dataKeyService,
                    cipherService,
                    compressionService,
                    sentFilesSuccess,
                    sentFilesFailure)

                val specification = EgressSpecification(
                    SOURCE_BUCKET, SOURCE_PREFIX,
                    DESTINATION_BUCKET, DESTINATION_PREFIX, S3_TRANSFER_TYPE,
                    decrypt = false, rewrapDataKey=true, encryptingKeySsmParmName= SSM_PARAM_NAME,
                    compress = false, compressionFormat = "gz", roleArn = "ROLE_ARN",
                    pipelineName = PIPELINE_NAME, recipient = RECIPIENT
                )
                dataService.egressObjects(specification)
                verify(s3Client, times(100)).getObject(any<GetObjectRequest>())
                verifyNoMoreInteractions(s3Client)

                verify(s3AsyncClient, times(1)).listObjectsV2(any<ListObjectsV2Request>())
                verify(s3AsyncClient, times(100)).getObject(
                    any<GetObjectRequest>(),
                    any<AsyncResponseTransformer<GetObjectResponse, ResponseBytes<GetObjectResponse>>>()
                )
                verify(assumedRoleSsmClient, times(100)).getParameter(any<GetParameterRequest>())
                verifyNoMoreInteractions(s3AsyncClient)
                verify(dataKeyService, times(100)).decryptKey(any(), any())
                verify(cipherService, times(100)).rsaEncrypt(any(), any())

                verifyNoMoreInteractions(dataKeyService)
                verifyNoMoreInteractions(cipherService)
                verifyZeroInteractions(decryptingS3Client)
                verify(assumedRoleS3Client, times(100)).putObject(any<PutObjectRequest>(), any<AsyncRequestBody>())
                verifyNoMoreInteractions(assumedRoleS3Client)
                verifyNoMoreInteractions(assumedRoleSsmClient)
                verifyZeroInteractions(compressionService)

                verify(sentFilesSuccessChild, times(100)).inc()
                verifyZeroInteractions(sentFilesFailure)
                verifyZeroInteractions(controlFileService)

                reset(sentFilesSuccess)
                reset(sentFilesFailure)
            }

            "assume role, not decrypt, compress" {
                val objects = objectsSummaries()

                val listObjectsResponse = with(ListObjectsV2Response.builder()) {
                    contents(objects)
                    build()
                }

                val objectsWithContents = List(100) { index ->
                    val resp = with(GetObjectResponse.builder()) {
                        metadata(
                            mapOf(
                                ENCRYPTING_KEY_ID_METADATA_KEY to ENCRYPTING_KEY_ID_METADATA_VALUE,
                                INITIALISATION_VECTOR_METADATA_KEY to INITIALISATION_VECTOR_METADATA_VALUE,
                                CIPHERTEXT_METADATA_KEY to CIPHERTEXT_METADATA_VALUE
                            )
                        )
                        build()
                    }
                    ResponseBytes.fromByteArray(resp, "OBJECT_BODY_$index".toByteArray())
                }.map { CompletableFuture.completedFuture(it) }

                val s3AsyncClient = mock<S3AsyncClient> {
                    on {
                        listObjectsV2(any<ListObjectsV2Request>())
                    } doReturn CompletableFuture.completedFuture(listObjectsResponse)

                    on {
                        getObject(
                            any<GetObjectRequest>(),
                            any<AsyncResponseTransformer<GetObjectResponse, ResponseBytes<GetObjectResponse>>>()
                        )
                    } doReturnConsecutively objectsWithContents
                }

                val objectsWithMetadata = List(100) {
                    with(GetObjectResponse.builder()) {
                        metadata(mapOf())
                        build()
                    }
                }.map {
                    ResponseInputStream(it, AbortableInputStream.create(ByteArrayInputStream("CONTENTS".toByteArray())))
                }

                val s3Client = mock<S3Client> {
                    on { getObject(any<GetObjectRequest>()) } doReturnConsecutively objectsWithMetadata
                }

                val ssmClient = mock<SsmClient> ()
                val decryptingS3Client = mock<AmazonS3EncryptionV2>()
                val assumedRoleS3Client = mock<S3AsyncClient> {
                    on {
                        putObject(any<PutObjectRequest>(), any<AsyncRequestBody>())
                    } doReturn CompletableFuture.completedFuture(PutObjectResponse.builder().build())
                }
                val assumedRoleSsmClient = mock<SsmClient>()
                val assumedRoleS3ClientProvider: suspend (String) -> S3AsyncClient = { assumedRoleS3Client }
                val assumedRoleSsmClientProvider: suspend (String) -> SsmClient = { assumedRoleSsmClient }
                val dataKeyService = mock<DataKeyService>()
                val cipherService = mock<CipherService>()
                val controlFileService = mock<ControlFileService>()
                val manifestFileService = mock<ManifestFileService>()

                val compressionService = mock<CompressionService> {
                    on { compress(any(), any()) } doReturn "COMPRESSED_CONTENTS".toByteArray()
                }
                reset(sentFilesSuccess)
                reset(sentFilesFailure)
                val sentFilesSuccessChild = mock<Counter.Child>()
                given(sentFilesSuccess.labels(any(), any(), any(), any(), any())).willReturn(sentFilesSuccessChild)
                val dataService = DataServiceImpl(
                    s3AsyncClient,
                    s3Client,
                    ssmClient,
                    decryptingS3Client,
                    assumedRoleS3ClientProvider,
                    assumedRoleSsmClientProvider,
                    controlFileService,
                    manifestFileService,
                    dataKeyService,
                    cipherService,
                    compressionService,
                    sentFilesSuccess,
                    sentFilesFailure
                )


                val specification = EgressSpecification(
                    SOURCE_BUCKET, SOURCE_PREFIX,
                    DESTINATION_BUCKET, DESTINATION_PREFIX, S3_TRANSFER_TYPE,
                    decrypt = false, rewrapDataKey=false, encryptingKeySsmParmName="",
                    compress = true, compressionFormat = "gz", roleArn = "ROLE_ARN",
                    pipelineName = PIPELINE_NAME, recipient = RECIPIENT
                )
                dataService.egressObjects(specification)
                verify(s3Client, times(100)).getObject(any<GetObjectRequest>())
                verifyNoMoreInteractions(s3Client)

                verify(s3AsyncClient, times(1)).listObjectsV2(any<ListObjectsV2Request>())
                verify(s3AsyncClient, times(100)).getObject(
                    any<GetObjectRequest>(),
                    any<AsyncResponseTransformer<GetObjectResponse, ResponseBytes<GetObjectResponse>>>()
                )

                verifyNoMoreInteractions(s3AsyncClient)
                verifyZeroInteractions(dataKeyService)
                verifyZeroInteractions(cipherService)
                verifyZeroInteractions(decryptingS3Client)
                verify(assumedRoleS3Client, times(100)).putObject(any<PutObjectRequest>(), any<AsyncRequestBody>())
                verifyNoMoreInteractions(assumedRoleS3Client)
                verify(compressionService, times(100)).compress(any(), any())
                verifyNoMoreInteractions(compressionService)

                verify(sentFilesSuccessChild, times(100)).inc()
                verifyZeroInteractions(sentFilesFailure)
                verifyZeroInteractions(controlFileService)

                reset(sentFilesSuccess)
                reset(sentFilesFailure)
            }

            "write to file not s3" {
                val objects = objectsSummaries()
                val objectsWithContents = objectsWithContents()
                val s3AsyncClient = s3AsyncClient(objects, objectsWithContents)
                val objectsWithMetadata = objectsWithMetadata()

                val s3Client = mock<S3Client> {
                    on { getObject(any<GetObjectRequest>()) } doReturnConsecutively objectsWithMetadata
                }
                val ssmClient = mock<SsmClient>()

                val decryptedS3Object = mock<S3ObjectVersion1> {
                    on { objectContent } doReturn S3ObjectInputStream(
                        ByteArrayInputStream("OBJECT_CONTENT".toByteArray()),
                        null
                    )
                }
                val decryptingS3Client = mock<AmazonS3EncryptionV2> {
                    on { getObject(any()) } doReturn decryptedS3Object
                }

                val assumedRoleS3Client = mock<S3AsyncClient>()
                val assumedRoleSsmClient = mock<SsmClient>()
                val assumedRoleS3ClientProvider: suspend (String) -> S3AsyncClient = { assumedRoleS3Client }
                val assumedRoleSsmClientProvider: suspend (String) -> SsmClient = { assumedRoleSsmClient }
                val dataKeyService = mock<DataKeyService> {
                    on { decryptKey(any(), any()) } doReturn "DECRYPTED_KEY"
                }
                val cipherService = mock<CipherService> {
                    on { decrypt(any(), any(), any()) } doReturn "DECRYPTED_CONTENTS".toByteArray()
                }
                val compressionService = mock<CompressionService>()

                reset(sentFilesSuccess)
                reset(sentFilesFailure)
                val sentFilesSuccessChild = mock<Counter.Child>()
                given(sentFilesSuccess.labels(any(), any(), any(), any(), any())).willReturn(sentFilesSuccessChild)
                val controlFileService = mock<ControlFileService>()
                val manifestFileService = mock<ManifestFileService>()

                val dataService = DataServiceImpl(
                    s3AsyncClient,
                    s3Client,
                    ssmClient,
                    decryptingS3Client,
                    assumedRoleS3ClientProvider,
                    assumedRoleSsmClientProvider,
                    controlFileService,
                    manifestFileService,
                    dataKeyService,
                    cipherService,
                    compressionService,
                    sentFilesSuccess,
                    sentFilesFailure
                )
                val currentDirectory = System.getProperty("user.dir")
                val testFolderLocation = "/$currentDirectory/sftTest"
                val specification = EgressSpecification(
                    SOURCE_BUCKET, SOURCE_PREFIX,
                    DESTINATION_BUCKET, testFolderLocation, SFT_TRANSFER_TYPE,
                    decrypt = true, rewrapDataKey=false, encryptingKeySsmParmName= "",
                    compress = false, compressionFormat = null, roleArn = null,
                    pipelineName = PIPELINE_NAME, recipient = RECIPIENT
                )

                dataService.egressObjects(specification)
                verify(s3Client, times(100)).getObject(any<GetObjectRequest>())
                verifyNoMoreInteractions(s3Client)

                verify(s3AsyncClient, times(1)).listObjectsV2(any<ListObjectsV2Request>())
                verify(s3AsyncClient, times(67)).getObject(
                    any<GetObjectRequest>(),
                    any<AsyncResponseTransformer<GetObjectResponse, ResponseBytes<GetObjectResponse>>>()
                )

                verifyNoMoreInteractions(s3AsyncClient)
                verify(dataKeyService, times(34)).decryptKey(any(), any())
                verifyNoMoreInteractions(dataKeyService)

                verify(cipherService, times(34)).decrypt(any(), any(), any())
                verifyNoMoreInteractions(cipherService)

                verify(decryptingS3Client, times(33)).getObject(any())
                verifyNoMoreInteractions(decryptingS3Client)
                verifyZeroInteractions(assumedRoleS3Client)
                verifyZeroInteractions(compressionService)


                val file = File(testFolderLocation)
                val filesCount = getFilesCount(file)
                assert(filesCount == 100)
                file.deleteRecursively()

                verify(sentFilesSuccessChild, times(100)).inc()
                verifyZeroInteractions(sentFilesFailure)
                verifyZeroInteractions(controlFileService)

                reset(sentFilesSuccess)
                reset(sentFilesFailure)
            }

            "gracefully handle unsupported transfer type" {
                val objects = objectsSummaries()
                val objectsWithContents = objectsWithContents()
                val s3AsyncClient = s3AsyncClient(objects, objectsWithContents)
                val objectsWithMetadata = objectsWithMetadata()

                val s3Client = mock<S3Client> {
                    on { getObject(any<GetObjectRequest>()) } doReturnConsecutively objectsWithMetadata
                }
                val ssmClient = mock<SsmClient> ()

                val decryptedS3Object = mock<S3ObjectVersion1> {
                    on { objectContent } doReturn S3ObjectInputStream(
                        ByteArrayInputStream("OBJECT_CONTENT".toByteArray()),
                        null
                    )
                }
                val decryptingS3Client = mock<AmazonS3EncryptionV2> {
                    on { getObject(any()) } doReturn decryptedS3Object
                }

                val assumedRoleS3Client = mock<S3AsyncClient>()
                val assumedRoleSsmClient = mock<SsmClient>()
                val assumedRoleS3ClientProvider: suspend (String) -> S3AsyncClient = { assumedRoleS3Client }
                val assumedRoleSsmClientProvider: suspend (String) -> SsmClient = { assumedRoleSsmClient }
                val dataKeyService = mock<DataKeyService> {
                    on { decryptKey(any(), any()) } doReturn "DECRYPTED_KEY"
                }
                val cipherService = mock<CipherService> {
                    on { decrypt(any(), any(), any()) } doReturn "DECRYPTED_CONTENTS".toByteArray()
                }
                val compressionService = mock<CompressionService>()
                val controlFileService = mock<ControlFileService>()
                val manifestFileService = mock<ManifestFileService>()

                val dataService = DataServiceImpl(
                    s3AsyncClient,
                    s3Client,
                    ssmClient,
                    decryptingS3Client,
                    assumedRoleS3ClientProvider,
                    assumedRoleSsmClientProvider,
                    controlFileService,
                    manifestFileService,
                    dataKeyService,
                    cipherService,
                    compressionService,
                    sentFilesSuccess,
                    sentFilesFailure)

                val currentDirectory = System.getProperty("user.dir")
                val testFolderLocation = "/$currentDirectory/sftTest"
                val specification = EgressSpecification(
                    SOURCE_BUCKET, SOURCE_PREFIX,
                    DESTINATION_BUCKET, testFolderLocation, "3FT",
                    decrypt = true, rewrapDataKey=false, encryptingKeySsmParmName="",
                    compress = false, compressionFormat = null, roleArn = null,
                    pipelineName = PIPELINE_NAME, recipient = RECIPIENT
                )

                dataService.egressObjects(specification)
                verify(s3Client, times(100)).getObject(any<GetObjectRequest>())
                verifyNoMoreInteractions(s3Client)
                verify(s3AsyncClient, times(1)).listObjectsV2(any<ListObjectsV2Request>())
                verify(s3AsyncClient, times(67)).getObject(
                    any<GetObjectRequest>(),
                    any<AsyncResponseTransformer<GetObjectResponse, ResponseBytes<GetObjectResponse>>>()
                )
                verifyNoMoreInteractions(s3AsyncClient)
                verify(dataKeyService, times(34)).decryptKey(any(), any())
                verifyNoMoreInteractions(dataKeyService)
                verify(cipherService, times(34)).decrypt(any(), any(), any())
                verifyNoMoreInteractions(cipherService)
                verify(decryptingS3Client, times(33)).getObject(any())
                verifyNoMoreInteractions(decryptingS3Client)
                verifyZeroInteractions(assumedRoleS3Client)
                verifyZeroInteractions(compressionService)
                verifyZeroInteractions(controlFileService)
            }

        }
    }

    private fun getFilesCount(file: File): Int {
        val files = file.listFiles()
        var count = 0
        for (f in files) if (f.isDirectory) count += getFilesCount(f) else count++
        return count
    }

    private fun s3AsyncClient(
        objects: List<S3Object>,
        objectsWithContents: List<CompletableFuture<ResponseBytes<GetObjectResponse>>>
    ): S3AsyncClient =
        mock {
            on {
                listObjectsV2(any<ListObjectsV2Request>())
            } doReturn CompletableFuture.completedFuture(with(ListObjectsV2Response.builder()) {
                contents(objects)
                build()
            })

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

    private fun objectsWithMetadata(): List<ResponseInputStream<GetObjectResponse>> =
        List(100) { index ->
            with(GetObjectResponse.builder()) {
                metadata(
                    when (index % 3) {
                        0 -> {
                            mapOf(
                                ENCRYPTING_KEY_ID_METADATA_KEY to ENCRYPTING_KEY_ID_METADATA_VALUE,
                                INITIALISATION_VECTOR_METADATA_KEY to INITIALISATION_VECTOR_METADATA_VALUE,
                                CIPHERTEXT_METADATA_KEY to CIPHERTEXT_METADATA_VALUE
                            )
                        }
                        1 -> {
                            mapOf(MATERIALS_DESCRIPTION_METADATA_KEY to "MATERIALS_DESCRIPTION")
                        }
                        else -> {
                            mapOf()
                        }
                    }
                )
                build()
            }
        }.map {
            ResponseInputStream(it, AbortableInputStream.create(ByteArrayInputStream("CONTENTS".toByteArray())))
        }

    private fun objectsSummaries(): List<S3Object> =
        List(100) { index ->
            with(S3Object.builder()) {
                key("KEY_$index")
                build()
            }
        }

    private fun objectsWithContents(): List<CompletableFuture<ResponseBytes<GetObjectResponse>>> =
        List(100) { index ->
            val resp = with(GetObjectResponse.builder()) {
                metadata(
                    when (index % 2) {
                        0 -> {
                            mapOf(
                                ENCRYPTING_KEY_ID_METADATA_KEY to ENCRYPTING_KEY_ID_METADATA_VALUE,
                                INITIALISATION_VECTOR_METADATA_KEY to INITIALISATION_VECTOR_METADATA_VALUE,
                                CIPHERTEXT_METADATA_KEY to CIPHERTEXT_METADATA_VALUE
                            )
                        }
                        1 -> {
                            mapOf(MATERIALS_DESCRIPTION_METADATA_KEY to "MATERIALS_DESCRIPTION")
                        }
                        else -> {
                            mapOf()
                        }
                    }
                )
                build()
            }
            ResponseBytes.fromByteArray(resp, "OBJECT_BODY_$index".toByteArray())
        }.map { CompletableFuture.completedFuture(it) }

    companion object {
        private const val SOURCE_BUCKET = "SOURCE_BUCKET"
        private const val SOURCE_PREFIX = "SOURCE_PREFIX"
        private const val DESTINATION_BUCKET = "DESTINATION_BUCKET"
        private const val DESTINATION_PREFIX = "DESTINATION_PREFIX"
        private const val S3_TRANSFER_TYPE = "S3"
        private const val SFT_TRANSFER_TYPE = "SFT"
        private const val PIPELINE_NAME = "PIPELINE_NAME"
        private const val RECIPIENT = "RECIPIENT"
        private const val CONTROL_FILE_PREFIX = "CONTROL_FILE_PREFIX"


        private const val ENCRYPTING_KEY_ID_METADATA_KEY = "datakeyencryptionkeyid"
        private const val INITIALISATION_VECTOR_METADATA_KEY = "iv"
        private const val CIPHERTEXT_METADATA_KEY = "ciphertext"
        private const val DATA_PRODUCT = "data_product"
        private const val DATA_PRODUCT_TYPE= "data_product_type"

        private const val MATERIALS_DESCRIPTION_METADATA_KEY = "x-amz-matdesc"
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
