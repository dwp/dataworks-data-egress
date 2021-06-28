package uk.gov.dwp.dataworks.egress.services.impl

import com.amazonaws.services.s3.AmazonS3EncryptionV2
import com.amazonaws.services.s3.model.S3ObjectInputStream
import com.nhaarman.mockitokotlin2.*
import io.kotest.core.spec.style.AnnotationSpec
import io.kotest.core.spec.style.WordSpec
import io.prometheus.client.Counter
import org.aspectj.lang.annotation.Before
import org.springframework.boot.test.mock.mockito.MockBean
import software.amazon.awssdk.core.ResponseBytes
import software.amazon.awssdk.core.ResponseInputStream
import software.amazon.awssdk.core.async.AsyncRequestBody
import software.amazon.awssdk.core.async.AsyncResponseTransformer
import software.amazon.awssdk.http.AbortableInputStream
import software.amazon.awssdk.services.s3.S3AsyncClient
import software.amazon.awssdk.services.s3.S3Client
import software.amazon.awssdk.services.s3.model.*
import uk.gov.dwp.dataworks.egress.domain.EgressSpecification
import uk.gov.dwp.dataworks.egress.services.CipherService
import uk.gov.dwp.dataworks.egress.services.CompressionService
import uk.gov.dwp.dataworks.egress.services.DataKeyService
import uk.gov.dwp.dataworks.egress.services.MetricsService
import java.io.ByteArrayInputStream
import java.io.File
import java.util.concurrent.CompletableFuture
import com.amazonaws.services.s3.model.S3Object as S3ObjectVersion1

import org.junit.jupiter.api.BeforeAll

class DataServiceImplTest : WordSpec() {

    @MockBean(name = "sentFilesSuccess")
    private var sentFilesSuccess: Counter = mock()

    @MockBean(name = "sentFilesFailure")
    private var sentFilesFailure: Counter = mock()

    init {
        "dataService" should {
            "decrypt" {
                val objects = objectsSummaries()
                val objectsWithContents = objectsWithContents()
                val s3AsyncClient = s3AsyncClient(objects, objectsWithContents)
                val objectsWithMetadata = objectsWithMetadata()

                val s3Client = mock<S3Client> {
                    on { getObject(any<GetObjectRequest>()) } doReturnConsecutively objectsWithMetadata
                }

                val decryptedS3Object = mock<S3ObjectVersion1> {
                    on { objectContent } doReturn S3ObjectInputStream(
                        ByteArrayInputStream("OBJECT_CONTENT".toByteArray()),
                        null
                    )
                }
                val decryptingS3Client = mock<AmazonS3EncryptionV2> {
                    on { getObject(any()) } doReturn decryptedS3Object
                }

                val assumedRoleClient = mock<S3AsyncClient>()
                val assumedRoleClientProvider: suspend (String) -> S3AsyncClient = { assumedRoleClient }
                val dataKeyService = mock<DataKeyService> {
                    on { decryptKey(any(), any()) } doReturn "DECRYPTED_KEY"
                }
                val cipherService = mock<CipherService> {
                    on { decrypt(any(), any(), any()) } doReturn "DECRYPTED_CONTENTS".toByteArray()
                }
                val compressionService = mock<CompressionService>()
                reset(sentFilesSuccess)
                reset(sentFilesFailure)


                val dataService = DataServiceImpl(
                    s3AsyncClient,
                    s3Client,
                    decryptingS3Client,
                    assumedRoleClientProvider,
                    dataKeyService,
                    cipherService,
                    compressionService,
                    sentFilesSuccess,
                    sentFilesFailure
                )


                val specification = EgressSpecification(
                    SOURCE_BUCKET, SOURCE_PREFIX,
                    DESTINATION_BUCKET, DESTINATION_PREFIX, S3_TRANSFER_TYPE,
                    decrypt = true, compress = false, null, null,
                    PIPELINE_NAME, RECIPIENT
                )

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
                verifyZeroInteractions(assumedRoleClient)
                verifyZeroInteractions(compressionService)

                verify(sentFilesSuccess, times(100)).inc()
                verifyZeroInteractions(sentFilesFailure)
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

                val decryptingS3Client = mock<AmazonS3EncryptionV2>()
                val assumedRoleClient = mock<S3AsyncClient> {
                    on {
                        putObject(any<PutObjectRequest>(), any<AsyncRequestBody>())
                    } doReturn CompletableFuture.completedFuture(PutObjectResponse.builder().build())
                }
                val assumedRoleClientProvider: suspend (String) -> S3AsyncClient = { assumedRoleClient }
                val dataKeyService = mock<DataKeyService>()
                val cipherService = mock<CipherService>()

                val compressionService = mock<CompressionService> {
                    on { compress(any(), any()) } doReturn "COMPRESSED_CONTENTS".toByteArray()
                }
                reset(sentFilesSuccess)
                reset(sentFilesFailure)
                val dataService = DataServiceImpl(
                    s3AsyncClient,
                    s3Client,
                    decryptingS3Client,
                    assumedRoleClientProvider,
                    dataKeyService,
                    cipherService,
                    compressionService,
                    sentFilesSuccess,
                    sentFilesFailure
                )


                val specification = EgressSpecification(
                    SOURCE_BUCKET, SOURCE_PREFIX,
                    DESTINATION_BUCKET, DESTINATION_PREFIX, S3_TRANSFER_TYPE,
                    decrypt = false, compress = true, "gz", "ROLE_ARN",
                    PIPELINE_NAME, RECIPIENT
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
                verify(assumedRoleClient, times(100)).putObject(any<PutObjectRequest>(), any<AsyncRequestBody>())
                verifyNoMoreInteractions(assumedRoleClient)
                verify(compressionService, times(100)).compress(any(), any())
                verifyNoMoreInteractions(compressionService)

                verify(sentFilesSuccess, times(100)).inc()
                verifyZeroInteractions(sentFilesFailure)

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

                val decryptedS3Object = mock<S3ObjectVersion1> {
                    on { objectContent } doReturn S3ObjectInputStream(
                        ByteArrayInputStream("OBJECT_CONTENT".toByteArray()),
                        null
                    )
                }
                val decryptingS3Client = mock<AmazonS3EncryptionV2> {
                    on { getObject(any()) } doReturn decryptedS3Object
                }

                val assumedRoleClient = mock<S3AsyncClient>()
                val assumedRoleClientProvider: suspend (String) -> S3AsyncClient = { assumedRoleClient }
                val dataKeyService = mock<DataKeyService> {
                    on { decryptKey(any(), any()) } doReturn "DECRYPTED_KEY"
                }
                val cipherService = mock<CipherService> {
                    on { decrypt(any(), any(), any()) } doReturn "DECRYPTED_CONTENTS".toByteArray()
                }
                val compressionService = mock<CompressionService>()

                reset(sentFilesSuccess)
                reset(sentFilesFailure)

                val dataService = DataServiceImpl(
                    s3AsyncClient,
                    s3Client,
                    decryptingS3Client,
                    assumedRoleClientProvider,
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
                    decrypt = true, compress = false, null, null,
                    PIPELINE_NAME, RECIPIENT
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
                verifyZeroInteractions(assumedRoleClient)
                verifyZeroInteractions(compressionService)


                val file = File(testFolderLocation)
                val filesCount = getFilesCount(file)
                assert(filesCount == 100)
                file.deleteRecursively()

                verify(sentFilesSuccess, times(100)).inc()
                verifyZeroInteractions(sentFilesFailure)

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

                val decryptedS3Object = mock<S3ObjectVersion1> {
                    on { objectContent } doReturn S3ObjectInputStream(
                        ByteArrayInputStream("OBJECT_CONTENT".toByteArray()),
                        null
                    )
                }
                val decryptingS3Client = mock<AmazonS3EncryptionV2> {
                    on { getObject(any()) } doReturn decryptedS3Object
                }

                val assumedRoleClient = mock<S3AsyncClient>()
                val assumedRoleClientProvider: suspend (String) -> S3AsyncClient = { assumedRoleClient }
                val dataKeyService = mock<DataKeyService> {
                    on { decryptKey(any(), any()) } doReturn "DECRYPTED_KEY"
                }
                val cipherService = mock<CipherService> {
                    on { decrypt(any(), any(), any()) } doReturn "DECRYPTED_CONTENTS".toByteArray()
                }
                val compressionService = mock<CompressionService>()

                val dataService = DataServiceImpl(
                    s3AsyncClient,
                    s3Client,
                    decryptingS3Client,
                    assumedRoleClientProvider,
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
                    DESTINATION_BUCKET, testFolderLocation, "3FT",
                    decrypt = true, compress = false, null, null,
                    PIPELINE_NAME, RECIPIENT
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
                verifyZeroInteractions(assumedRoleClient)
                verifyZeroInteractions(compressionService)
            }

            "send failure metrics if the files can't be written  " {
                val objects = objectsSummaries()
                val objectsWithContents = objectsWithContents()
                val s3AsyncClient = s3AsyncClient(objects, objectsWithContents)
                val objectsWithMetadata = objectsWithMetadata()

                val s3Client = mock<S3Client> {
                    on { getObject(any<GetObjectRequest>()) } doReturnConsecutively objectsWithMetadata
                }

                val decryptedS3Object = mock<S3ObjectVersion1> {
                    on { objectContent } doReturn S3ObjectInputStream(
                        ByteArrayInputStream("OBJECT_CONTENT".toByteArray()),
                        null
                    )
                }
                val decryptingS3Client = mock<AmazonS3EncryptionV2> {
                    on { getObject(any()) } doReturn decryptedS3Object
                }

                val assumedRoleClient = mock<S3AsyncClient>()
                val assumedRoleClientProvider: suspend (String) -> S3AsyncClient = { assumedRoleClient }
                val dataKeyService = mock<DataKeyService> {
                    on { decryptKey(any(), any()) } doReturn "DECRYPTED_KEY"
                }
                val cipherService = mock<CipherService> {
                    on { decrypt(any(), any(), any()) } doReturn "DECRYPTED_CONTENTS".toByteArray()
                }
                val compressionService = mock<CompressionService>()

                val dataService = DataServiceImpl(
                    s3AsyncClient,
                    s3Client,
                    decryptingS3Client,
                    assumedRoleClientProvider,
                    dataKeyService,
                    cipherService,
                    compressionService,
                    sentFilesSuccess,
                    sentFilesFailure
                )
                val specification = EgressSpecification(
                    SOURCE_BUCKET, SOURCE_PREFIX,
                    DESTINATION_BUCKET, "//failTest", "SFT",
                    decrypt = true, compress = false, null, null,
                    PIPELINE_NAME, RECIPIENT
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
                verifyZeroInteractions(assumedRoleClient)
                verifyZeroInteractions(compressionService)

                verify(sentFilesFailure, times(100)).inc()
                verifyZeroInteractions(sentFilesSuccess)
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


        private const val ENCRYPTING_KEY_ID_METADATA_KEY = "datakeyencryptionkeyid"
        private const val INITIALISATION_VECTOR_METADATA_KEY = "iv"
        private const val CIPHERTEXT_METADATA_KEY = "ciphertext"

        private const val MATERIALS_DESCRIPTION_METADATA_KEY = "x-amz-matdesc"
        private const val ENCRYPTING_KEY_ID_METADATA_VALUE = "KEY_ID"
        private const val INITIALISATION_VECTOR_METADATA_VALUE = "INITIALISATION_VECTOR"
        private const val CIPHERTEXT_METADATA_VALUE = "ENCRYPTED_KEY"
    }
}
