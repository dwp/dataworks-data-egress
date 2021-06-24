package uk.gov.dwp.dataworks.egress

import com.amazonaws.services.s3.AmazonS3EncryptionV2
import com.amazonaws.services.s3.model.ObjectMetadata
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.collections.shouldContainAll
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.ktor.client.*
import io.ktor.client.features.*
import io.ktor.client.features.get
import io.ktor.client.features.json.*
import io.ktor.client.request.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.future.await
import kotlinx.coroutines.time.withTimeout
import org.slf4j.LoggerFactory
import org.springframework.context.annotation.AnnotationConfigApplicationContext
import software.amazon.awssdk.core.ResponseBytes
import software.amazon.awssdk.core.async.AsyncRequestBody
import software.amazon.awssdk.core.async.AsyncResponseTransformer
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient
import software.amazon.awssdk.services.dynamodb.model.AttributeValue
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest
import software.amazon.awssdk.services.dynamodb.model.PutItemResponse
import software.amazon.awssdk.services.s3.S3AsyncClient
import software.amazon.awssdk.services.s3.model.GetObjectRequest
import software.amazon.awssdk.services.s3.model.GetObjectResponse
import software.amazon.awssdk.services.s3.model.NoSuchKeyException
import software.amazon.awssdk.services.s3.model.PutObjectRequest
import software.amazon.awssdk.services.sqs.SqsAsyncClient
import software.amazon.awssdk.services.sqs.model.SendMessageRequest
import uk.gov.dwp.dataworks.egress.services.CipherService
import uk.gov.dwp.dataworks.egress.services.DataKeyService
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import java.text.SimpleDateFormat
import java.time.Duration
import java.util.*
import java.util.zip.GZIPInputStream
import java.util.zip.Inflater
import kotlin.time.ExperimentalTime
import com.amazonaws.services.s3.model.PutObjectRequest as PutObjectRequestVersion1


@ExperimentalTime
class IntegrationTests: StringSpec() {


    init {

        "Should process client-side-encrypted encrypted files" {
            val identifier = "cse"
            val sourceContents = sourceContents(identifier)
            val inputStream = ByteArrayInputStream(sourceContents.toByteArray())
            val putRequest =
                PutObjectRequestVersion1(SOURCE_BUCKET, "$identifier/$identifier.csv", inputStream, ObjectMetadata())
            encryptingS3.putObject(putRequest)
            verifyEgress(sourceContents, identifier, false)
        }

        "Should decrypt htme encrypted files if requested" {
            val identifier = "htme"
            val sourceContents = sourceContents(identifier)
            val (encryptingKeyId, plaintextDataKey, ciphertextDataKey) = dataKeyService.batchDataKey()
            val (iv, encrypted) = cipherService.encrypt(plaintextDataKey, sourceContents.toByteArray())
            val putRequest = with(PutObjectRequest.builder()) {
                bucket(SOURCE_BUCKET)
                key("$identifier/$identifier.csv.enc")
                metadata(mapOf(ENCRYPTING_KEY_ID_METADATA_KEY to encryptingKeyId,
                    INITIALISATION_VECTOR_METADATA_KEY to iv,
                    CIPHERTEXT_METADATA_KEY to ciphertextDataKey))
                build()
            }
            s3.putObject(putRequest, AsyncRequestBody.fromBytes(encrypted)).await()
            verifyEgress(sourceContents, identifier, true)
        }

        "Should not decrypt htme encrypted files if not requested" {
            val identifier = "htme_put_encrypted"
            val sourceContents = sourceContents(identifier)
            val (encryptingKeyId, plaintext, ciphertext) = dataKeyService.batchDataKey()
            val (iv, encrypted) = cipherService.encrypt(plaintext, sourceContents.toByteArray())
            val putRequest = with(PutObjectRequest.builder()) {
                bucket(SOURCE_BUCKET)
                key("$identifier/$identifier.csv.enc")
                metadata(mapOf(ENCRYPTING_KEY_ID_METADATA_KEY to encryptingKeyId,
                    INITIALISATION_VECTOR_METADATA_KEY to iv,
                    CIPHERTEXT_METADATA_KEY to ciphertext))
                build()
            }
            s3.putObject(putRequest, AsyncRequestBody.fromBytes(encrypted)).await()
            insertEgressItem("$identifier/", "$identifier/", TRANSFER_TYPE, false)
            val message = messageBody("$identifier/$PIPELINE_SUCCESS_FLAG")
            val request = sendMessageRequest(message)
            sqs.sendMessage(request).await()
            withTimeout(Duration.ofSeconds(TEST_TIMEOUT)) {
                val metadata = egressedMetadata(DESTINATION_BUCKET, "$identifier/$identifier.csv.enc")
                val encryptingKeyIdFromMetadata = metadata[ENCRYPTING_KEY_ID_METADATA_KEY]
                val ivFromMetadata = metadata[INITIALISATION_VECTOR_METADATA_KEY]
                val ciphertextFromMetadata = metadata[CIPHERTEXT_METADATA_KEY]
                encryptingKeyIdFromMetadata.shouldNotBeNull()
                ivFromMetadata.shouldNotBeNull()
                ciphertextFromMetadata.shouldNotBeNull()
                encryptingKeyIdFromMetadata shouldBe encryptingKeyId
                ivFromMetadata shouldBe iv
                ciphertextFromMetadata shouldBe ciphertext
                val plaintextFromMetadata =
                    dataKeyService.decryptKey(encryptingKeyIdFromMetadata, ciphertextFromMetadata)
                plaintextFromMetadata shouldBe plaintext
                val targetContents = egressedContents(DESTINATION_BUCKET, "$identifier/$identifier.csv.enc")
                val decrypted = cipherService.decrypt(plaintextFromMetadata, ivFromMetadata, targetContents)
                String(decrypted) shouldBe sourceContents
            }
        }

        "Should process files with today's date in prefix" {
            val identifier = "today"
            val sourceContents = sourceContents(identifier)
            val putRequest = with(PutObjectRequest.builder()) {
                bucket(SOURCE_BUCKET)
                key("$identifier/${todaysDate()}/$identifier.csv")
                build()
            }
            s3.putObject(putRequest, AsyncRequestBody.fromString(sourceContents)).await()
            insertEgressItem("$identifier/\$TODAYS_DATE", "$identifier/\$TODAYS_DATE", TRANSFER_TYPE)
            val message = messageBody("$identifier/${todaysDate()}/$PIPELINE_SUCCESS_FLAG")
            val request = sendMessageRequest(message)
            sqs.sendMessage(request).await()

            withTimeout(Duration.ofSeconds(TEST_TIMEOUT)) {
                val targetContents = egressedContents(DESTINATION_BUCKET, "$identifier/${todaysDate()}/$identifier.csv")
                String(targetContents) shouldBe sourceContents
            }
        }

        "Should gz compress files if specified" {
            val identifier = "gz"
            val sourceContents = sourceContents(identifier)
            val putRequest = with(PutObjectRequest.builder()) {
                bucket(SOURCE_BUCKET)
                key("$identifier/$identifier.csv")
                build()
            }
            s3.putObject(putRequest, AsyncRequestBody.fromBytes(sourceContents.toByteArray())).await()
            verifyEgress(sourceContents, identifier, false, "gz")
        }

        "Should deflate files if specified" {
            val identifier = "z"
            val sourceContents = sourceContents(identifier)
            val putRequest = with(PutObjectRequest.builder()) {
                bucket(SOURCE_BUCKET)
                key("$identifier/$identifier.csv")
                build()
            }
            s3.putObject(putRequest, AsyncRequestBody.fromBytes(sourceContents.toByteArray())).await()
            verifyEgress(sourceContents, identifier, false, "z")
        }

        "Should save SFT files to disk" {
            val identifier = "sft"
            val sourceContents = sourceContents(identifier)
            val putRequest = with(PutObjectRequest.builder()) {
                bucket(SOURCE_BUCKET)
                key("/dataworks-data-egress/sft/$identifier.csv")
                build()
            }
            s3.putObject(putRequest, AsyncRequestBody.fromString(sourceContents)).await()
            insertEgressItem("/dataworks-data-egress/sft", "/testData/sft", SFT_TRANSFER_TYPE)
            val message = messageBody("/dataworks-data-egress/sft/$PIPELINE_SUCCESS_FLAG")
            val request = sendMessageRequest(message)
            sqs.sendMessage(request).await()

            withTimeout(Duration.ofSeconds(TEST_TIMEOUT)) {
                val testFile = File("/testData").exists()
                logger.info("Directory exists: '$testFile'")
                val file = File("/testData/sft/$identifier.csv")
                while (!file.exists() ) {
                    logger.info("$file doesn't exist")
                    delay(2000)
                }

                file.readText() shouldBe sourceContents
            }
        }

        "It should have pushed metrics" {

            val identifier = "cse"
            val sourceContents = sourceContents(identifier)
            val inputStream = ByteArrayInputStream(sourceContents.toByteArray())
            val putRequest =
                PutObjectRequestVersion1(SOURCE_BUCKET, "$identifier/$identifier.csv", inputStream, ObjectMetadata())
            encryptingS3.putObject(putRequest)
            verifyEgress(sourceContents, identifier, false)


            val response = client.get<JsonObject>("http://prometheus:9090/api/v1/targets/metadata")
            logger.info("Response from pushgateway '$response")
            val metricNames = response["data"].asJsonArray
                .map(JsonElement::getAsJsonObject)
                .filter { it["target"].asJsonObject["job"].asJsonPrimitive.asString == "pushgateway" }
                .map { it["metric"].asJsonPrimitive.asString }
                .filterNot {
                    it.startsWith("go_") || it.startsWith("process_") ||
                            it.startsWith("pushgateway_") || it.startsWith("push_")
                }

            metricNames shouldContainAll listOf(
                "data_egress_s3_files_sent_success"
            )
        }
    }

    private suspend fun verifyEgress(sourceContents: String,
                                     identifier: String,
                                     decrypt: Boolean = true,
                                     compressionFormat: String = "") {
        insertEgressItem("$identifier/", "$identifier/", TRANSFER_TYPE, decrypt, compressionFormat)
        val message = messageBody("$identifier/$PIPELINE_SUCCESS_FLAG")
        val request = sendMessageRequest(message)
        sqs.sendMessage(request).await()

        withTimeout(Duration.ofSeconds(TEST_TIMEOUT)) {
            val targetContents = egressedContents(DESTINATION_BUCKET,
                if (compressionFormat.isEmpty()) "$identifier/$identifier.csv" else "$identifier/$identifier.csv.$compressionFormat")

            if (compressionFormat.isNotEmpty()) {
                if (compressionFormat == "gz") {
                    val output = ByteArrayOutputStream()
                    GZIPInputStream(ByteArrayInputStream(targetContents)).use {
                        it.copyTo(output)
                    }
                    String(output.toByteArray()) shouldBe sourceContents
                } else if (compressionFormat == "z") {
                    with(Inflater()) {
                        setInput(targetContents, 0, targetContents.size)
                        val result = ByteArray(1_000_000)
                        val resultLength = inflate(result)
                        end()
                        String(result, 0, resultLength) shouldBe sourceContents
                    }
                }
            } else {
                String(targetContents) shouldBe sourceContents
            }
        }
    }

    private fun sendMessageRequest(message: String): SendMessageRequest =
        with(SendMessageRequest.builder()) {
            queueUrl("http://localstack:4566/000000000000/integration-queue")
            messageBody(message)
            build()
        }

    private fun messageBody(key: String) =
        """{ "Records": [ { "s3": { "object": { "key": "$key" } } } ] }""".trimIndent()

    private fun sourceContents(style: String) =
        List(100) { "$style,ENCRYPTED,CBOL,REPORT,LINE,NUMBER,$it" }.joinToString("\n")

    private suspend fun egressedContents(bucket: String, key: String): ByteArray =
        egressedResponse(bucket, key).asByteArray()

    private suspend fun egressedMetadata(bucket: String, key: String): Map<String, String> =
        egressedResponse(bucket, key).response().metadata()

    private tailrec suspend fun egressedResponse(bucket: String, key: String): ResponseBytes<GetObjectResponse> {
        try {
            return s3.getObject(egressedObjectRequest(bucket, key), AsyncResponseTransformer.toBytes()).await()
        } catch (e: NoSuchKeyException) {
            logger.info("'$bucket/$key' not present")
            delay(2000)
        }
        return egressedResponse(bucket, key)
    }

    private fun egressedObjectRequest(bucket: String,
                                      key: String): GetObjectRequest =
        with(GetObjectRequest.builder()) {
            bucket(bucket)
            key(key)
            build()
        }

    private fun egressColumn(column: String, value: String) =
        column to with(AttributeValue.builder()) {
            s(value)
            build()
        }


    private suspend fun insertEgressItem(sourcePrefix: String, destinationPrefix: String,
                                         transferType: String, decrypt: Boolean = false,
                                         compressionFormat: String = ""): PutItemResponse {
        val baseRecord = mapOf<String, AttributeValue>(
            egressColumn(SOURCE_BUCKET_FIELD_NAME, SOURCE_BUCKET),
            egressColumn(DESTINATION_BUCKET_FIELD_NAME, DESTINATION_BUCKET),
            egressColumn(PIPELINE_FIELD_NAME, PIPELINE_NAME),
            egressColumn(SOURCE_PREFIX_FIELD_NAME, sourcePrefix),
            egressColumn(DESTINATION_PREFIX_FIELD_NAME, destinationPrefix),
            egressColumn(TRANSFER_TYPE_FIELD_NAME, transferType))

        val withOptionalCompressionFields = baseRecord.let { r ->
            compressionFormat.takeIf(String::isNotBlank)?.let { format ->
                r + egressColumn(COMPRESSION_FORMAT_FIELD_NAME, format) +
                        Pair(COMPRESS_FIELD_NAME, AttributeValue.builder().bool(true).build())
            }
        } ?: baseRecord

        val withOptionalDecryptField = withOptionalCompressionFields.takeIf { decrypt }?.let { r ->
            r + Pair(DECRYPT_FIELD_NAME, AttributeValue.builder().bool(true).build())
        } ?: withOptionalCompressionFields

        val request = with(PutItemRequest.builder()) {
            tableName(EGRESS_TABLE)
            item(withOptionalDecryptField)
            build()
        }
        return dynamoDb.putItem(request).await()
    }

    companion object {

        private val logger = LoggerFactory.getLogger(IntegrationTests::class.java)

        private const val TEST_TIMEOUT: Long = 20


        private const val EGRESS_TABLE = "data-egress"
        private const val PIPELINE_NAME = "INTEGRATION_TESTS"
        private const val PIPELINE_SUCCESS_FLAG = "pipeline_success.flag"
        private const val SOURCE_BUCKET = "source"
        private const val DESTINATION_BUCKET = "destination"
        private const val TRANSFER_TYPE = "S3"
        private const val SFT_TRANSFER_TYPE = "SFT"

        private const val ENCRYPTING_KEY_ID_METADATA_KEY = "datakeyencryptionkeyid"
        private const val INITIALISATION_VECTOR_METADATA_KEY = "iv"
        private const val CIPHERTEXT_METADATA_KEY = "ciphertext"

        private const val SOURCE_BUCKET_FIELD_NAME = "source_bucket"
        private const val DESTINATION_BUCKET_FIELD_NAME = "destination_bucket"
        private const val PIPELINE_FIELD_NAME = "pipeline_name"
        private const val SOURCE_PREFIX_FIELD_NAME = "source_prefix"
        private const val DESTINATION_PREFIX_FIELD_NAME = "destination_prefix"
        private const val TRANSFER_TYPE_FIELD_NAME = "transfer_type"
        private const val COMPRESSION_FORMAT_FIELD_NAME = "compress_fmt"
        private const val COMPRESS_FIELD_NAME = "compress"
        private const val DECRYPT_FIELD_NAME = "decrypt"

        private val applicationContext by lazy {
            AnnotationConfigApplicationContext(TestConfiguration::class.java)
        }

        private val sqs = applicationContext.getBean(SqsAsyncClient::class.java)
        private val encryptingS3 = applicationContext.getBean(AmazonS3EncryptionV2::class.java)
        private val s3 = applicationContext.getBean(S3AsyncClient::class.java)
        private val dynamoDb = applicationContext.getBean(DynamoDbAsyncClient::class.java)
        private val cipherService = applicationContext.getBean(CipherService::class.java)
        private val dataKeyService = applicationContext.getBean(DataKeyService::class.java)

        private fun todaysDate() = SimpleDateFormat("yyyy-MM-dd").format(Date())

        val client = HttpClient {
            install(JsonFeature) {
                serializer = GsonSerializer {
                    setPrettyPrinting()
                }
            }
        }
    }
}
