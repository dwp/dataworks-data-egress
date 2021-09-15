package uk.gov.dwp.dataworks.egress

import com.amazonaws.services.s3.AmazonS3EncryptionV2
import com.amazonaws.services.s3.model.ObjectMetadata
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.collections.shouldContainAll
import io.kotest.matchers.collections.shouldContainExactlyInAnyOrder
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.ktor.client.*
import io.ktor.client.features.json.*
import io.ktor.client.request.*
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.future.await
import kotlinx.coroutines.launch
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
import software.amazon.awssdk.services.s3.model.*
import software.amazon.awssdk.services.sqs.SqsAsyncClient
import software.amazon.awssdk.services.sqs.model.SendMessageRequest
import uk.gov.dwp.dataworks.egress.services.CipherService
import uk.gov.dwp.dataworks.egress.services.DataKeyService
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
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

        "Should process collection specific files" {
            coroutineScope {
                List(10) { collectionNumber ->
                    List(10) { fileNumber -> sourceContents("collection_${collectionNumber}_file_${fileNumber}") }
                }.forEachIndexed { collectionNumber, list ->
                    val (encryptingKeyId, plaintextDataKey, ciphertextDataKey) = dataKeyService.batchDataKey()
                    list.forEachIndexed { fileNumber, fileContents ->
                        launch {
                            val (iv, encrypted) = cipherService.encrypt(plaintextDataKey, fileContents.toByteArray())

                            val key =
                                "collections/${todaysDate()}/incremental/database.collection$collectionNumber-$fileNumber.csv.enc"
                            val putRequest = with(PutObjectRequest.builder()) {
                                bucket(SOURCE_BUCKET)
                                key(key)
                                metadata(mapOf(ENCRYPTING_KEY_ID_METADATA_KEY to encryptingKeyId,
                                    INITIALISATION_VECTOR_METADATA_KEY to iv,
                                    CIPHERTEXT_METADATA_KEY to ciphertextDataKey))
                                build()
                            }
                            logger.info("Putting object at $key")
                            s3.putObject(putRequest, AsyncRequestBody.fromBytes(encrypted)).await()
                            logger.info("Put object at $key")
                        }
                    }
                }
                launch {
                    logger.info("Inserting egress item")
                    val wtf = insertEgressItem("collections/\$TODAYS_DATE/incremental/database.collection5-",
                        "collections/\$TODAYS_DATE/incremental/", S3_TRANSFER_TYPE, decrypt = true,
                        controlFilePrefix = "database.collection5-\$TODAYS_DATE.control",
                        timestampFiles = true)
                    logger.info("Inserted egress item: $wtf")
                }
            }
            val message =
                messageBody("collections/${todaysDate()}/incremental/database.collection5-$PIPELINE_SUCCESS_FLAG")
            val request = sendMessageRequest(message)
            logger.info("Sending SQS message: '$request'.")
            val response = sqs.sendMessage(request).await()
            logger.info("Sent SQS message: '$response'.")
            withTimeout(Duration.ofSeconds(TEST_TIMEOUT)) {
                egressedHtmeSubset() shouldContainExactlyInAnyOrder List(10) {
                    "collections/${todaysDate()}/incremental/database.collection5-$it.${todaysDate("yyyyMMdd")}.csv"
                } + "collections/${todaysDate()}/incremental/database.collection5-${todaysDate("yyyyMMdd")}.control"
            }
        }

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
            insertEgressItem("$identifier/", "$identifier/", S3_TRANSFER_TYPE, false)
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
            insertEgressItem("$identifier/\$TODAYS_DATE", "$identifier/\$TODAYS_DATE", S3_TRANSFER_TYPE)
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
                while (!file.exists()) {
                    logger.info("Awaiting presence of '$file'.")
                    delay(2000)
                }

                file.readText() shouldBe sourceContents
            }
        }

        "It should have pushed metrics" {
            val metricNames = withTimeout(Duration.ofSeconds(TEST_TIMEOUT)) { egressMetrics() }
            metricNames shouldContainAll listOf("data_egress_files_sent_success_total")
        }
    }

    private tailrec suspend fun egressedHtmeSubset(): List<String> {
        val request = with(ListObjectsV2Request.builder()) {
            bucket(DESTINATION_BUCKET)
            prefix("collections/${todaysDate()}/incremental/")
            build()
        }

        val keys = s3.listObjectsV2(request).await().contents().map(S3Object::key)
        logger.info("Got ${keys.size} keys: '$keys'.")
        if (keys.size > 10) {
            return keys
        }
        delay(3_000)
        return egressedHtmeSubset()
    }

    private tailrec suspend fun egressMetrics(): List<String> {
        val response = client.get<JsonObject>("http://prometheus:9090/api/v1/targets/metadata")
        logger.info("Response from prometheus '$response")
        val egressMetrics: List<String> = response["data"].asJsonArray
            .map(JsonElement::getAsJsonObject)
            .filter { it["target"].asJsonObject["job"].asJsonPrimitive.asString == "pushgateway" }
            .map { it["metric"].asJsonPrimitive.asString }
            .filterNot {
                it.startsWith("go_") || it.startsWith("process_") ||
                        it.startsWith("pushgateway_") || it.startsWith("push_")
            }

        if (egressMetrics.isNotEmpty()) {
            return egressMetrics
        }
        delay(3_000)
        return egressMetrics()
    }

    private suspend fun verifyEgress(sourceContents: String,
                                     identifier: String,
                                     decrypt: Boolean = true,
                                     compressionFormat: String = "", rewrapDatakey: Boolean = false,
                                     ssmParamName: String = "") {
        insertEgressItem("$identifier/",
            "$identifier/",
            S3_TRANSFER_TYPE,
            decrypt,
            compressionFormat,
            rewrapDatakey,
            ssmParamName)
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
            logger.info("Awaiting presence of '$bucket/$key'.")
            return s3.getObject(egressedObjectRequest(bucket, key), AsyncResponseTransformer.toBytes()).await()
        } catch (e: NoSuchKeyException) {
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

    private fun egressBooleanColumn(column: String, value: Boolean) =
        column to with(AttributeValue.builder()) {
            bool(value)
            build()
        }


    private suspend fun insertEgressItem(sourcePrefix: String,
                                         destinationPrefix: String,
                                         transferType: String,
                                         decrypt: Boolean = false,
                                         compressionFormat: String = "",
                                         rewrapDatakey: Boolean = false,
                                         ssmParamName: String = "",
                                         controlFilePrefix: String = "",
                                         timestampFiles: Boolean = false): PutItemResponse {
        val baseRecord = mapOf<String, AttributeValue>(
            egressColumn(SOURCE_BUCKET_FIELD_NAME, SOURCE_BUCKET),
            egressColumn(DESTINATION_BUCKET_FIELD_NAME, DESTINATION_BUCKET),
            egressColumn(PIPELINE_FIELD_NAME, PIPELINE_NAME),
            egressColumn(RECIPIENT_FIELD_NAME, RECIPIENT),
            egressColumn(SOURCE_PREFIX_FIELD_NAME, sourcePrefix),
            egressColumn(DESTINATION_PREFIX_FIELD_NAME, destinationPrefix),
            egressBooleanColumn(TIMESTAMP_OUTPUT_FIELD_NAME, timestampFiles),
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

        val withOptionalDataKeyReWrapField = withOptionalDecryptField.takeIf { rewrapDatakey }?.let { r ->
            r + Pair(REWRAP_DATAKEY_FIELD_NAME, AttributeValue.builder().bool(true).build())
        } ?: withOptionalDecryptField

        val withOptionalSsmParamField = withOptionalDataKeyReWrapField.takeIf { decrypt }?.let { r ->
            ssmParamName.takeIf(String::isNotBlank)?.let { paramName ->
                r + egressColumn(ENCRYPTING_KEY_SSM_PARAM_NAME_FIELD_NAME, paramName)
            }
        } ?: withOptionalDataKeyReWrapField

        val withOptionalMetadataPrefix = withOptionalSsmParamField.let { r ->
            controlFilePrefix.takeIf(String::isNotBlank)?.let { prefix ->
                r + egressColumn(CONTROL_FILE_PREFIX_FIELD_NAME, prefix)
            }
        } ?: withOptionalSsmParamField


        val request = with(PutItemRequest.builder()) {
            tableName(EGRESS_TABLE)
            item(withOptionalMetadataPrefix)
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
        private const val S3_TRANSFER_TYPE = "S3"
        private const val SFT_TRANSFER_TYPE = "SFT"
        private const val RECIPIENT = "recipient"

        private const val ENCRYPTING_KEY_ID_METADATA_KEY = "datakeyencryptionkeyid"
        private const val INITIALISATION_VECTOR_METADATA_KEY = "iv"
        private const val CIPHERTEXT_METADATA_KEY = "ciphertext"

        private const val SOURCE_BUCKET_FIELD_NAME = "source_bucket"
        private const val DESTINATION_BUCKET_FIELD_NAME = "destination_bucket"
        private const val PIPELINE_FIELD_NAME = "pipeline_name"
        private const val RECIPIENT_FIELD_NAME = "recipient_name"
        private const val SOURCE_PREFIX_FIELD_NAME = "source_prefix"
        private const val DESTINATION_PREFIX_FIELD_NAME = "destination_prefix"
        private const val TRANSFER_TYPE_FIELD_NAME = "transfer_type"
        private const val CONTROL_FILE_PREFIX_FIELD_NAME = "control_file_prefix"
        private const val TIMESTAMP_OUTPUT_FIELD_NAME = "timestamp_files"
        private const val COMPRESSION_FORMAT_FIELD_NAME = "compress_fmt"
        private const val COMPRESS_FIELD_NAME = "compress"
        private const val DECRYPT_FIELD_NAME = "decrypt"
        private const val REWRAP_DATAKEY_FIELD_NAME: String = "rewrap_datakey"
        private const val ENCRYPTING_KEY_SSM_PARAM_NAME_FIELD_NAME: String = "encrypting_key_ssm_parm_name"


        private val applicationContext by lazy {
            AnnotationConfigApplicationContext(TestConfiguration::class.java)
        }

        private val sqs = applicationContext.getBean(SqsAsyncClient::class.java)
        private val encryptingS3 = applicationContext.getBean(AmazonS3EncryptionV2::class.java)
        private val s3 = applicationContext.getBean(S3AsyncClient::class.java)
        private val dynamoDb = applicationContext.getBean(DynamoDbAsyncClient::class.java)
        private val cipherService = applicationContext.getBean(CipherService::class.java)
        private val dataKeyService = applicationContext.getBean(DataKeyService::class.java)

        private fun todaysDate(format: String = "yyyy-MM-dd") = SimpleDateFormat(format).format(Date())

        val client = HttpClient {
            install(JsonFeature) {
                serializer = GsonSerializer {
                    setPrettyPrinting()
                }
            }
        }
    }
}
