package uk.gov.dwp.dataworks.egress.services.impl

import com.amazonaws.services.s3.AmazonS3EncryptionV2
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.future.await
import kotlinx.coroutines.withContext
import org.springframework.stereotype.Service
import software.amazon.awssdk.core.async.AsyncRequestBody
import software.amazon.awssdk.core.async.AsyncResponseTransformer
import software.amazon.awssdk.services.s3.S3AsyncClient
import software.amazon.awssdk.services.s3.S3Client
import software.amazon.awssdk.services.s3.model.GetObjectRequest
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request
import software.amazon.awssdk.services.s3.model.PutObjectRequest
import software.amazon.awssdk.services.s3.model.S3Object
import uk.gov.dwp.dataworks.egress.domain.EgressSpecification
import uk.gov.dwp.dataworks.egress.services.CipherService
import uk.gov.dwp.dataworks.egress.services.CompressionService
import uk.gov.dwp.dataworks.egress.services.DataKeyService
import uk.gov.dwp.dataworks.egress.services.S3Service
import uk.gov.dwp.dataworks.logging.DataworksLogger
import java.io.ByteArrayOutputStream
import java.io.File
import com.amazonaws.services.s3.model.GetObjectRequest as GetObjectRequestVersion1

@Service
class S3ServiceImpl(private val s3AsyncClient: S3AsyncClient,
                    private val s3Client: S3Client,
                    private val decryptingS3Client: AmazonS3EncryptionV2,
                    private val assumedRoleS3ClientProvider: suspend (String) -> S3AsyncClient,
                    private val dataKeyService: DataKeyService,
                    private val cipherService: CipherService,
                    private val compressionService: CompressionService): S3Service {

    override suspend fun egressObjects(specifications: List<EgressSpecification>): Boolean =
        specifications.map { specification -> egressObjects(specification) }.all { it }

    override suspend fun egressObjects(specification: EgressSpecification): Boolean =
        s3AsyncClient.listObjectsV2(listObjectsRequest(specification)).await().contents()
            .map(S3Object::key)
            .filter { key -> !excludedObjects.any(key::endsWith) }
            .map { key -> egressObject(key, specification) }.all { it }

    private suspend fun egressObject(key: String, specification: EgressSpecification): Boolean =
        try {
            logger.info("Egressing s3 object", "key" to key, "specification" to "$specification")
            val metadata = objectMetadata(specification.sourceBucket, key)
            logger.info("Got metadata", "metadata" to "$metadata")
            val sourceContents = sourceContents(metadata, specification, key)
            val targetContents = targetContents(specification, sourceContents)
            val request = if (wasEncryptedByHtme(metadata) && !specification.decrypt) {
                putObjectRequestWithEncryptionMetadata(specification, key, metadata)
            } else {
                putObjectRequest(specification, key)
            }
            egressClient(specification).putObject(request, AsyncRequestBody.fromBytes(targetContents)).await()
            true
        } catch (e: Exception) {
            logger.error("Failed to egress object", e, "key" to key, "specification" to "$specification")
            false
        }


    private fun listObjectsRequest(specification: EgressSpecification): ListObjectsV2Request =
        with(ListObjectsV2Request.builder()) {
            bucket(specification.sourceBucket)
            prefix(specification.sourcePrefix)
            build()
        }


    private fun putObjectRequest(specification: EgressSpecification,
                                 key: String): PutObjectRequest =
        with(PutObjectRequest.builder()) {
            bucket(specification.destinationBucket)
            key(targetKey(specification, key))
            build()
        }

    private fun putObjectRequestWithEncryptionMetadata(specification: EgressSpecification,
                                                       key: String, metadata: Map<String, String>): PutObjectRequest =
        with(PutObjectRequest.builder()) {
            bucket(specification.destinationBucket)
            key(targetKey(specification, key))
            metadata(mapOf(INITIALISATION_VECTOR_METADATA_KEY to metadata[INITIALISATION_VECTOR_METADATA_KEY],
                ENCRYPTING_KEY_ID_METADATA_KEY to metadata[ENCRYPTING_KEY_ID_METADATA_KEY],
                CIPHERTEXT_METADATA_KEY to metadata[CIPHERTEXT_METADATA_KEY]))
            build()
        }

    private fun targetKey(specification: EgressSpecification,
                          key: String): String {
        val base = "${specification.destinationPrefix.replace(Regex("""/$"""), "")}/${File(key).name}"
            .replace(Regex("""^/"""), "")
            .replace(Regex("""\.enc$"""), if (specification.decrypt) "" else ".enc")

        return if (specification.compressionFormat?.isNotBlank() == true) {
            "${base}.${specification.compressionFormat}"
        } else {
            base
        }
    }


    private suspend fun egressClient(specification: EgressSpecification): S3AsyncClient =
        specification.roleArn?.let {
            assumedRoleS3ClientProvider(specification.roleArn)
        } ?: run {
            s3AsyncClient
        }

    private fun targetContents(specification: EgressSpecification,
                               sourceContents: ByteArray): ByteArray {
        return if (specification.compress) {
            compressionService.compress(specification.compressionFormat, sourceContents)
        } else {
            sourceContents
        }
    }

    private suspend fun sourceContents(metadata: MutableMap<String, String>,
                                       specification: EgressSpecification,
                                       key: String): ByteArray {
        val metadataPairs = metadata.entries.map { (k, v) -> Pair(k, v) }.toTypedArray()

        return when {
            wasEncryptedByEmr(metadata) -> {
                logger.info("Found EMR client-side encrypted object",
                    "bucket" to specification.sourceBucket,
                    "key" to key,
                    *metadataPairs)
                emrEncryptedObjectContents(specification.sourceBucket, key)
            }
            wasEncryptedByHtme(metadata) && specification.decrypt -> {
                logger.info("Found HTME encrypted object",
                    "bucket" to specification.sourceBucket,
                    "key" to key,
                    *metadataPairs)
                htmeEncryptedObjectContents(specification.sourceBucket, key)
            }
            else -> {
                logger.info("Found unencrypted object",
                    "bucket" to specification.sourceBucket,
                    "key" to key,
                    *metadataPairs)
                unencryptedObjectContents(specification.sourceBucket, key)
            }
        }
    }

    private suspend fun emrEncryptedObjectContents(bucket: String, key: String) =
        withContext(Dispatchers.IO) {
            ByteArrayOutputStream().run {
                decryptingS3Client.getObject(GetObjectRequestVersion1(bucket, key)).objectContent.use {
                    it.copyTo(this)
                }
                toByteArray()
            }
        }

    private suspend fun htmeEncryptedObjectContents(bucket: String, key: String): ByteArray =
        with(s3AsyncClient.getObject(getObjectRequest(bucket, key), AsyncResponseTransformer.toBytes()).await()) {
            val metadata = response().metadata()
            val iv = metadata[INITIALISATION_VECTOR_METADATA_KEY]
            val encryptingKeyId = metadata[ENCRYPTING_KEY_ID_METADATA_KEY]
            val encryptedKey = metadata[CIPHERTEXT_METADATA_KEY]
            val decryptedKey = dataKeyService.decryptKey(encryptingKeyId!!, encryptedKey!!)
            cipherService.decrypt(decryptedKey, iv!!, asByteArray())
        }


    private suspend fun unencryptedObjectContents(bucket: String, key: String): ByteArray =
        s3AsyncClient.getObject(getObjectRequest(bucket, key), AsyncResponseTransformer.toBytes()).await().asByteArray()

    private fun wasEncryptedByEmr(metadata: MutableMap<String, String>) =
        metadata.containsKey(MATERIALS_DESCRIPTION_METADATA_KEY)

    private fun wasEncryptedByHtme(metadata: MutableMap<String, String>): Boolean =
        listOf(ENCRYPTING_KEY_ID_METADATA_KEY, INITIALISATION_VECTOR_METADATA_KEY, CIPHERTEXT_METADATA_KEY)
            .all(metadata::containsKey)

    private suspend fun objectMetadata(bucket: String, key: String) =
        withContext(Dispatchers.IO) {
            s3Client.getObject(getObjectRequest(bucket, key)).response().metadata()
        }

    private fun getObjectRequest(bucket: String, key: String): GetObjectRequest =
        with(GetObjectRequest.builder()) {
            bucket(bucket)
            key(key)
            build()
        }

    companion object {
        private val logger = DataworksLogger.getLogger(S3ServiceImpl::class)
        private const val MATERIALS_DESCRIPTION_METADATA_KEY = "x-amz-matdesc"
        private const val ENCRYPTING_KEY_ID_METADATA_KEY = "datakeyencryptionkeyid"
        private const val INITIALISATION_VECTOR_METADATA_KEY = "iv"
        private const val CIPHERTEXT_METADATA_KEY = "ciphertext"
        private val excludedObjects = listOf("pipeline_success.flag")
    }
}

