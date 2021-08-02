package uk.gov.dwp.dataworks.egress.services.impl

import com.amazonaws.services.s3.AmazonS3EncryptionV2
import com.google.gson.GsonBuilder
import io.prometheus.client.Counter
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.future.await
import kotlinx.coroutines.withContext
import org.springframework.stereotype.Service
import software.amazon.awssdk.core.async.AsyncRequestBody
import software.amazon.awssdk.core.async.AsyncResponseTransformer
import software.amazon.awssdk.services.s3.S3AsyncClient
import software.amazon.awssdk.services.s3.S3Client
import software.amazon.awssdk.services.s3.model.*
import software.amazon.awssdk.services.ssm.SsmClient
import uk.gov.dwp.dataworks.egress.domain.EgressSpecification
import uk.gov.dwp.dataworks.egress.services.CipherService
import uk.gov.dwp.dataworks.egress.services.CompressionService
import uk.gov.dwp.dataworks.egress.services.DataKeyService
import uk.gov.dwp.dataworks.egress.services.DataService
import uk.gov.dwp.dataworks.logging.DataworksLogger
import java.io.ByteArrayOutputStream
import java.io.File
import com.amazonaws.services.s3.model.GetObjectRequest as GetObjectRequestVersion1
import software.amazon.awssdk.services.ssm.model.GetParameterRequest
import software.amazon.awssdk.services.ssm.model.SsmException
import uk.gov.dwp.dataworks.egress.domain.ReWrapKeyParameterStoreResult


@Service
class DataServiceImpl(
    private val s3AsyncClient: S3AsyncClient,
    private val s3Client: S3Client,
    private val ssmClient: SsmClient,
    private val decryptingS3Client: AmazonS3EncryptionV2,
    private val assumedRoleS3ClientProvider: suspend (String) -> S3AsyncClient,
    private val assumedRoleSsmClientProvider: suspend (String) -> SsmClient,
    private val dataKeyService: DataKeyService,
    private val cipherService: CipherService,
    private val compressionService: CompressionService,
    private val sentFilesSuccess: Counter,
    private val sentFilesFailure: Counter
) : DataService {

    override suspend fun egressObjects(specifications: List<EgressSpecification>): Boolean =
        specifications.map { specification -> egressObjects(specification) }.all { it }

    override suspend fun egressObjects(specification: EgressSpecification): Boolean =
        s3AsyncClient.listObjectsV2(listObjectsRequest(specification)).await().contents()
            .map(S3Object::key)
            .filter { key -> !excludedObjects.any(key::endsWith) }
            .map { key -> egressObject(key, specification) }.all { it }

    private suspend fun fetchReWrappingKeyParameter(specification: EgressSpecification) : Pair<String, String> {
        try {
            val ssmClient = rtgSsmClient(specification)
            val parameterRequest = GetParameterRequest.builder().name(specification.encryptingKeySsmParmName).build()
            val rtgParameter = ssmClient.getParameter(parameterRequest).parameter().value()

            val gson = GsonBuilder().setLenient().create()
            val rtgParameterJsonObj = gson.fromJson(rtgParameter, ReWrapKeyParameterStoreResult::class.java)
            return Pair(rtgParameterJsonObj.KeyId, rtgParameterJsonObj.PublicKey)


        } catch (e: SsmException) {
            logger.error(("Failed to get encrypting key " to "$specification.encryptingKeySsmParmName").toString())
        } finally {
            ssmClient.close()
        }
        return Pair("","")
    }

    private fun reWrapDataKey(encryptingKeyId: String?, encryptedKey: String?, reWrappingKey: String):ByteArray  {
        val decryptedKey = dataKeyService.decryptKey(encryptingKeyId!!, encryptedKey!!)
        return cipherService.rsaEncrypt(reWrappingKey, decryptedKey.toByteArray())
    }

    private suspend fun egressObject(key: String, specification: EgressSpecification): Boolean =
        try {
            logger.info("Egressing s3 object", "key" to key, "specification" to "$specification")
            //Gets source object
            val metadata = objectMetadata(specification.sourceBucket, key)
            logger.info("Got metadata", "metadata" to "$metadata")
            logger.info("Getting source contents", "specification" to "$specification")
            val sourceContents = sourceContents(metadata, specification, key)
            logger.info("Got source contents", "specification" to "$specification")
            logger.info("Getting target contents", "specification" to "$specification")
            val targetContents = targetContents(specification, sourceContents)
            logger.info("Got target contents", "specification" to "$specification")
            when {
                specification.transferType.equals("S3", true) -> {
                    logger.info("Transferring contents to s3", "specification" to "$specification")
                    val request = if (wasEncryptedByHtme(metadata) && specification.rewrapDataKey)
                    {
                        val(encryptingKeyID, reWrappingKey) = fetchReWrappingKeyParameter(specification)
                        logger.info("ReWrapping .....", "public" to "PUBLIC")
                        val reWrappedDataKey = reWrapDataKey(
                            metadata[ENCRYPTING_KEY_ID_METADATA_KEY],
                            metadata[CIPHERTEXT_METADATA_KEY],
                            reWrappingKey
                        )
                        logger.info("ReWrapped ......", "datak" to "DATAK")
                        putObjectRequestWithReWrappedKeyAsEncryptionMetadata(specification, key, encryptingKeyID,
                            String(reWrappedDataKey), metadata)
                    }
                    else if (wasEncryptedByHtme(metadata) && !specification.decrypt && !specification.rewrapDataKey) {
                        putObjectRequestWithEncryptionMetadata(specification, key, metadata)
                    } else {
                        putObjectRequest(specification, key)
                    }
                    egressClient(specification).putObject(request, AsyncRequestBody.fromBytes(targetContents)).await()
                    sentFilesSuccess.labels(
                        specification.sourcePrefix,
                        specification.pipelineName,
                        specification.destinationPrefix,
                        specification.recipient,
                        specification.transferType
                    ).inc()
                    logger.info("Transferred contents to s3", "key" to key, "specification" to "$specification")
                    logger.info("Check metadata", "metadata" to "$request")
                    true
                }
                specification.transferType.equals("SFT", true) -> {
                    logger.info("Transferring contents to file", "specification" to "$specification")
                    writeToFile(File(key).name, specification.destinationPrefix, targetContents)
                    sentFilesSuccess.labels(
                        specification.sourcePrefix,
                        specification.pipelineName,
                        specification.destinationPrefix,
                        specification.recipient,
                        specification.transferType
                    ).inc()
                    logger.info("Transferred contents to file", "key" to key, "specification" to "$specification")
                    true
                }
                else -> {
                    logger.warn("Unsupported transfer type", "specification" to "$specification")
                    false
                }
            }
        } catch (e: Exception) {
            logger.error("Failed to egress object", e, "key" to key, "specification" to "$specification")
            sentFilesFailure.labels(
                specification.sourcePrefix,
                specification.pipelineName,
                specification.destinationPrefix,
                specification.recipient,
                specification.transferType
            ).inc()
            false
        }

    private fun listObjectsRequest(specification: EgressSpecification): ListObjectsV2Request =
        with(ListObjectsV2Request.builder()) {
            bucket(specification.sourceBucket)
            prefix(specification.sourcePrefix)
            build()
        }

    private fun putObjectRequest(
        specification: EgressSpecification,
        key: String
    ): PutObjectRequest =
        with(PutObjectRequest.builder()) {
            bucket(specification.destinationBucket)
            acl(ObjectCannedACL.BUCKET_OWNER_FULL_CONTROL)
            key(targetKey(specification, key))
            build()
        }

    private fun putObjectRequestWithEncryptionMetadata(
        specification: EgressSpecification,
        key: String, metadata: Map<String, String>
    ): PutObjectRequest =
        with(PutObjectRequest.builder()) {
            bucket(specification.destinationBucket)
            key(targetKey(specification, key))
            acl(ObjectCannedACL.BUCKET_OWNER_FULL_CONTROL)
            metadata(
                mapOf(
                    INITIALISATION_VECTOR_METADATA_KEY to metadata[INITIALISATION_VECTOR_METADATA_KEY],
                    ENCRYPTING_KEY_ID_METADATA_KEY to metadata[ENCRYPTING_KEY_ID_METADATA_KEY],
                    CIPHERTEXT_METADATA_KEY to metadata[CIPHERTEXT_METADATA_KEY],
                    DATA_PRODUCT to sendMetadata(metadata[DATA_PRODUCT]),
                    DATA_PRODUCT_TYPE to sendMetadata(metadata[DATA_PRODUCT_TYPE])
                )
            )
            build()
        }

    private fun putObjectRequestWithReWrappedKeyAsEncryptionMetadata(
        specification: EgressSpecification,
        key: String,
        keyEncryptionKeyId: String,
        reWrappedDataKey: String,
        metadata: Map<String, String>
    ): PutObjectRequest =
        with(PutObjectRequest.builder()) {
            bucket(specification.destinationBucket)
            key(targetKey(specification, key))
            acl(ObjectCannedACL.BUCKET_OWNER_FULL_CONTROL)
            metadata(
                mapOf(
                    INITIALISATION_VECTOR_METADATA_KEY to "metadata[INITIALISATION_VECTOR_METADATA_KEY]",
                    ENCRYPTING_KEY_ID_METADATA_KEY to "keyEncryptionKeyId",
                    CIPHERTEXT_METADATA_KEY to "reWrappedDataKey"
//                    DATA_PRODUCT to sendMetadata(metadata[DATA_PRODUCT]),
//                    DATA_PRODUCT_TYPE to sendMetadata(metadata[DATA_PRODUCT_TYPE]),
                )
            )
            build()
        }

    private fun targetKey(
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


    private suspend fun egressClient(specification: EgressSpecification): S3AsyncClient =
        specification.roleArn?.let {
            assumedRoleS3ClientProvider(specification.roleArn)
        } ?: run {
            s3AsyncClient
        }

    private suspend fun rtgSsmClient(specification: EgressSpecification): SsmClient =
        specification.roleArn?.let {
            assumedRoleSsmClientProvider(specification.roleArn)
        } ?: run {
            ssmClient
        }

    private fun targetContents(
        specification: EgressSpecification,
        sourceContents: ByteArray
    ): ByteArray {
        return if (specification.compress) {
            compressionService.compress(specification.compressionFormat, sourceContents)
        } else {
            sourceContents
        }
    }

    private suspend fun sourceContents(
        metadata: MutableMap<String, String>,
        specification: EgressSpecification,
        key: String
    ): ByteArray {
        val metadataPairs = metadata.entries.map { (k, v) -> Pair(k, v) }.toTypedArray()

        return when {
            wasEncryptedByEmr(metadata) -> {
                logger.info(
                    "Found EMR client-side encrypted object",
                    "bucket" to specification.sourceBucket,
                    "key" to key,
                    *metadataPairs
                )
                emrEncryptedObjectContents(specification.sourceBucket, key)
            }
            wasEncryptedByHtme(metadata) && specification.decrypt -> {
                logger.info(
                    "Found HTME encrypted object",
                    "bucket" to specification.sourceBucket,
                    "key" to key,
                    *metadataPairs
                )
                htmeEncryptedObjectContents(specification.sourceBucket, key)
            }
            else -> {
                logger.info(
                    "Found unencrypted object",
                    "bucket" to specification.sourceBucket,
                    "key" to key,
                    *metadataPairs
                )
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

    private suspend fun writeToFile(fileName: String, folder: String, targetContents: ByteArray) =
        withContext(Dispatchers.IO) {
            val parent = File(if (folder.startsWith("/")) folder else "/$folder")

            if (!parent.isDirectory) {
                logger.info("Making parent directory", "parent" to "$parent", "filename" to fileName)
                if (!parent.mkdirs()) {
                    logger.error("Failed to make parent directories", "parent" to "$parent", "filename" to fileName)
                    throw RuntimeException("Failed to make parent directories, parent: '$parent', filename: '$fileName'")
                }
            }

            val file = File(parent, fileName)
            logger.info("Writing file", "file" to "$file", "parent" to "$parent", "filename" to fileName)
            file.writeBytes(targetContents)
        }

    private fun sendMetadata(metadata: String?):String {
        if(metadata != null){
            return metadata;
        }
        return "";
    }

    companion object {
        private val logger = DataworksLogger.getLogger(DataServiceImpl::class)
        private const val MATERIALS_DESCRIPTION_METADATA_KEY = "x-amz-matdesc"
        private const val ENCRYPTING_KEY_ID_METADATA_KEY = "datakeyencryptionkeyid"
        private const val INITIALISATION_VECTOR_METADATA_KEY = "iv"
        private const val CIPHERTEXT_METADATA_KEY = "ciphertext"
        private const val DATA_PRODUCT = "data_product"
        private const val DATA_PRODUCT_TYPE= "data_product_type"
        private val excludedObjects = listOf("pipeline_success.flag")
    }
}
