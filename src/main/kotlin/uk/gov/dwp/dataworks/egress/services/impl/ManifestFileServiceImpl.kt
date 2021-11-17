package uk.gov.dwp.dataworks.egress.services.impl

import com.google.gson.GsonBuilder
import kotlinx.coroutines.future.await
import org.springframework.stereotype.Service
import software.amazon.awssdk.core.async.AsyncRequestBody
import software.amazon.awssdk.services.s3.S3AsyncClient
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request
import software.amazon.awssdk.services.s3.model.ObjectCannedACL
import software.amazon.awssdk.services.s3.model.PutObjectRequest
import software.amazon.awssdk.services.s3.model.S3Object
import software.amazon.awssdk.services.ssm.SsmClient
import software.amazon.awssdk.services.ssm.model.GetParameterRequest
import software.amazon.awssdk.services.ssm.model.SsmException
import uk.gov.dwp.dataworks.egress.domain.EgressSpecification
import uk.gov.dwp.dataworks.egress.domain.ReWrapKeyParameterStoreResult
import uk.gov.dwp.dataworks.egress.services.CipherService
import uk.gov.dwp.dataworks.egress.services.DataKeyService
import uk.gov.dwp.dataworks.egress.services.ManifestFileService
import uk.gov.dwp.dataworks.egress.utility.FileUtility.writeToFile
import uk.gov.dwp.dataworks.logging.DataworksLogger
import java.io.File
import java.text.SimpleDateFormat
import java.util.*

@Service
class ManifestFileServiceImpl(private val s3AsyncClient: S3AsyncClient,
                              private val dataKeyService: DataKeyService,
                              private val cipherService: CipherService,
                              private val ssmClient: SsmClient,
                              private val assumedRoleSsmClientProvider: suspend (String) -> SsmClient,
                              assumedRoleS3ClientProvider: suspend (String) -> S3AsyncClient): ManifestFileService,
    EgressServiceImpl(s3AsyncClient, assumedRoleS3ClientProvider) {

    override suspend fun egressManifestFile(specification: EgressSpecification): Pair<String, Boolean> {
        val manifestFileName = specification.manifestFileName?: ""
        return try {
            if (manifestFileName.isNotBlank()) {
                val targetKey = targetKey(specification, manifestFileName.replace(TODAYS_YYYYMMDD_FORMATTED_DATE_PLACEHOLDER, todaysDate("yyyyMMdd")).
                replace(TODAYS_DATE_PLACEHOLDER, todaysDate()))
                logger.info("Got manifest target key",
                    "specification" to "$specification",
                    "target_key" to targetKey)

                val (targetContents, putRequest) = targetContentsAndRequest(specification, targetKey)
                logger.info("Got manifest target contents", "specification" to "$specification")

                when (specification.transferType) {
                    "S3" -> {

                        logger.info("Transferring manifest file to s3",
                            "specification" to "$specification",
                            "target_key" to targetKey)

                        egressClient(specification).putObject(putRequest, AsyncRequestBody.fromBytes(targetContents))
                            .await()
                        logger.info("Transferred manifest file to s3",
                            "target_key" to targetKey,
                            "specification" to "$specification")
                        Pair(targetKey, true)
                    }
                    "SFT" -> {
                        logger.info("Transferring manifest contents to file",
                            "target_key" to targetKey,
                            "specification" to "$specification")
                        writeToFile(File(targetKey).name, specification.destinationPrefix, targetContents)
                        logger.info("Transferred manifest contents to file",
                            "target_key" to targetKey,
                            "specification" to "$specification")
                        Pair(targetKey, true)
                    }
                    else -> {
                        logger.warn("Unsupported manifest type", "specification" to "$specification")
                        Pair(targetKey, false)
                    }
                }
            } else {
                Pair(manifestFileName, false)
            }
        } catch (e: Exception) {
            logger.error("Failed to egress manifest object", e, "specification" to "$specification")
            Pair(manifestFileName, false)
        }
    }

    private suspend fun targetContentsAndRequest(specification: EgressSpecification, targetKey:String): Pair<ByteArray, PutObjectRequest> {

        val sourcePrefix = specification.sourcePrefix
        val todaysDate = if (sourcePrefix.contains(TODAYS_YYYYMMDD_FORMATTED_DATE_PLACEHOLDER)) todaysDate("yyyyMMdd")
                            else todaysDate()

        // DataProductType only applicable for HTME Collections, or anything containing full or incremental in source prefix, last - is removed
        val dataProductType = if (sourcePrefix.lowercase().contains("full")) "full"
                                else if (sourcePrefix.lowercase().contains("incremental")) "incremental"
                                else ""
        // DataProduct is name of HTME Collections, taken from source prefix and last - is removed if present
        val dataProduct = sourcePrefix.substring(sourcePrefix.lastIndexOf('/')+1).replace("-$".toRegex(),"")


        // Get the list of all the objects on source path, find their sizes and prepare manifest file contents in following
        // format, 'TargetKey Size(of file in bytes) Date(YYYYMMDD)', one record per line
        val s3ObjectsList = s3AsyncClient.listObjectsV2(with(ListObjectsV2Request.builder()) {
            bucket(specification.sourceBucket)
            prefix(specification.sourcePrefix)
            build()
        }).await().contents()
        val objectKeyList = s3ObjectsList.map(S3Object::key)                 // Get S3 object key
        val objectSizeList = s3ObjectsList.map(S3Object::size)               // Get S3 object size

        val contents = objectKeyList
            .zip(objectSizeList) {                                           // Zip key with object size of each object
                 key, size ->                                                // then make key, file-size and date
                "${targetKey(specification,key)}  $size $todaysDate\n"       // Calculate the landing path of object using targetKey function
            }
            .toList()                                                         // Make list of strings containing target key
            .joinToString( separator = "") { it }                             // Convert that list to String
            .toByteArray()


        return when (specification.manifestFileEncryption?.let{it.lowercase()}) {
            "encrypted" -> {
                val (encryptingKeyId, plainDataKey, encryptedDataKey) = dataKeyService.batchDataKey()
                val (iv, encryptedContents) = cipherService.encrypt(plainDataKey, contents)

                val putRequestObj = with(PutObjectRequest.builder()) {
                    bucket(specification.destinationBucket)
                    key(targetKey)
                    acl(ObjectCannedACL.BUCKET_OWNER_FULL_CONTROL)
                    metadata(mapOf(ENCRYPTING_KEY_ID_METADATA_KEY to encryptingKeyId,
                        INITIALISATION_VECTOR_METADATA_KEY to iv,
                        CIPHERTEXT_METADATA_KEY to encryptedDataKey,
                        DATA_PRODUCT to dataProduct,
                        DATA_PRODUCT_TYPE to dataProductType))
                    build()
                }
                Pair(encryptedContents, putRequestObj)
            }
            "re-wrapped", "rewrapped" -> {
                val (_, plainDataKey, _) = dataKeyService.batchDataKey()                            // Get data key from DKS
                val (iv, encryptedContents) = cipherService.encrypt(plainDataKey, contents)         // Encrypt manifest file contents with that data key
                val(reWrappingKeyID, reWrappingKey) = fetchReWrappingKeyParameter(specification)    // Get re-wrapping key

                logger.info("ReWrapping key for manifest file received, re-wrapping the data key", "re-wrapping key" to reWrappingKey)
                val reWrappedDataKey = cipherService.rsaEncrypt(reWrappingKey, plainDataKey.toByteArray())  // Re-wrap data key with re-wrapping key
                logger.info("Data key for manifest file re-wrapped", "re-wrapped data key" to reWrappedDataKey)

                val putRequestObj = with(PutObjectRequest.builder()) {
                    bucket(specification.destinationBucket)
                    key(targetKey)
                    acl(ObjectCannedACL.BUCKET_OWNER_FULL_CONTROL)
                    metadata(mapOf(ENCRYPTING_KEY_ID_METADATA_KEY to reWrappingKeyID,
                        INITIALISATION_VECTOR_METADATA_KEY to iv,
                        CIPHERTEXT_METADATA_KEY to reWrappedDataKey,
                        DATA_PRODUCT to dataProduct,
                        DATA_PRODUCT_TYPE to dataProductType))
                    build()
                }
                Pair(encryptedContents, putRequestObj)
            }
            else    -> {
                val putRequestObj = with(PutObjectRequest.builder()) {
                    bucket(specification.destinationBucket)
                    acl(ObjectCannedACL.BUCKET_OWNER_FULL_CONTROL)
                    key(targetKey)
                    build()
                }
                Pair(contents, putRequestObj)
            }
        }
    }

    private suspend fun fetchReWrappingKeyParameter(specification: EgressSpecification) : Pair<String, String> {
        try {
            val ssmClient = rtgSsmClient(specification)
            val parameterRequest = GetParameterRequest.builder().name(specification.encryptingKeySsmParmName).build()
            val rtgParameter = ssmClient.getParameter(parameterRequest).parameter().value()

            val gson = GsonBuilder().setLenient().create()
            val rtgParameterJsonObj = gson.fromJson(rtgParameter, ReWrapKeyParameterStoreResult::class.java)
            return Pair(rtgParameterJsonObj.KeyId, rtgParameterJsonObj.PublicKey)
        } catch (e: SsmException) {
            logger.error("Failed to get encrypting key", "ssm_param_name" to "$specification.encryptingKeySsmParmName")
        } finally {
            ssmClient.close()
        }
        return Pair("","")
    }

    private suspend fun rtgSsmClient(specification: EgressSpecification): SsmClient =
        specification.roleArn?.let {
            assumedRoleSsmClientProvider(specification.roleArn)
        } ?: run {
            ssmClient
        }

    companion object {
        private val logger = DataworksLogger.getLogger(ManifestFileServiceImpl::class)
        private const val TODAYS_DATE_PLACEHOLDER = "\$TODAYS_DATE"
        private const val TODAYS_YYYYMMDD_FORMATTED_DATE_PLACEHOLDER = "\$TODAYS_YYYYMMDD_FORMATTED_DATE"

        private const val ENCRYPTING_KEY_ID_METADATA_KEY = "datakeyencryptionkeyid"
        private const val INITIALISATION_VECTOR_METADATA_KEY = "iv"
        private const val CIPHERTEXT_METADATA_KEY = "ciphertext"

        private const val DATA_PRODUCT = "data_product"
        private const val DATA_PRODUCT_TYPE= "data_product_type"

        private fun todaysDate(dateFormat:String = "yyyy-MM-dd") = SimpleDateFormat(dateFormat).format(Date())
    }
}
