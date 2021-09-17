package uk.gov.dwp.dataworks.egress.services.impl

import kotlinx.coroutines.future.await
import org.springframework.stereotype.Service
import software.amazon.awssdk.core.async.AsyncRequestBody
import software.amazon.awssdk.services.s3.S3AsyncClient
import software.amazon.awssdk.services.s3.model.ObjectCannedACL
import software.amazon.awssdk.services.s3.model.PutObjectRequest
import uk.gov.dwp.dataworks.egress.domain.EgressSpecification
import uk.gov.dwp.dataworks.egress.services.ControlFileService
import uk.gov.dwp.dataworks.egress.utility.FileUtility.writeToFile
import uk.gov.dwp.dataworks.logging.DataworksLogger
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.text.SimpleDateFormat
import java.util.*

@Service
class ControlFileServiceImpl(s3AsyncClient: S3AsyncClient,
                             assumedRoleS3ClientProvider: suspend (String) -> S3AsyncClient): ControlFileService,
    EgressServiceImpl(s3AsyncClient, assumedRoleS3ClientProvider) {

    override suspend fun egressControlFile(egressed: List<String>,
                                           specification: EgressSpecification): Pair<String, Boolean> {
        val key = specification.controlFilePrefix ?: ""
        return try {
            if (key.isNotBlank()) {
                val targetContents = targetContents(egressed)
                logger.info("Got control target contents", "specification" to "$specification")
                val targetKey = targetKey(specification, key.replace(TODAYS_DATE_PLACEHOLDER, todaysDate))
                logger.info("Got control target key",
                    "specification" to "$specification",
                    "target_key" to targetKey)
                when (specification.transferType) {
                    "S3" -> {
                        logger.info("Transferring control contents to s3",
                            "specification" to "$specification",
                            "target_key" to targetKey)
                        val request = with(PutObjectRequest.builder()) {
                            bucket(specification.destinationBucket)
                            acl(ObjectCannedACL.BUCKET_OWNER_FULL_CONTROL)
                            key(targetKey)
                            build()
                        }

                        egressClient(specification).putObject(request, AsyncRequestBody.fromBytes(targetContents))
                            .await()
                        logger.info("Transferred control contents to s3",
                            "target_key" to targetKey,
                            "specification" to "$specification")
                        Pair(targetKey, true)
                    }
                    "SFT" -> {
                        logger.info("Transferring control contents to file",
                            "target_key" to targetKey,
                            "specification" to "$specification")
                        writeToFile(File(targetKey).name, specification.destinationPrefix, targetContents)
                        logger.info("Transferred control contents to file",
                            "target_key" to targetKey,
                            "specification" to "$specification")
                        Pair(targetKey, true)
                    }
                    else -> {
                        logger.warn("Unsupported transfer type", "specification" to "$specification")
                        Pair(targetKey, false)
                    }
                }
            } else {
                Pair(key, false)
            }
        } catch (e: Exception) {
            logger.error("Failed to egress control object", e, "specification" to "$specification")
            Pair(key, false)
        }
    }

    private fun targetContents(egressed: List<String>): ByteArray =
        with (ByteArrayOutputStream()) {
            BufferedOutputStream(this).use { buffered ->
                egressed.map(::File).map(File::getName).map { "$it\n" }.map(String::toByteArray).forEach(buffered::write)
            }
            toByteArray()
        }

    companion object {
        private val logger = DataworksLogger.getLogger(ControlFileServiceImpl::class)
        private const val TODAYS_DATE_PLACEHOLDER = "\$TODAYS_DATE"
        private val todaysDate get() = SimpleDateFormat("YYYYMMdd").format(Date())
    }
}
