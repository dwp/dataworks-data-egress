package uk.gov.dwp.dataworks.egress.services.impl

import com.google.gson.Gson
import org.apache.http.client.methods.HttpGet
import org.apache.http.client.methods.HttpPost
import org.apache.http.entity.ContentType
import org.apache.http.entity.StringEntity
import org.apache.http.util.EntityUtils
import org.springframework.retry.annotation.Backoff
import org.springframework.retry.annotation.Retryable
import org.springframework.stereotype.Service
import uk.gov.dwp.dataworks.egress.domain.DataKeyResult
import uk.gov.dwp.dataworks.egress.exceptions.DataKeyDecryptionException
import uk.gov.dwp.dataworks.egress.exceptions.DataKeyServiceUnavailableException
import uk.gov.dwp.dataworks.egress.provider.HttpClientProvider
import uk.gov.dwp.dataworks.egress.services.DataKeyService
import uk.gov.dwp.dataworks.logging.DataworksLogger
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.URLEncoder
import java.util.*

@Service
class DataKeyServiceImpl(private val httpClientProvider: HttpClientProvider,
                         private val dksUrl: String): DataKeyService {

    @Override
    @Retryable(value = [DataKeyServiceUnavailableException::class],
        maxAttemptsExpression = "\${datakeyservice.retry.maxAttempts:5}",
        backoff = Backoff(delayExpression = "\${datakeyservice.retry.delay:1000}",
            multiplierExpression = "\${datakeyservice.retry.multiplier:2}"))
    @Throws(DataKeyServiceUnavailableException::class)
    @Synchronized
    override fun batchDataKey(): DataKeyResult {
        if (dataKeyResult == null) {
            dataKeyResult = dataKey()
        }
        return dataKeyResult!!
    }

    private fun dataKey(): DataKeyResult {
        val dksUrl = "$dksUrl/datakey"
        val dksCorrelationId = UUID.randomUUID().toString()
        val dksUrlWithCorrelationId = "$dksUrl?correlationId=$dksCorrelationId"
        try {
            httpClientProvider.client().use { client ->
                client.execute(HttpGet(dksUrlWithCorrelationId)).use { response ->
                    val statusCode = response.statusLine.statusCode
                    return if (statusCode == 201) {
                        val entity = response.entity
                        val result = BufferedReader(InputStreamReader(entity.content))
                            .use(BufferedReader::readText).let {
                                Gson().fromJson(it, DataKeyResult::class.java)
                            }
                        EntityUtils.consume(entity)
                        result
                    } else {
                        logger.warn("Getting batch data key - data key service returned bad status code",
                            "dks_url" to dksUrl,
                            "dks_correlation_id" to dksCorrelationId,
                            "status_code" to "$statusCode")
                        throw DataKeyServiceUnavailableException("Getting batch data key - data key service returned bad status code '$statusCode' for dks_correlation_id: '$dksCorrelationId'")
                    }
                }
            }
        } catch (ex: Exception) {
            when (ex) {
                is DataKeyServiceUnavailableException -> {
                    ex.printStackTrace()
                    throw ex
                }
                else -> {
                    ex.printStackTrace()
                    throw DataKeyServiceUnavailableException("Error contacting data key service: '$ex' for dks_correlation_id: '$dksCorrelationId'")
                }
            }
        }
    }

    @Override
    @Retryable(value = [DataKeyServiceUnavailableException::class],
        maxAttemptsExpression = "\${datakeyservice.retry.maxAttempts:5}",
        backoff = Backoff(delayExpression = "\${datakeyservice.retry.delay:1000}",
            multiplierExpression = "\${datakeyservice.retry.multiplier:2}"))
    @Throws(DataKeyServiceUnavailableException::class, DataKeyDecryptionException::class)
    override fun decryptKey(encryptionKeyId: String, encryptedKey: String): String {
        val dksCorrelationId = UUID.randomUUID().toString()
        try {
            val cacheKey = "$encryptedKey/$encryptionKeyId"
            return if (decryptedKeyCache.containsKey(cacheKey)) {
                decryptedKeyCache[cacheKey]!!
            } else {
                httpClientProvider.client().use { client ->
                    val dksUrl = "$dksUrl/datakey/actions/decrypt?keyId=${
                        URLEncoder.encode(encryptionKeyId, "US-ASCII")
                    }"
                    val dksUrlWithCorrelationId = "$dksUrl&correlationId=$dksCorrelationId"
                    val httpPost = HttpPost(dksUrlWithCorrelationId)
                    httpPost.entity = StringEntity(encryptedKey, ContentType.TEXT_PLAIN)
                    client.execute(httpPost).use { response ->
                        return when (val statusCode = response.statusLine.statusCode) {
                            200 -> {
                                val entity = response.entity
                                val text =
                                    BufferedReader(InputStreamReader(response.entity.content)).use(BufferedReader::readText)
                                EntityUtils.consume(entity)
                                val dataKeyResult = Gson().fromJson(text, DataKeyResult::class.java)
                                decryptedKeyCache[cacheKey] = dataKeyResult.plaintextDataKey
                                dataKeyResult.plaintextDataKey
                            }
                            400 -> {
                                logger.error("DataKeyDecryptionException from data key service",
                                    "encrypted_key" to encryptedKey,
                                    "key_encryption_key_id" to encryptionKeyId,
                                    "dks_url" to dksUrl,
                                    "dks_correlation_id" to dksCorrelationId,
                                    "status_code" to "$statusCode")
                                throw DataKeyDecryptionException("Decrypting encryptedKey: '$encryptedKey' with keyEncryptionKeyId: '$encryptionKeyId' data key service returned status code '$statusCode' for dks_correlation_id: '$dksCorrelationId'")
                            }
                            else -> {
                                logger.error("DataKeyServiceUnavailableException from data key service",
                                    "encrypted_key" to encryptedKey,
                                    "key_encryption_key_id" to encryptionKeyId,
                                    "dks_url" to dksUrl,
                                    "dks_correlation_id" to dksCorrelationId,
                                    "status_code" to "$statusCode")
                                throw DataKeyServiceUnavailableException("Decrypting encryptedKey: '$encryptedKey' with keyEncryptionKeyId: '$encryptionKeyId' data key service returned status code '$statusCode' for dks_correlation_id: '$dksCorrelationId'")
                            }
                        }
                    }
                }
            }
        } catch (ex: Exception) {
            when (ex) {
                is DataKeyDecryptionException -> {
                    throw ex
                }
                is DataKeyServiceUnavailableException -> {
                    throw ex
                }
                else -> throw DataKeyServiceUnavailableException("Error contacting data key service: '$ex' for dks_correlation_id: '$dksCorrelationId'")
            }
        }
    }

    override fun clearCache() {
        this.decryptedKeyCache = mutableMapOf()
    }

    private var decryptedKeyCache = mutableMapOf<String, String>()

    private var dataKeyResult: DataKeyResult? = null

    companion object {
        private val logger: DataworksLogger = DataworksLogger.getLogger(DataKeyServiceImpl::class.java)
    }
}
