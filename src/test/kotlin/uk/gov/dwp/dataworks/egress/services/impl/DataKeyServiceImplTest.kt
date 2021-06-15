package uk.gov.dwp.dataworks.egress.services.impl

import com.google.gson.Gson
import com.nhaarman.mockitokotlin2.*
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldMatch
import org.apache.http.HttpEntity
import org.apache.http.StatusLine
import org.apache.http.client.methods.CloseableHttpResponse
import org.apache.http.client.methods.HttpGet
import org.apache.http.client.methods.HttpPost
import org.apache.http.client.methods.HttpUriRequest
import org.apache.http.impl.client.CloseableHttpClient
import uk.gov.dwp.dataworks.egress.domain.DataKeyResult
import uk.gov.dwp.dataworks.egress.exceptions.DataKeyDecryptionException
import uk.gov.dwp.dataworks.egress.exceptions.DataKeyServiceUnavailableException
import uk.gov.dwp.dataworks.egress.provider.HttpClientProvider
import java.io.ByteArrayInputStream

class DataKeyServiceImplTest: StringSpec() {

    init {
        "testBatchDataKey_WillCallClientOnce_AndReturnKey" {
            val responseBody = """
                |{
                |    "dataKeyEncryptionKeyId": "DATAKEY_ENCRYPTION_KEY_ID",
                |    "plaintextDataKey": "PLAINTEXT_DATAKEY",
                |    "ciphertextDataKey": "CIPHERTEXT_DATAKEY"
                |}
            """.trimMargin()

            val byteArrayInputStream = ByteArrayInputStream(responseBody.toByteArray())
            val statusLine = mock<StatusLine>()
            val entity = mock<HttpEntity>()
            given(entity.content).willReturn(byteArrayInputStream)
            given(statusLine.statusCode).willReturn(201)
            val httpResponse = mock<CloseableHttpResponse>()
            given(httpResponse.statusLine).willReturn(statusLine)
            given(httpResponse.entity).willReturn(entity)
            val httpClient = mock<CloseableHttpClient>()
            given(httpClient.execute(any<HttpGet>())).willReturn(httpResponse)

            val httpClientProvider = mock<HttpClientProvider> {
                on { client() } doReturn httpClient
            }

            val keyService = DataKeyServiceImpl(httpClientProvider, DATA_KEY_SERVICE_URL)
            val dataKeyResult = keyService.batchDataKey()
            val expectedResult: DataKeyResult = Gson().fromJson(responseBody, DataKeyResult::class.java)
            dataKeyResult shouldBe expectedResult
            val argumentCaptor = argumentCaptor<HttpUriRequest>()
            verify(httpClient, times(1)).execute(argumentCaptor.capture())
            argumentCaptor.firstValue.uri.toString() shouldMatch  Regex(DATAKEY_REQUEST_PATTERN)
        }

        "testBatchDataKey_ServerError_ThrowsException" {
            val httpClient = mock<CloseableHttpClient>()
            val statusLine = mock<StatusLine>()
            given(statusLine.statusCode).willReturn(503)
            val httpResponse = mock<CloseableHttpResponse>()
            given(httpResponse.statusLine).willReturn(statusLine)
            given(httpClient.execute(any<HttpGet>())).willReturn(httpResponse)
            val httpClientProvider = mock<HttpClientProvider> {
                on { client() } doReturn httpClient
            }

            shouldThrow<DataKeyServiceUnavailableException> {
                val keyService = DataKeyServiceImpl(httpClientProvider, DATA_KEY_SERVICE_URL)
                keyService.batchDataKey()
            }

            val argumentCaptor = argumentCaptor<HttpGet>()
            verify(httpClient, times(1)).execute(argumentCaptor.capture())
            argumentCaptor.firstValue.uri.toString() shouldMatch  Regex(DATAKEY_REQUEST_PATTERN)
        }

        "testBatchDataKey_UnknownHttpError_ThrowsException_AndWillRetry" {
            val statusLine = mock<StatusLine>()
            given(statusLine.statusCode).willReturn(503)
            val httpResponse = mock<CloseableHttpResponse>()
            given(httpResponse.statusLine).willReturn(statusLine)
            val httpClient = mock<CloseableHttpClient>()
            given(httpClient.execute(any<HttpGet>())).willThrow(RuntimeException("Boom!"))
            val httpClientProvider = mock<HttpClientProvider> {
                on { client() } doReturn httpClient
            }
            shouldThrow<DataKeyServiceUnavailableException> {
                val keyService = DataKeyServiceImpl(httpClientProvider, DATA_KEY_SERVICE_URL)
                keyService.batchDataKey()
            }

            val argumentCaptor = argumentCaptor<HttpGet>()
            verify(httpClient, times(1)).execute(argumentCaptor.capture())
            argumentCaptor.firstValue.uri.toString() shouldMatch  Regex(DATAKEY_REQUEST_PATTERN)
        }

        "testBatchDataKey_WhenErrorsOccur_WillRetryUntilSuccessful" {
            val responseBody = """
                |{
                |    "dataKeyEncryptionKeyId": "DATAKEY_ENCRYPTION_KEY_ID",
                |    "plaintextDataKey": "PLAINTEXT_DATAKEY",
                |    "ciphertextDataKey": "CIPHERTEXT_DATAKEY"
                |}
            """.trimMargin()

            val byteArrayInputStream = ByteArrayInputStream(responseBody.toByteArray())
            val statusLine = mock<StatusLine>()
            val entity = mock<HttpEntity>()
            given(entity.content).willReturn(byteArrayInputStream)
            given(statusLine.statusCode).willReturn(503, 503, 201)
            val httpResponse = mock<CloseableHttpResponse>()
            given(httpResponse.statusLine).willReturn(statusLine)
            given(httpResponse.entity).willReturn(entity)
            val httpClient = mock<CloseableHttpClient>()
            given(httpClient.execute(any<HttpGet>())).willReturn(httpResponse)
            val httpClientProvider = mock<HttpClientProvider> {
                on { client() } doReturn httpClient
            }

            val keyService = DataKeyServiceImpl(httpClientProvider, DATA_KEY_SERVICE_URL)


            shouldThrow<DataKeyServiceUnavailableException> {
                keyService.batchDataKey()
            }


            val argumentCaptor = argumentCaptor<HttpGet>()
            verify(httpClient, times(1)).execute(argumentCaptor.capture())
            argumentCaptor.firstValue.uri.toString() shouldMatch  Regex(DATAKEY_REQUEST_PATTERN)
        }

        "testDecryptKey_HappyCase_CallsServerOnce_AndReturnsUnencryptedData" {
            val responseBody = """
                |{
                |  "dataKeyEncryptionKeyId": "DATAKEY_ENCRYPTION_KEY_ID",
                |  "plaintextDataKey": "PLAINTEXT_DATAKEY"
                |}
            """.trimMargin()

            val byteArrayInputStream = ByteArrayInputStream(responseBody.toByteArray())
            val statusLine = mock<StatusLine>()
            val entity = mock<HttpEntity>()
            given(entity.content).willReturn(byteArrayInputStream)
            given(statusLine.statusCode).willReturn(200)
            val httpResponse = mock<CloseableHttpResponse>()
            given(httpResponse.statusLine).willReturn(statusLine)
            given(httpResponse.entity).willReturn(entity)
            val httpClient = mock<CloseableHttpClient>()
            given(httpClient.execute(any<HttpPost>())).willReturn(httpResponse)
            val httpClientProvider = mock<HttpClientProvider> {
                on { client() } doReturn httpClient
            }
            val keyService = DataKeyServiceImpl(httpClientProvider, DATA_KEY_SERVICE_URL)
            val dataKeyResult = keyService.decryptKey("123", "ENCRYPTED_KEY_ID")

            dataKeyResult shouldBe "PLAINTEXT_DATAKEY"
            val argumentCaptor = argumentCaptor<HttpPost>()
            verify(httpClient, times(1)).execute(argumentCaptor.capture())
            argumentCaptor.firstValue.uri.toString() shouldMatch  Regex(DECRYPT_KEY_REQUEST_PATTERN)
        }

        "testDecryptKey_HappyCase_WillCallServerOnce_AndCacheResponse" {
            val responseBody = """
                |{
                |  "dataKeyEncryptionKeyId": "DATAKEY_ENCRYPTION_KEY_ID",
                |  "plaintextDataKey": "PLAINTEXT_DATAKEY"
                |}
            """.trimMargin()

            val byteArrayInputStream = ByteArrayInputStream(responseBody.toByteArray())
            val statusLine = mock<StatusLine>()
            val entity = mock<HttpEntity>()
            given(entity.content).willReturn(byteArrayInputStream)
            given(statusLine.statusCode).willReturn(200)
            val httpResponse = mock<CloseableHttpResponse>()
            given(httpResponse.statusLine).willReturn(statusLine)
            given(httpResponse.entity).willReturn(entity)
            val httpClient = mock<CloseableHttpClient>()
            given(httpClient.execute(any<HttpPost>())).willReturn(httpResponse)
            val httpClientProvider = mock<HttpClientProvider> {
                on { client() } doReturn httpClient
            }
            val keyService = DataKeyServiceImpl(httpClientProvider, DATA_KEY_SERVICE_URL)

            val dataKeyResult = keyService.decryptKey("123", "ENCRYPTED_KEY_ID")
            dataKeyResult shouldBe "PLAINTEXT_DATAKEY"

            val argumentCaptor = argumentCaptor<HttpPost>()
            verify(httpClient, times(1)).execute(argumentCaptor.capture())
            argumentCaptor.firstValue.uri.toString() shouldMatch  Regex(DECRYPT_KEY_REQUEST_PATTERN)
        }

        "testDecryptKey_WithABadKey_WillCallServerOnce_AndNotRetry" {
            val statusLine = mock<StatusLine>()
            given(statusLine.statusCode).willReturn(400)
            val httpResponse = mock<CloseableHttpResponse>()
            given(httpResponse.statusLine).willReturn(statusLine)
            val httpClient = mock<CloseableHttpClient>()
            given(httpClient.execute(any<HttpPost>())).willReturn(httpResponse)
            val httpClientProvider = mock<HttpClientProvider> {
                on { client() } doReturn httpClient
            }
            val keyService = DataKeyServiceImpl(httpClientProvider, DATA_KEY_SERVICE_URL)

            val ex = shouldThrow<DataKeyDecryptionException> {
                keyService.decryptKey("123", "ENCRYPTED_KEY_ID")
            }
            ex.message shouldMatch Regex("""Decrypting encryptedKey: 'ENCRYPTED_KEY_ID' with keyEncryptionKeyId: '123' data key service returned status code '400' for dks_correlation_id: '[^']+'""")
            val argumentCaptor = argumentCaptor<HttpPost>()
            verify(httpClient, times(1)).execute(argumentCaptor.capture())
            argumentCaptor.firstValue.uri.toString() shouldMatch  Regex(DECRYPT_KEY_REQUEST_PATTERN)
        }

    }
    companion object {
        private const val DATA_KEY_SERVICE_URL = "http://dks:8443"
        private const val DATAKEY_REQUEST_PATTERN = """^http://dks:8443/datakey\?correlationId=.+$"""
        private const val DECRYPT_KEY_REQUEST_PATTERN = """^http://dks:8443/datakey/actions/decrypt\?keyId=123&correlationId=.+$"""
    }
}
