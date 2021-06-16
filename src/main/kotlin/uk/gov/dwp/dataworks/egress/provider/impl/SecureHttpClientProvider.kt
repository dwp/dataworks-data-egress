package uk.gov.dwp.dataworks.egress.provider.impl

import org.apache.http.client.config.RequestConfig
import org.apache.http.conn.ssl.SSLConnectionSocketFactory
import org.apache.http.impl.client.CloseableHttpClient
import org.apache.http.impl.client.HttpClients
import org.apache.http.ssl.SSLContexts
import org.springframework.stereotype.Component
import uk.gov.dwp.dataworks.egress.provider.HttpClientProvider
import java.io.File
import javax.net.ssl.SSLContext


@Component
class SecureHttpClientProvider(private val keystore: String,
                               private val keystorePassword: String,
                               private val keystoreAlias: String,
                               private val keyPassword: String,
                               private val truststore: String,
                               private val truststorePassword: String,
                               private val connectTimeout: Int,
                               private val connectionRequestTimeout: Int,
                               private val socketTimeout: Int) : HttpClientProvider {

    override fun client(): CloseableHttpClient =
        HttpClients.custom().run {
            setDefaultRequestConfig(requestConfig())
            setSSLSocketFactory(connectionFactory())
            build()
        }


    private fun requestConfig(): RequestConfig =
        RequestConfig.custom().run {
            setConnectTimeout(connectTimeout)
            setConnectionRequestTimeout(connectionRequestTimeout)
            setSocketTimeout(socketTimeout)
            build()
        }


    private fun connectionFactory() = SSLConnectionSocketFactory(
        sslContext(),
        arrayOf("TLSv1.2"),
        null,
        SSLConnectionSocketFactory.getDefaultHostnameVerifier())

    private fun sslContext(): SSLContext =
        SSLContexts.custom().run {
            loadKeyMaterial(
                File(keystore),
                keystorePassword.toCharArray(),
                keyPassword.toCharArray()) { _, _ -> keystoreAlias }
            loadTrustMaterial(File(truststore), truststorePassword.toCharArray())
            build()
        }
}
