package uk.gov.dwp.dataworks.egress.provider

import org.apache.http.impl.client.CloseableHttpClient

interface HttpClientProvider {
    fun client(): CloseableHttpClient
}
