package uk.gov.dwp.dataworks.egress.services

interface CompressionService {
    fun compress(format: String?, input: ByteArray): ByteArray
}
