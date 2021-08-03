package uk.gov.dwp.dataworks.egress.services

import uk.gov.dwp.dataworks.egress.domain.EncryptionResult

interface CipherService {
    fun decrypt(key: String, initializationVector: String, encrypted: ByteArray): ByteArray
    fun encrypt(key: String, plaintext: ByteArray): EncryptionResult
    fun rsaEncrypt(key: String, plaintext: ByteArray): String
    fun rsaDecrypt(key: String, encrypted: ByteArray): ByteArray
}
