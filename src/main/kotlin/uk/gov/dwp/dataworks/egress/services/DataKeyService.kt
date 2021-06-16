package uk.gov.dwp.dataworks.egress.services

import uk.gov.dwp.dataworks.egress.domain.DataKeyResult

interface DataKeyService {
    fun decryptKey(encryptionKeyId: String, encryptedKey: String): String
    fun batchDataKey(): DataKeyResult
    fun clearCache()
}
