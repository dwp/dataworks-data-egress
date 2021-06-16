package uk.gov.dwp.dataworks.egress.provider.impl

import com.nhaarman.mockitokotlin2.doReturn
import com.nhaarman.mockitokotlin2.mock
import com.nhaarman.mockitokotlin2.times
import com.nhaarman.mockitokotlin2.verify
import io.kotest.core.spec.style.StringSpec
import uk.gov.dwp.dataworks.egress.domain.DataKeyResult
import uk.gov.dwp.dataworks.egress.services.DataKeyService
import kotlin.time.ExperimentalTime


@ExperimentalTime
class DksEncryptionMaterialsProviderTest: StringSpec() {

    init {
        "testGetEncryptionMaterialsForEncryption()" {
            val dataKeyResult = DataKeyResult("keyId", "plainTextKey", "cipher")
            val keyService = mock<DataKeyService> {
                on { batchDataKey() } doReturn dataKeyResult
            }
            val dksEncryptionMaterialsProvider = DksEncryptionMaterialsProvider(keyService)
            val map = mutableMapOf<String, String>()
            dksEncryptionMaterialsProvider.getEncryptionMaterials(map)
            verify(keyService, times(1)).batchDataKey()
        }

        "testGetEncryptionMaterialsForDecryption()" {
            val keyId = "keyid"
            val encryptedKey = "encryptedkey"
            val keyService = mock<DataKeyService> {
                on { decryptKey(keyId, encryptedKey) } doReturn "plainTextKey"
            }
            val dksEncryptionMaterialsProvider = DksEncryptionMaterialsProvider(keyService)
            val map = mutableMapOf<String, String>()
            map.put("keyid", keyId)
            map.put("encryptedkey", encryptedKey)
            dksEncryptionMaterialsProvider.getEncryptionMaterials(map)
            verify(keyService, times(1)).decryptKey(keyId, encryptedKey)
        }

    }

}
