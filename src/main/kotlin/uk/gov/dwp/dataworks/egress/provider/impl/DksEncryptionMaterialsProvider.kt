package uk.gov.dwp.dataworks.egress.provider.impl

import com.amazonaws.services.s3.model.EncryptionMaterials
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider
import org.springframework.stereotype.Component
import uk.gov.dwp.dataworks.egress.services.DataKeyService
import uk.gov.dwp.dataworks.logging.DataworksLogger
import java.util.*
import javax.crypto.spec.SecretKeySpec

@Component
class DksEncryptionMaterialsProvider(private val dataKeyService: DataKeyService): EncryptionMaterialsProvider {

    override fun getEncryptionMaterials(materialsDescription: MutableMap<String, String>?): EncryptionMaterials {
        if (materialsDescription == null) {
            logger.info("Received null materials, using default")
            return encryptionMaterials
        }
        val keyId = materialsDescription[METADATA_KEYID]
        val encryptedKey = materialsDescription[METADATA_ENCRYPTED_KEY]
        logger.info("Received encryption materials", "keyId" to (keyId ?: ""), "encryptedKey" to (encryptedKey ?: ""))
        return if (null == keyId && null == encryptedKey) {
            encryptionMaterials
        } else {
            getMaterialForDecryption(keyId!!, encryptedKey!!)
        }
    }

    override fun getEncryptionMaterials(): EncryptionMaterials {
        val dataKeyResult = dataKeyService.batchDataKey()
        val decodeKey = Base64.getDecoder().decode(dataKeyResult.plaintextDataKey)
        val secretKeySpec = SecretKeySpec(decodeKey, 0, decodeKey.size, ALGORITHM)
        val keyId = dataKeyResult.dataKeyEncryptionKeyId
        val cipherKey = dataKeyResult.ciphertextDataKey
        return EncryptionMaterials(secretKeySpec)
            .addDescription(METADATA_KEYID, keyId)
            .addDescription(METADATA_ENCRYPTED_KEY, cipherKey)
    }

    override fun refresh() {}

    private fun getMaterialForDecryption(keyId: String, encryptedKey: String): EncryptionMaterials {
        val decryptedKey = dataKeyService.decryptKey(keyId, encryptedKey)
        val decodeKey = Base64.getDecoder().decode(decryptedKey)
        val secretKeySpec = SecretKeySpec(decodeKey, 0, decodeKey.size, ALGORITHM)
        return EncryptionMaterials(secretKeySpec)
    }

    companion object {
        private val logger: DataworksLogger = DataworksLogger.getLogger(DksEncryptionMaterialsProvider::class.java)
        private const val ALGORITHM = "AES"
        private const val METADATA_KEYID = "keyid"
        private const val METADATA_ENCRYPTED_KEY = "encryptedkey"
    }
}
