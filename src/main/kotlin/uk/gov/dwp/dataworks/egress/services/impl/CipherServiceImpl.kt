package uk.gov.dwp.dataworks.egress.services.impl

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Service
import uk.gov.dwp.dataworks.egress.domain.EncryptionResult
import uk.gov.dwp.dataworks.egress.services.CipherService
import java.security.Key
import java.security.SecureRandom
import java.security.Security
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

@Service
class CipherServiceImpl(private val secureRandom: SecureRandom,
                        private val cipherTransformation: String): CipherService {

    init {
        Security.addProvider(BouncyCastleProvider())
    }

    override fun encrypt(key: String, plaintext: ByteArray): EncryptionResult {
        val initialisationVector = ByteArray(16).apply { secureRandom.nextBytes(this) }
        val keySpec: Key = SecretKeySpec(Base64.getDecoder().decode(key), "AES")
        val cipher = encryptingCipher(keySpec, initialisationVector)
        return EncryptionResult(Base64.getEncoder().encodeToString(initialisationVector), cipher.doFinal(plaintext))
    }

    override fun decrypt(key: String, initializationVector: String, encrypted: ByteArray): ByteArray {
        val keySpec: Key = SecretKeySpec(Base64.getDecoder().decode(key), "AES")
        val cipher = decryptingCipher(keySpec, Base64.getDecoder().decode(initializationVector))
        return cipher.doFinal(encrypted)
    }

    private fun encryptingCipher(key: Key, initialisationVector: ByteArray): Cipher =
        cipher(key, Cipher.ENCRYPT_MODE, initialisationVector)

    private fun decryptingCipher(key: Key, initialisationVector: ByteArray): Cipher =
        cipher(key, Cipher.DECRYPT_MODE, initialisationVector)

    private fun cipher(key: Key, mode: Int, initialisationVector: ByteArray): Cipher =
        Cipher.getInstance(cipherTransformation, "BC").apply {
            init(mode, key, IvParameterSpec(initialisationVector))
        }

}
