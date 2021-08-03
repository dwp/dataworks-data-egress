package uk.gov.dwp.dataworks.egress.services.impl

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.springframework.stereotype.Service
import uk.gov.dwp.dataworks.egress.domain.EncryptionResult
import uk.gov.dwp.dataworks.egress.services.CipherService
import java.security.*
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource.PSpecified
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

    override fun rsaEncrypt(key: String, plaintext: ByteArray): String {
        val algorithm = "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING"
        val keySpec = X509EncodedKeySpec(Base64.getDecoder().decode(key))
        val kf = KeyFactory.getInstance("RSA")
        val publicKey: RSAPublicKey = kf.generatePublic(keySpec) as RSAPublicKey

        val cipher = Cipher.getInstance(algorithm)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        return Base64.getEncoder().encodeToString(cipher.doFinal(plaintext))
    }

    override fun rsaDecrypt(key: String, encrypted: ByteArray): ByteArray {
        val keySpec = PKCS8EncodedKeySpec(Base64.getDecoder().decode(key))
        val kf = KeyFactory.getInstance("RSA")
        val privateKey: RSAPrivateKey = kf.generatePrivate(keySpec) as RSAPrivateKey

        val algorithm = "RSA/ECB/OAEPPadding"
        val cipher = Cipher.getInstance(algorithm)
        val oaepParams = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec("SHA-1"), PSpecified.DEFAULT)
        cipher.init(Cipher.DECRYPT_MODE, privateKey,oaepParams)
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
