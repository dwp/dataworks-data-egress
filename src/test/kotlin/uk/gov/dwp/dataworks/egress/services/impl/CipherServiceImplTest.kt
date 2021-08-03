package uk.gov.dwp.dataworks.egress.services.impl

import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.util.*


class CipherServiceImplTest: StringSpec() {

    init {
        "Decrypting encrypted should give plaintext" {
            val cipherService = CipherServiceImpl(SecureRandom.getInstance("SHA1PRNG"), CIPHER_TRANSFORMATION_AES)
            val original = "Original unencrypted text that should come out of decrypt".toByteArray()
            val (initialisationVector, encrypted) = cipherService.encrypt(DATA_KEY, original)
            val decrypted = cipherService.decrypt(DATA_KEY, initialisationVector, encrypted)
            decrypted shouldBe original
        }

        "Wrong key should give wrong plaintext" {
            val cipherService = CipherServiceImpl(SecureRandom.getInstance("SHA1PRNG"), CIPHER_TRANSFORMATION_AES)
            val original = "Original unencrypted text that should come out of decrypt."
            val (initialisationVector, encrypted) = cipherService.encrypt(DATA_KEY, original.toByteArray())
            val decrypted = cipherService.decrypt(DATA_KEY.replace('c', 'd'), initialisationVector, encrypted)
            decrypted shouldNotBe original
        }

        "Wrong IV should give wrong plaintext" {
            val cipherService = CipherServiceImpl(SecureRandom.getInstance("SHA1PRNG"), CIPHER_TRANSFORMATION_AES)
            val original = "Original unencrypted text that should come out of decrypt."
            val (initialisationVector, encrypted) = cipherService.encrypt(DATA_KEY, original.toByteArray())
            val firstChar = initialisationVector[0]
            val decrypted =
                cipherService.decrypt(DATA_KEY, initialisationVector.replace(firstChar, firstChar + 1), encrypted)
            decrypted shouldNotBe original
        }

        "Decrypting RSA encrypted key should give plain text key" {
            val cipherService = CipherServiceImpl(SecureRandom.getInstance("SHA1PRNG"), CIPHER_TRANSFORMATION_RSA)
            val encryptedKey  = cipherService.rsaEncrypt(rsaPublicKey, "DATA_KEY".toByteArray())
            val decryptedKey  = cipherService.rsaDecrypt(rsaPrivateKey, Base64.getDecoder().decode(encryptedKey))
            decryptedKey shouldBe "DATA_KEY".toByteArray()
        }
    }

    companion object {
        private fun getRSAKeys(bitSize:Int): KeyPair{
            val kpg = KeyPairGenerator.getInstance("RSA")
            kpg.initialize(bitSize)
            return kpg.generateKeyPair()
        }
        private const val CIPHER_TRANSFORMATION_AES = "AES/CTR/NoPadding"
        private const val CIPHER_TRANSFORMATION_RSA = "RSA/ECB/0AEPWithSHA-256ANDMGF1Padding"
        private const val DATA_KEY = "czMQLgW/OrzBZwFV9u4EBA=="

        //Generate RSA Public and Private keys to test the rsaEncrypt and rsaDecrypt functions
        private val keyPair = getRSAKeys(4096)
        private val rsaPublicKey = Base64.getMimeEncoder().encodeToString(keyPair.public.encoded).replace("\n", "").replace("\r", "")
        private val rsaPrivateKey = Base64.getMimeEncoder().encodeToString(keyPair.private.encoded).replace("\n", "").replace("\r", "")
    }
}
