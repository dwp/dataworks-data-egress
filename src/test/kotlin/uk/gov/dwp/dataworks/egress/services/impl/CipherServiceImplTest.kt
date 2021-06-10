package uk.gov.dwp.dataworks.egress.services.impl

import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import java.security.SecureRandom

class CipherServiceImplTest: StringSpec() {

    init {
        "testEncryptionDecryption" {
            val cipherService = CipherServiceImpl(SecureRandom.getInstance("SHA1PRNG"), CIPHER_TRANSFORMATION)
            val key = "czMQLgW/OrzBZwFV9u4EBA=="
            val original = "Original unencrypted text that should come out of decrypt".toByteArray()
            val (initialisationVector, encrypted) = cipherService.encrypt(key, original)
            val decrypted = cipherService.decrypt(key, initialisationVector, encrypted)
            decrypted shouldBe original
        }

        "testWrongKey" {
            val cipherService = CipherServiceImpl(SecureRandom.getInstance("SHA1PRNG"), CIPHER_TRANSFORMATION)
            val key = "czMQLgW/OrzBZwFV9u4EBA=="
            val original = "Original unencrypted text that should come out of decrypt."
            val (initialisationVector, encrypted) = cipherService.encrypt(key, original.toByteArray())
            val decrypted = cipherService.decrypt(key.replace('c', 'd'), initialisationVector, encrypted)
            decrypted shouldNotBe original
        }

        "wrongIv" {
            val cipherService = CipherServiceImpl(SecureRandom.getInstance("SHA1PRNG"), CIPHER_TRANSFORMATION)
            val key = "czMQLgW/OrzBZwFV9u4EBA=="
            val original = "Original unencrypted text that should come out of decrypt."
            val (initialisationVector, encrypted) = cipherService.encrypt(key, original.toByteArray())
            val firstChar = initialisationVector[0]
            val decrypted =
                cipherService.decrypt(key, initialisationVector.replace(firstChar, firstChar + 1), encrypted)
            decrypted shouldNotBe original
        }

    }

    companion object {
        private const val CIPHER_TRANSFORMATION = "AES/CTR/NoPadding"
    }
}
