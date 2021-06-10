package uk.gov.dwp.dataworks.egress.domain

data class EgressSpecification(val sourceBucket: String,
                               val sourcePrefix: String,
                               val destinationBucket: String,
                               val destinationPrefix: String,
                               val transferType: String,
                               val decrypt: Boolean = false,
                               val compress: Boolean = false,
                               val compressionFormat: String?,
                               val roleArn: String?)

data class DataKeyResult(val dataKeyEncryptionKeyId: String, val plaintextDataKey: String, val ciphertextDataKey: String)

data class EncryptionResult(val initialisationVector: String, val encrypted: ByteArray) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as EncryptionResult

        if (initialisationVector != other.initialisationVector) return false
        if (!encrypted.contentEquals(other.encrypted)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = initialisationVector.hashCode()
        result = 31 * result + encrypted.contentHashCode()
        return result
    }
}
