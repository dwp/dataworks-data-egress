package uk.gov.dwp.dataworks.egress.services

import kotlinx.coroutines.flow.Flow
import software.amazon.awssdk.services.sqs.model.DeleteMessageResponse

interface QueueService {
    fun incomingPrefixes(): Flow<Pair<String, List<String>>>
    suspend fun deleteMessage(receiptHandle: String): DeleteMessageResponse
}
