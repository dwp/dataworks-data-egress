package uk.gov.dwp.dataworks.egress.services.impl

import com.nhaarman.mockitokotlin2.*
import io.kotest.core.spec.style.WordSpec
import io.kotest.matchers.collections.shouldContainInOrder
import io.kotest.matchers.shouldBe
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.withTimeoutOrNull
import software.amazon.awssdk.services.sqs.SqsAsyncClient
import software.amazon.awssdk.services.sqs.model.*
import java.util.concurrent.CompletableFuture
import kotlin.time.ExperimentalTime

@ExperimentalTime
class QueueServiceImplTest: WordSpec() {

    init {

        "QueueService" should {

            "emit a message when one appears on the queue" {

                val queueAttributesResponse = with(GetQueueAttributesResponse.builder()) {
                    attributes(mapOf(QueueAttributeName.APPROXIMATE_NUMBER_OF_MESSAGES to "1"))
                    build()
                }

                val noMessagesResponse = with(GetQueueAttributesResponse.builder()) {
                    attributes(mapOf(QueueAttributeName.APPROXIMATE_NUMBER_OF_MESSAGES to "0"))
                    build()
                }

                val message = with(Message.builder()) {
                    receiptHandle(SQS_RECEIPT_HANDLE)
                    body("""
                    {
                        "Records": [
                            {"s3": {"object": {"key": "$S3_OBJECT_KEY_1"}}},
                            {"s3": {"object": {"key": "$S3_OBJECT_KEY_2"}}}
                        ]
                    }
                """.trimIndent())
                    build()
                }

                val receiveMessageResponse = with(ReceiveMessageResponse.builder()) {
                    messages(message)
                    build()
                }

                val queueAttributesFuture = CompletableFuture.completedFuture(queueAttributesResponse)
                val noMessagesFuture = CompletableFuture.completedFuture(noMessagesResponse)
                val receiveMessageFuture = CompletableFuture.completedFuture(receiveMessageResponse)


                val sqs = mock<SqsAsyncClient> {
                    on { getQueueAttributes(any<GetQueueAttributesRequest>()) } doReturnConsecutively
                            List(10) { noMessagesFuture } + listOf(queueAttributesFuture, noMessagesFuture)
                    on { receiveMessage(any<ReceiveMessageRequest>()) } doReturn receiveMessageFuture
                }

                val queueService = QueueServiceImpl(sqs, SQS_QUEUE_URL, SQS_CHECK_INTERVAL)
                withTimeoutOrNull(100) {
                    queueService.incomingPrefixes().collect { (receiptHandle, keys) ->
                        receiptHandle shouldBe SQS_RECEIPT_HANDLE
                        keys shouldContainInOrder listOf(S3_OBJECT_KEY_1, S3_OBJECT_KEY_2)
                        verify(sqs, times(1)).receiveMessage(any<ReceiveMessageRequest>())
                    }
                }
            }
        }
    }

    companion object {
        private const val SQS_CHECK_INTERVAL = 1L
        private const val SQS_QUEUE_URL = "SQS_QUEUE_URL"
        private const val SQS_RECEIPT_HANDLE = "SQS_RECEIPT_HANDLE"
        private const val S3_OBJECT_KEY_1 = "S3_OBJECT_KEY_1"
        private const val S3_OBJECT_KEY_2 = "S3_OBJECT_KEY_2"
    }
}
