package uk.gov.dwp.dataworks.egress.services.impl

import com.nhaarman.mockitokotlin2.*
import io.kotest.core.spec.style.WordSpec
import io.kotest.matchers.collections.shouldContainExactly
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient
import software.amazon.awssdk.services.dynamodb.model.AttributeValue
import software.amazon.awssdk.services.dynamodb.model.ScanRequest
import software.amazon.awssdk.services.dynamodb.model.ScanResponse
import uk.gov.dwp.dataworks.egress.domain.EgressSpecification
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.CompletableFuture

class DbServiceImplTest: WordSpec() {
    init {
        "DbService" should {

            "page for all items, returning matches, filtering non-matches" {
                val receivedPrefix = "source/prefix/pipeline_success.flag"
                val matchingPrefix = "source/prefix/"
                val matchingItem = egressTableItem(matchingPrefix)
                val nonMatchingItem = egressTableItem("non/matching/prefix")

                val scanResponse1 = with(ScanResponse.builder()) {
                    items(nonMatchingItem)
                    lastEvaluatedKey(mapOf(SOURCE_PREFIX_KEY to attributeValue(LAST_EVALUATED_KEY)))
                    build()
                }

                val scanResponse2 = with(ScanResponse.builder()) {
                    items(matchingItem)
                    build()
                }

                val scanFuture1 = CompletableFuture.completedFuture(scanResponse1)
                val scanFuture2 = CompletableFuture.completedFuture(scanResponse2)
                val dynamoDb = mock<DynamoDbAsyncClient> {
                    on { scan(any<ScanRequest>()) } doReturnConsecutively listOf(scanFuture1, scanFuture2)
                }
                val dbService = DbServiceImpl(dynamoDb, DATA_EGRESS_TABLE)
                val entries = dbService.tableEntryMatches(receivedPrefix)
                entries shouldContainExactly listOf(egressSpecification(matchingPrefix))
                verify(dynamoDb, times(2)).scan(any<ScanRequest>())
                verifyNoMoreInteractions(dynamoDb)
            }

            "match items with today's date" {
                val interpolatedPrefix = "source/prefix/${todaysDate()}"
                val receivedPrefix = "$interpolatedPrefix/pipeline_success.flag"
                val matchingPrefix = "source/prefix/$TODAYS_DATE_PLACEHOLDER/"

                val matchingItem = egressTableItem(matchingPrefix)
                val scanResponse = with(ScanResponse.builder()) {
                    items(matchingItem)
                    build()
                }
                val scanFuture = CompletableFuture.completedFuture(scanResponse)
                val dynamoDb = mock<DynamoDbAsyncClient> {
                    on { scan(any<ScanRequest>()) } doReturn scanFuture
                }
                val dbService = DbServiceImpl(dynamoDb, DATA_EGRESS_TABLE)
                val entries = dbService.tableEntryMatches(receivedPrefix)
                entries shouldContainExactly listOf(egressSpecification("$interpolatedPrefix/"))
            }

            "match items with wildcard" {
                val interpolatedPrefix = "source/prefix/${todaysDate()}"
                val receivedPrefix = "$interpolatedPrefix/pipeline_success.flag"
                val matchingPrefix = "source/prefix/$TODAYS_DATE_PLACEHOLDER/*"

                val matchingItem = egressTableItem(matchingPrefix)
                val scanResponse = with(ScanResponse.builder()) {
                    items(matchingItem)
                    build()
                }
                val scanFuture = CompletableFuture.completedFuture(scanResponse)
                val dynamoDb = mock<DynamoDbAsyncClient> {
                    on { scan(any<ScanRequest>()) } doReturn scanFuture
                }
                val dbService = DbServiceImpl(dynamoDb, DATA_EGRESS_TABLE)
                val entries = dbService.tableEntryMatches(receivedPrefix)
                entries shouldContainExactly listOf(egressSpecification("$interpolatedPrefix/"))
            }

        }
    }

    private fun egressSpecification(matchingPrefix: String) = EgressSpecification(
        SOURCE_BUCKET, matchingPrefix, DESTINATION_BUCKET, DESTINATION_PREFIX, TRANSFER_TYPE, false, false, null, null, PIPELINE_NAME, RECIPIENT


    )

    private fun egressTableItem(matchingPrefix: String) = mapOf(
        SOURCE_PREFIX_KEY to attributeValue(matchingPrefix),
        DESTINATION_PREFIX_KEY to attributeValue(DESTINATION_PREFIX),
        SOURCE_BUCKET_KEY to attributeValue(SOURCE_BUCKET),
        DESTINATION_BUCKET_KEY to attributeValue(DESTINATION_BUCKET),
        TRANSFER_TYPE_KEY to attributeValue(TRANSFER_TYPE)).toMutableMap()


    companion object {
        private fun attributeValue(matchingPrefix: String) = AttributeValue.builder().s(matchingPrefix).build()
        private fun todaysDate() = SimpleDateFormat("yyyy-MM-dd").format(Date())

        private const val DATA_EGRESS_TABLE = "DATA_EGRESS_TABLE"
        private const val SOURCE_PREFIX_KEY: String = "source_prefix"
        private const val SOURCE_BUCKET_KEY: String = "source_bucket"
        private const val DESTINATION_BUCKET_KEY: String = "destination_bucket"
        private const val DESTINATION_PREFIX_KEY: String = "destination_prefix"
        private const val TRANSFER_TYPE_KEY: String = "transfer_type"
        private const val TODAYS_DATE_PLACEHOLDER = "\$TODAYS_DATE"
        private const val PIPELINE_NAME = "PIPELINE_NAME"
        private const val RECIPIENT = "RECIPIENT"

        private const val SOURCE_BUCKET = "source"
        private const val DESTINATION_BUCKET = "destination"
        private const val TRANSFER_TYPE = "S3"
        private const val DESTINATION_PREFIX = "destination/prefix"
        private const val LAST_EVALUATED_KEY = "LAST_EVALUATED_KEY"
    }
}
