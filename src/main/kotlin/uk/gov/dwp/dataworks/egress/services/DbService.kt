package uk.gov.dwp.dataworks.egress.services

import kotlinx.coroutines.flow.Flow
import software.amazon.awssdk.services.dynamodb.model.AttributeValue
import uk.gov.dwp.dataworks.egress.domain.EgressSpecification

interface DbService {
    suspend fun tableEntryMatches(prefix: String): List<EgressSpecification>
}
