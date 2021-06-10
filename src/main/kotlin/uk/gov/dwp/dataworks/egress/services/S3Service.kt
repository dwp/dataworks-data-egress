package uk.gov.dwp.dataworks.egress.services

import uk.gov.dwp.dataworks.egress.domain.EgressSpecification

interface S3Service {
    suspend fun egressObjects(specifications: List<EgressSpecification>): Boolean
    suspend fun egressObjects(specification: EgressSpecification): Boolean
}
