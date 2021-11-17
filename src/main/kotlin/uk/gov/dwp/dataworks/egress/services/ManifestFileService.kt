package uk.gov.dwp.dataworks.egress.services

import uk.gov.dwp.dataworks.egress.domain.EgressSpecification

interface ManifestFileService {
    suspend fun egressManifestFile(specification: EgressSpecification): Pair<String, Boolean>
}
