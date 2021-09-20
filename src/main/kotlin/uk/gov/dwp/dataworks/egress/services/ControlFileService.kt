package uk.gov.dwp.dataworks.egress.services

import uk.gov.dwp.dataworks.egress.domain.EgressSpecification

interface ControlFileService {
    suspend fun egressControlFile(egressed: List<String>,
                                  specification: EgressSpecification): Pair<String, Boolean>
}
