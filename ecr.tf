resource "aws_ecr_repository" "dataworks-data-egress" {
  name = "dataworks-data-egress"
  tags = merge(
    local.common_tags,
    { DockerHub : "dwpdigital/dataworks-data-egress" }
  )
}

resource "aws_ecr_repository_policy" "dataworks-data-egress" {
  repository = aws_ecr_repository.dataworks-data-egress.name
  policy     = data.terraform_remote_state.management.outputs.ecr_iam_policy_document
}

output "ecr_example_url" {
  value = aws_ecr_repository.dataworks-data-egress.repository_url
}
