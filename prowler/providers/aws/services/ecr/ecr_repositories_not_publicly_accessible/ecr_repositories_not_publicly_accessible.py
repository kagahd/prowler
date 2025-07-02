from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ecr.ecr_client import ecr_client


class ecr_repositories_not_publicly_accessible(Check):

    organizations_trusted_ids = ecr_client.audit_config.get("organizations_trusted_ids", [])

    def execute(self):
        findings = []
        for registry in ecr_client.registries.values():
            for repository in registry.repositories:
                report = Check_Report_AWS(self.metadata(), resource=repository)
                report.region = repository.region
                report.resource_id = repository.name
                report.resource_arn = repository.arn
                report.resource_tags = repository.tags
                report.status = "PASS"
                report.status_extended = (
                    f"Repository {repository.name} is not publicly accessible."
                )
                if repository.policy:
                    for statement in repository.policy["Statement"]:
                        if statement["Effect"] == "Allow":
                            if "*" in statement["Principal"] or (
                                "AWS" in statement["Principal"]
                                and "*" in statement["Principal"]["AWS"]
                            ):
                                if "Condition" in statement:
                                    if self.is_condition_meets_idealo_requirements(
                                        condition=statement["Condition"], organizations_trusted_ids=self.organizations_trusted_ids
                                    ):
                                        report.status_extended = f"Repository {repository.name} is not publicly accessible because the condition of its policy meets idealo's minimum security requirements."
                                    else:
                                        report.status = "FAIL"
                                        report.status_extended = f"Repository {repository.name} is publicly accessible because the condition of its policy does not meet idealo's minimum security requirements."
                                        break
                                else:
                                    report.status = "FAIL"
                                    report.status_extended = f"Repository {repository.name} is publicly accessible because its policy allows anonymous users to perform actions (Principal: '*')."
                                    break

                findings.append(report)

        return findings

    @staticmethod
    def is_condition_meets_idealo_requirements(condition: dict, organizations_trusted_ids: list) -> bool:

        # Check for "aws:PrincipalOrgID" condition
        if (
            "StringEquals" not in condition
            or "aws:PrincipalOrgID" not in condition["StringEquals"]
        ):
            return False

        org_id = condition["StringEquals"]["aws:PrincipalOrgID"]
        if isinstance(org_id, str):
            return org_id in organizations_trusted_ids
        else:
            return all(value in organizations_trusted_ids for value in org_id)
