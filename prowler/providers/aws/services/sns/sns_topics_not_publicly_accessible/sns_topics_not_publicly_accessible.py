from importlib.metadata import metadata

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.lib.policy import (
    is_condition_block_restrictive,
)
from prowler.providers.aws.services.sns.sns_client import sns_client


class sns_topics_not_publicly_accessible(Check):

    organizations_trusted_ids = sns_client.audit_config.get("organizations_trusted_ids", [])

    def execute(self):
        findings = []
        for topic in sns_client.topics:
            report = Check_Report_AWS(metadata=self.metadata(), resource=topic)
            report.status = "PASS"
            report.status_extended = (
                f"SNS topic {topic.name} is not publicly accessible."
            )
            if topic.policy:
                for statement in topic.policy["Statement"]:
                    # Only check allow statements
                    if statement["Effect"] == "Allow":
                        if (
                            "*" in statement["Principal"]
                            or (
                                "AWS" in statement["Principal"]
                                and "*" in statement["Principal"]["AWS"]
                            )
                            or (
                                "CanonicalUser" in statement["Principal"]
                                and "*" in statement["Principal"]["CanonicalUser"]
                            )
                        ):
                            if "Condition" in statement:
                                if is_condition_block_restrictive(
                                    statement["Condition"], sns_client.audited_account
                                ) or self.is_condition_meets_idealo_requirements(
                                    statement["Condition"]
                                ):
                                    report.status_extended = f"SNS topic {topic.name} is not public because its policy allows access only from the same account or it meets idealo's minimum security requirements for public access."
                                else:
                                    report.status = "FAIL"
                                    report.status_extended = f"SNS topic {topic.name} is public because the condition of its policy does not limit access to resources within the same account or does not meet idealo's minimum security requirements for public access."
                                    break
                            else:
                                report.status = "FAIL"
                                report.status_extended = f"SNS topic {topic.name} is public because its policy allows public access."
                                break

            findings.append(report)

        return findings

    @staticmethod
    def is_condition_meets_idealo_requirements(condition):

        # Check for "aws:PrincipalArn" condition
        if (
            "ArnEquals" not in condition
            or "aws:PrincipalArn" not in condition["ArnEquals"]
        ):
            return False

        principal_arns = condition["ArnEquals"]["aws:PrincipalArn"]

        # Transform principal_arns to an array if it's a string
        if isinstance(principal_arns, str):
            principal_arns = [principal_arns]

        # Check each ARN for wildcards
        for arn in principal_arns:
            if any(wildcard in arn for wildcard in ("*", "?")):
                return False

        # Check for "aws:PrincipalOrgID" condition
        if (
            "StringEquals" not in condition
            or "aws:PrincipalOrgID" not in condition["StringEquals"]
        ):
            return False

        org_id = condition["StringEquals"]["aws:PrincipalOrgID"]
        if isinstance(org_id, str):
            return org_id in sns_topics_not_publicly_accessible.organizations_trusted_ids
        else:
            return all(value in sns_topics_not_publicly_accessible.organizations_trusted_ids for value in org_id)
