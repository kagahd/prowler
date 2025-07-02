from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.lib.policy import (
    is_condition_block_restrictive,
)
from prowler.providers.aws.services.sqs.sqs_client import sqs_client


class sqs_queues_not_publicly_accessible(Check):

    organizations_trusted_ids = sqs_client.audit_config.get("organizations_trusted_ids", [])

    def execute(self):
        findings = []
        for queue in sqs_client.queues:
            report = Check_Report_AWS(self.metadata(), resource=queue)
            report.region = queue.region
            report.resource_id = queue.id
            report.resource_arn = queue.arn
            report.resource_tags = queue.tags
            report.status = "PASS"
            report.status_extended = f"SQS queue {queue.name} is not public."
            if queue.policy:
                for statement in queue.policy["Statement"]:
                    # Only check allow statements
                    if statement["Effect"] == "Allow":
                        if "Principal" in statement and (
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
                                    statement["Condition"], sqs_client.audited_account
                                ) or self.is_condition_meets_idealo_requirements(
                                    statement["Condition"]
                                ):
                                    report.status_extended = f"SQS queue {queue.name} is not public because its policy allows access only from the same account or it meets idealo's minimum security requirements for public access."
                                else:
                                    report.status = "FAIL"
                                    report.status_extended = f"SQS queue {queue.name} is public because the condition of its policy does not limit access to resources within the same account or does not meet idealo's minimum security requirements for public access."
                                    break
                            else:
                                report.status = "FAIL"
                                report.status_extended = f"SQS queue {queue.name} is public because its policy allows public access."
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
            return org_id in sqs_queues_not_publicly_accessible.organizations_trusted_ids
        else:
            return all(value in sqs_queues_not_publicly_accessible.organizations_trusted_ids for value in org_id)
