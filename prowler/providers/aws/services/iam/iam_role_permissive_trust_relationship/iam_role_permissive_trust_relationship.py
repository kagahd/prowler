from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_role_permissive_trust_relationship(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        for role in iam_client.roles:
            if not role.is_service_role:  # Avoid service roles since they cannot be modified by the user
                report = Check_Report_AWS(self.metadata())
                report.region = iam_client.region
                report.resource_arn = role.arn
                report.resource_id = role.name
                report.resource_tags = role.tags
                report.status = "PASS"
                report.status_extended = (
                    f"IAM Role {role.name} does not have permissive trust relationship to other accounts."
                )
                permissive_trust_relationship_found = False

                # Check if the role has a list of statements or a single statement
                if isinstance(role.assume_role_policy["Statement"], list):
                    for statement in role.assume_role_policy["Statement"]:
                        if not permissive_trust_relationship_found:
                            permissive_trust_relationship_found = self.has_permissive_trust_relationship_statement(
                                permissive_trust_relationship_found, statement)
                        else:
                            break
                else:
                    statement = role.assume_role_policy["Statement"]
                    permissive_trust_relationship_found = self.has_permissive_trust_relationship_statement(
                        permissive_trust_relationship_found, statement)

                if permissive_trust_relationship_found:
                    report.status = "FAIL"
                    report.status_extended = f"IAM Role {role.name} has permissive trust relationship to other accounts"

                findings.append(report)

        return findings

    def has_permissive_trust_relationship_statement(self, permissive_trust_relationship: bool, statement: dict) -> bool:
        if statement["Effect"] == "Allow" and "AWS" in statement["Principal"]:
            # Check if the role has a list of AWS principals or a single principal
            if isinstance(statement["Principal"]["AWS"], list):
                for aws_account in statement["Principal"]["AWS"]:
                    if self.has_permissive_trust_relationship(aws_account):
                        permissive_trust_relationship = True
                        break
            else:
                if self.has_permissive_trust_relationship(statement["Principal"]["AWS"]):
                    permissive_trust_relationship = True

        # check if the statement allows to assume the role into the audited account (sts:AssumeRole)
        permissive_trust_relationship = self.has_assume_role_permission_assigned(permissive_trust_relationship,
                                                                                 statement)

        # check if a condition is present and if it restricts the trust relationship
        permissive_trust_relationship = self.contains_statement_conditions(permissive_trust_relationship, statement)

        return permissive_trust_relationship

    @staticmethod
    def contains_statement_conditions(permissive_trust_relationship: bool, statement: dict) -> bool:
        # check if a condition is present and if it restricts the trust relationship
        # https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html
        if permissive_trust_relationship and "Condition" in statement:
            if "StringEquals" in statement["Condition"]:
                if "sts:ExternalId" in statement["Condition"]["StringEquals"]:
                    permissive_trust_relationship = False
        return permissive_trust_relationship

    @staticmethod
    def has_assume_role_permission_assigned(permissive_trust_relationship: bool, statement: dict) -> bool:
        # check if the statement allows to assume the role into the audited account (sts:AssumeRole)
        has_assume_role_permission = False
        if permissive_trust_relationship and "Action" in statement:
            if isinstance(statement["Action"], list):
                for action in statement["Action"]:
                    if "sts:AssumeRole" == action:
                        has_assume_role_permission = True
                        break
            else:
                if "sts:AssumeRole" in statement["Action"]:
                    has_assume_role_permission = True

            if not has_assume_role_permission:
                permissive_trust_relationship = False

        return permissive_trust_relationship

    @staticmethod
    def has_permissive_trust_relationship(aws_account: str) -> bool:
        return (
            # Check if any account is allowed to assume the role
            "*" == aws_account
            or
            # Check if cross account access is allowed for any role in the cross account
            (
                    aws_account.startswith("arn:aws:iam::")
                    and aws_account.endswith(":root")
            )
            or
            # Check if the value is digits only (account ID) a shortened form that
            # allows an entire account to assume the role
            aws_account.isdigit()
        )
