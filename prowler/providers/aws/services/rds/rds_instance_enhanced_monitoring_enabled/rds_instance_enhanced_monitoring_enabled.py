from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_enhanced_monitoring_enabled(Check):
    def execute(self):
        findings = []
        for db_instance_arn, db_instance in rds_client.db_instances.items():
            report = Check_Report_AWS(self.metadata())
            report.region = db_instance.region
            report.resource_id = db_instance.id
            report.resource_arn = db_instance_arn
            report.resource_tags = db_instance.tags
            if db_instance.enhanced_monitoring_arn:
                report.status = "PASS"
                report.status_extended = (
                    f"RDS Instance {db_instance.id} has enhanced monitoring enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"RDS Instance {db_instance.id} does not have enhanced monitoring enabled."

            findings.append(report)

        return findings
