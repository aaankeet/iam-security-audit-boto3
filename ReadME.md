# Automated AWS IAM Security Auditor

An event-driven, serverless security auditing tool built with **Terraform** and **Python (`boto3`)**. This project continuously monitors an AWS account for identity misconfigurations—specifically stale IAM access keys, console users without MFA, and overly permissive policies—and dispatches automated security alerts via Amazon SNS.

---

## Architecture

```text
+-------------------+       +-------------------+       +-------------------+

|   Amazon          |       |    AWS Lambda     |       |     AWS IAM       |
|   EventBridge     | ----> |   (auditor.py)    | ----> |  (Read-Only Scan) |
| (Daily Schedule)  |       |                   |       |                   |
+-------------------+       +-------------------+       +-------------------+
                                      |
                                      v
                            +-------------------+       +-------------------+

                            |    Amazon SNS     | ----> |  Security Team    |
                            |  (Alert Topic)    |       |  (Email / Slack)  |
                            +-------------------+       +-------------------+
```

### How It Works
1. **Scheduled Trigger:** Amazon EventBridge triggers the Lambda function every 24 hours.
2. **Least-Privilege Scan:** The Python script assumes an execution role restricted strictly to `iam:List*` and `iam:Get*` permissions.
3. **Security Checks:**
   * **[CRITICAL]** Detects IAM users with `AdministratorAccess` directly attached.
   * **[HIGH]** Identifies IAM users with console passwords enabled (`LoginProfile`) but no Multi-Factor Authentication (MFA) device registered.
   * **[MEDIUM]** Flags active IAM access keys exceeding the configured age threshold (default: `90` days).
4. **Alerting:** If any findings are detected, a formatted report is published to an Amazon SNS topic.

---

## Repository Structure

```text
iam-security-audit-boto3/
├── main.tf          # Core AWS infrastructure (Lambda, IAM, SNS, Policies, EventBridge)
├── variables.tf     # Input variables and configurable thresholds
├── terraform.tfvars # Assign values to variables
├── outputs.tf       # Exported ARNs and resource names
├── auditor.py       # Python Boto3 script for IAM inspection
└── README.md        # Project documentation
```

---

## Prerequisites

* **AWS Account** with permissions to deploy IAM, Lambda, SNS, and EventBridge resources.
* **AWS CLI** configured locally (`aws configure`).
* **Terraform** `>= 1.5.0` installed.
* **Python** `3.12` (for local testing/linting).

---

## Deployment Instructions

1. **Clone the repository:**
   ```bash
   git clone https://github.com
   cd iam-security-audit-boto3
   ```

2. **Initialize Terraform:**
   ```bash
   terraform init
   ```

3. **Review and deploy the infrastructure:**
   Replace `your-email@example.com` with the email address where you want to receive security alerts and make sure to rename `terraform.tfvars.example` to `terraform.tfvars`.
   ```bash
   terraform apply
   ```

4. **Confirm SNS Subscription:**
   Check your inbox for an email from **AWS Notifications** and click **Confirm subscription** to activate alerting.

---

## Testing & Verification

To verify the auditor works without waiting 24 hours:

1. **Create a test user** (console access enabled, no MFA, or `AdministratorAccess` attached) in your sandbox AWS account.
2. **Manually invoke the Lambda function:**
   ```bash
   aws lambda invoke \
     --function-name lambda_iam_auditor \
     --payload '{}' \
     response.json

   cat response.json
   ```
3. **Verify the alert:** You should receive an email containing the severity-tagged findings within seconds.
4. **Delete the test user** once verification is complete.

---

## Cleanup

To tear down all deployed resources and avoid any ongoing AWS charges:

```bash
terraform destroy
```

---

## Security & Design Decisions

* **Principle of Least Privilege:** The Lambda execution role is scoped exclusively to the exact `iam:List*`, `iam:Get*`, and `sns:Publish` actions required to run the audit. No write or delete permissions are granted to IAM.
* **Zero Hardcoded Secrets:** All configuration values (such as the SNS Topic ARN and maximum key age) are injected dynamically via Lambda environment variables managed by Terraform.
* **Serverless Cost Efficiency:** Runs entirely within the AWS Free Tier for standard accounts, incurring zero idle compute costs.

---

## Future Enhancements

* [ ] Integrate **AWS IAM Access Analyzer** to detect unused permissions based on CloudTrail logs.
* [ ] Add an optional `AUTO_REMEDIATE` flag to automatically deactivate access keys older than 120 days.
* [ ] Format alert payloads for **Slack** or **Microsoft Teams** webhooks using AWS Chatbot.
