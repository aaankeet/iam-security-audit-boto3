import boto3
import os
from datetime import datetime, timezone


iam = boto3.client('iam')
sns = boto3.client('sns')

SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']
MAX_KEY_AGE_DAYS = int(os.environ.get('MAX_KEY_AGE_DAYS', 90))
MAX_KEY_UNUSED_DAYS = int(os.environ.get('MAX_KEY_UNUSED_DAYS',90))
ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"

def lambda_handler(event,context):
    findings= []
    now = datetime.now(timezone.utc)

    # Paginate through all IAM Users
    paginator = iam.get_paginator('list_users')
    for page in paginator.paginate():
        for user in page['Users']:
            username = user['UserName']

            # 1. Check for MFA devices on console users
            mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']
            try:
                iam.get_login_profile(UserName=username)
                has_console_access = True
            except iam.exceptions.NoSuchEntityException:
                has_console_access = False

            if has_console_access and not mfa_devices:
                findings.append(f"[HIGH] User '{username}' has console access without MFA'")

            # 2. Check Access Key age
            keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
            for key in keys:
                if key['Status'] == 'Active':
                    age =(now - key['CreateDate']).days
                    if age > MAX_KEY_AGE_DAYS:
                        findings.append(f"[MEDIUM] User '{username}' has an active key({key['AccessKeyId']}) aged {age} days.")

            # 3. Check Unused access key
            for key in keys:
                if key['Status'] != "Active":
                    continue

                access_key_id = key['AccessKeyId']
                response = iam.get_access_key_last_used(AccessKeyId=access_key_id)
                last_used = response['AccessKeyLastUsed'].get('LastUsedDate')

                if last_used:
                    days_unused = (datetime.now(timezone.utc)- last_used).days
                    if days_unused > MAX_KEY_UNUSED_DAYS:
                     findings.append(f"[MEDIUM] User '{username}' has key ({access_key_id}) not used for more than {MAX_KEY_UNUSED_DAYS} days."
                         f"Last used {days_unused} days ago."
                         )
                elif (now - key['CreateDate']).days > MAX_KEY_UNUSED_DAYS:
                    findings.append(f"[MEDIUM] User '{username}' has an active key"
                        f"({access_key_id} with no recorded usage.)"
                    )

            # 4. Check of AdministratorAccess policy attachments
            attached_policies = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
            for policy in attached_policies:
                if policy['PolicyArn'] == ADMIN_POLICY_ARN:
                    findings.append(f"[CRITICAL] User '{username}' has direct AdministratorAccess attached.")

            # 5 Check if User inherits AdministratroAccess through Groups
            groups = iam.list_groups_for_user(UserName=username)["Groups"]
            for group in groups:
                group_name = group["GroupName"]
                group_policies = iam.list_attached_group_policies(GroupName=group_name)["AttachedPolicies"]
                for policy in group_policies:
                    if policy["PolicyArn"] == ADMIN_POLICY_ARN:
                        findings.append(f"[CRITICAL] User '{username}' inherits "
                            f"AdministratorAccess through group "
                            f"'{group_name}'."
                        )
            # 6 Check In-line policies for broader permission
            # this only detects explicit wildcard grants, not complete administrator privilege detection.
            user_inline_policies = iam.list_user_policies(UserName=username)['PolicyNames']
            for policy_name in user_inline_policies:
                policy_document = iam.get_user_policy(UserName=username,PolicyName=policy_name)['PolicyDocument']

                statements = policy_document.get("Statement",[])
                # Normalize a single statement into a list
                if isinstance(statements, dict):
                    statements = [statements]

                for statement in statements:
                    if statement.get("Effect") != "Allow":
                        continue

                    actions = statement.get("Action",[])
                    resources = statement.get("Resource",[])

                    # Normalize strings into lists
                    if isinstance(actions, str):
                        actions = [actions]

                    if isinstance(resources, str):
                        resources = [resources]

                    has_wildcard_action = any(action == "*" or action.endswith(":*")
                        for action in actions)
                    has_wildcard_resource = "*" in resources

                    if  has_wildcard_action  and has_wildcard_resource:
                        findings.append(f"[Critical] User {username} has inline policy {policy_name}"
                            f"granting wildcards."
                            )

    # Publish report if there are any findings
    if findings:
        report = ( "AWS IAM Security Audit Report:\n\n" + "\n\n".join(findings))
        sns.publish(
            TopicArn = SNS_TOPIC_ARN,
            Subject = "AWS IAM Security Audit Findings",
            Message = report
        )
        return {"status":"Findings reported", "count": len(findings)}

    return {"status": "Clean", "count": 0}
