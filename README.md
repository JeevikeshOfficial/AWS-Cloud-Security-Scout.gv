# Cloud Security Scout

**Cloud Security Scout** is a serverless Python tool for automated security auditing of your AWS environment. It runs as an AWS Lambda function, periodically scanning for common security misconfigurations across various services. Findings are classified by severity, stored in Amazon DynamoDB for tracking, and sent as alerts via Amazon SNS.

## Features

  - **Serverless & Automated:** Runs on a schedule using AWS Lambda and Amazon EventBridge, requiring no dedicated server.
  - **Multi-Service Coverage:** Scans a wide range of critical AWS services.
  - **Risk Prioritization:** Findings are classified into **CRITICAL, HIGH, MEDIUM,** and **LOW** severities to help you focus on the most important issues.
  - **Persistent Storage:** All findings are stored in a DynamoDB table, creating a historical audit trail.
  - **Real-time Notifications:** A summary of findings is published to an SNS topic for immediate alerts via email, SMS, or other integrations.

-----

## Architecture

The tool follows a simple, event-driven serverless architecture:

1.  **Amazon EventBridge** triggers the Lambda function on a defined schedule (e.g., daily).
2.  The **AWS Lambda** function, containing the Python script, executes and scans the configured AWS regions.
3.  The script uses the **AWS Boto3 SDK** to inspect services like IAM, S3, EC2, etc.
4.  Findings are written to an **Amazon DynamoDB** table for persistent storage and analysis.
5.  A summary report is published to an **Amazon SNS** topic, which then pushes the notification to all subscribers (e.g., a security team's email distribution list).

-----

## Security Checks Performed

Cloud Security Scout checks for the following misconfigurations:

  - **IAM (Identity and Access Management)**
      - Root account without MFA enabled.
      - IAM users without MFA configured.
      - Overly permissive IAM roles (`Action:*` on `Resource:*`).
  - **S3 (Simple Storage Service)**
      - Publicly accessible buckets.
    <!-- end list -->
      * "Block Public Access" feature not fully enabled.
    <!-- end list -->
      - Server-side encryption not enabled.
      - Access logging not enabled.
  - **EC2 (Elastic Compute Cloud)**
      - Security groups open to the internet (`0.0.0.0/0`).
      - EBS volumes not encrypted.
  - **RDS (Relational Database Service)**
      - Database instances that are publicly accessible.
      - Database storage not encrypted.
      - Backup retention period less than 7 days.
  - **VPC (Virtual Private Cloud)**
      - Default security group allowing all inbound traffic.
      - Network ACLs (NACLs) allowing all traffic.
  - **KMS (Key Management Service)**
      - KMS keys with key rotation disabled.
      - Overly broad KMS key policies.
  - **Lambda**
      - Functions with over-privileged IAM roles.
      - Functions not connected to a VPC.
  - **SNS (Simple Notification Service)**
      - Topics with public access policies.
      - Topics without server-side encryption enabled.

-----

## Setup and Deployment

### Prerequisites

  - An AWS Account.
  - AWS CLI configured with appropriate permissions to create the necessary resources.

### Step 1: Create the IAM Role and Policy

The Lambda function needs permissions to scan your resources. Create an IAM policy with the JSON below and attach it to a new IAM role for the Lambda function.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:GetAccountSummary",
                "iam:ListUsers",
                "iam:ListRoles",
                "iam:ListMFADevices",
                "iam:ListAttachedRolePolicies",
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "s3:ListAllMyBuckets",
                "s3:GetBucketLocation",
                "s3:GetBucketPolicyStatus",
                "s3:GetBucketLogging",
                "s3:GetEncryptionConfiguration",
                "s3:GetBucketPublicAccessBlock",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeVolumes",
                "ec2:DescribeNetworkAcls",
                "ec2:DescribeVpcEndpoints",
                "rds:DescribeDBInstances",
                "lambda:ListFunctions",
                "kms:ListKeys",
                "kms:DescribeKey",
                "kms:GetKeyPolicy",
                "kms:ListGrants",
                "sns:ListTopics",
                "sns:GetTopicAttributes",
                "dynamodb:PutItem",
                "sns:Publish",
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "*"
        }
    ]
}
```

### Step 2: Create a DynamoDB Table

Create a DynamoDB table to store the scan results.

  - **Table Name:** `CloudSecurityScoutResults`
  - **Primary Key:** `ScanID` (Type: String)

### Step 3: Create an SNS Topic

Create an SNS topic that will receive the alert summaries.

  - **Topic Name:** `SecurityAlerts`
  - After creating the topic, create a subscription (e.g., an email subscription) to receive the notifications.

### Step 4: Deploy the Lambda Function

1.  **Create a new Lambda function** in the AWS Console.
      - **Function name:** `CloudSecurityScout`
      - **Runtime:** Python 3.9 or later.
      - **Architecture:** x86\_64
      - **Execution role:** Choose "Use an existing role" and select the IAM role you created in Step 1.
2.  **Configure the Script:**
      - Download the Python script provided.
      - Update the global variables at the top of the script with your DynamoDB table name and SNS topic ARN if they are different from the defaults.
3.  **Upload the Code:**
      - Place the Python script in a ZIP file.
      - In the "Code source" section of your Lambda function, click **"Upload from"** and select **".zip file"**. Upload your ZIP file.
4.  **Configure General Settings:**
      - In the "Configuration" tab, go to "General configuration".
      - Set the **Timeout** to at least **5 minutes** to ensure the scan can complete.
5.  **Set Up a Trigger:**
      - In the function overview, click **"Add trigger"**.
      - Select **"EventBridge (CloudWatch Events)"**.
      - Choose "Create a new rule".
      - Give the rule a name (e.g., `DailySecurityScan`).
      - Select **"Schedule expression"** and set your desired schedule (e.g., `rate(1 day)` for a daily scan).
      - Click **"Add"**.

-----

## Usage

Once deployed and triggered, the function will run automatically.

  - **View Findings:** You can query the `CloudSecurityScoutResults` DynamoDB table to see all historical findings.
  - **Receive Alerts:** You will receive a summary of the findings at the email address you subscribed to the `SecurityAlerts` SNS topic.
