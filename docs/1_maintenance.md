# Overview

Maintaining an AWS Organization necessitates recurring review, particularly in regards to security and cost. This document outlines those responsibilities at a high level.

## Continously
- All security admins listed in the security_notifications var, team members listed as a contact in AWS Incident Response, and those monitoring the shared AWS email account (the `base_email` inbox) should watch carefully for security-related emails from AWS and respond as quickly as possible if any are received

## Weekly
- Brief review of Security Hub CSPM, ensuring no new unexpected Critical findings
- Brief review of Incident Response
- Brief review of Cost Explorer

## Monthly
- Review of Cost Explorer and cost alerts defined in Terraform
- Review user access, remove inactive users, ensure least privilege
- Review Security Hub CSPM
- Ensure CloudTrail is functioning as expected: all accounts are logging to Log_Archive

## Quarterly
- Detailed review of Cost Explorer and cost alerts defined in Terraform. In particular, review Savings Plans and Cost Optimization Hub.
- Detailed review of access to the Github repository holding this code. Changes made there directly modify your AWS Organization; access should be tightly controlled, PRs to main should require specific approvals.
- Detailed review user access
- Detailed review Security Hub CSPM
- Review OIDC connections allowed
- Review CloudTrail log storage costs and its related S3 policies.
- Review S3 and CloudWatch costs org-wide. These costs often grow unchecked.
- Review AWS Organizations and accounts: deprovision unused accounts, ensure guardrails are in place, ensure no accounts were created outside of Terraform

## Semi-Annually

- Review guardrails: SCPs, RCPs, declarative, etc. The AWS Agent Toolkit (https://github.com/aws/agent-toolkit-for-aws) in combination with an LLM can help find new guardrails that might be useful to add.
- Review Savings Plan and/or Reserve Instance contract expirations
- Review Trusted Advisor in important accounts
- Review root user access: ensure each Core Infrastructure and Security team member has access to the email account, password, and that their MFA is functioning.
