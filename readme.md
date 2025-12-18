# AWS IAM Policy Analyzer

**AWS IAM Policy Analyzer** is a Rust-based command-line tool designed to detect weak or risky IAM permissions and policy misconfigurations in AWS accounts. It analyzes **user and group policies** (both inline and attached) to identify potential privilege escalation paths, overly broad permissions, and dangerous administrative actions.

---
## Installation

### Prerequisites
- Rust (stable) — install via https://rustup.rs
- AWS CLI configured **or** valid AWS access keys
- Permissions to read IAM policies (e.g., `iam:List*`, `iam:Get*`)

### Setup
Clone the repository and build the project:

```bash
  git clone https://github.com/your-username/iam-misconfiguration-detector.git

  cd iam-misconfiguration-detector
  cargo build --release
```
## Run 
Execute the detector:
```
  cargo run
```

## Features / Capabilities

- Extracts and analyzes all IAM policies for a given user, including:
  - **Attached user policies**  
  - **Inline user policies**  
  - **Attached group policies**  
  - **Inline group policies**  
- Detects risky or weak permissions such as:
  - Wildcards in actions/resources (`*`)  
  - Privilege escalation opportunities (e.g., `iam:PassRole` + compute creation)  
  - Key and secret management risks (access keys, KMS grants)  
  - Dangerous actions on S3 buckets and objects  
  - Lambda function misconfigurations (Invoke, UpdateCode)  
  - CloudTrail or CloudWatch log deletion  
- Ignores statements with `Effect: Deny` and focuses only on actionable `Allow` statements  
- Outputs findings with:
  - Severity (CRITICAL, HIGH, MEDIUM, LOW)  
  - Impact and remediation guidance  
  - Policy category (attached user, inline user, attached group, inline group)  
  - Matched risky actions  

---

Example output:
```
  [CRITICAL] 10
    Rule: Policy allows all actions or resources using wildcard (*)
    Impact: Principal has unrestricted access to all AWS services and resources
    Remediation: Replace wildcards with least-privilege actions and resources; add conditions
    Policy category: attached_user_policies
    Matched patterns: Action:*, Resource:*
```
