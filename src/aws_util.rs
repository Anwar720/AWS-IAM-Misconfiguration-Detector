use aws_sdk_iam::{Client, Error};
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use serde_json::{json, Value};
use urlencoding::decode;

/// Struct to store user credentials
pub struct AwsCredentials {
    pub access_key: String,
    pub secret_key: String,
    pub region: String,
}

/// Ask the user for AWS credentials
pub fn ask_for_credentials() -> AwsCredentials {
    let mut access_key = String::new();
    let mut secret_key = String::new();
    let mut region = String::new();

    print!("Enter AWS Access Key: ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut access_key).unwrap();

    print!("Enter AWS Secret Key: ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut secret_key).unwrap();

    print!("Enter AWS Region (e.g. us-east-1): ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut region).unwrap();

    AwsCredentials {
        access_key: access_key.trim().to_string(),
        secret_key: secret_key.trim().to_string(),
        region: region.trim().to_string(),
    }
}

/// Extract IAM policies for a specific user.
/// Returns a JSON object with policies.
pub async fn extract_user_policies_from_aws(
    user_name: &str,
    client: &Client,
) -> Result<Value, Error> {
    // Create policy directory if missing
    let policy_dir = Path::new("./policies");
    if !policy_dir.exists() {
        if let Err(e) = fs::create_dir_all(policy_dir) {
            eprintln!("Failed to create policies directory: {}", e);
        }
    }

    let mut results = json!({
        "user": user_name,
        "attached_user_policies": [],
        "inline_user_policies": [],
        "attached_group_policies": [],
        "inline_group_policies": [],
    });

    // ---------------- User Attached Policies ----------------
    if let Ok(attached_user) = client
        .list_attached_user_policies()
        .user_name(user_name)
        .send()
        .await
    {
        for p in attached_user.attached_policies() {
            if let Some(arn) = &p.policy_arn {
                if let Ok(policy) = client.get_policy().policy_arn(arn).send().await {
                    if let Some(policy_obj) = policy.policy {
                        if let Some(version_id) = policy_obj.default_version_id {
                            if let Ok(version) = client
                                .get_policy_version()
                                .policy_arn(arn)
                                .version_id(version_id)
                                .send()
                                .await
                            {
                                if let Some(encoded) = &version.policy_version.unwrap().document {
                                    let decoded = decode(encoded).unwrap_or_else(|_| encoded.clone().into()).to_string();
                                    let doc_json: Value =
                                        serde_json::from_str(&decoded).unwrap_or(json!({"raw": decoded}));

                                    results["attached_user_policies"]
                                        .as_array_mut()
                                        .unwrap()
                                        .push(json!({
                                            "name": p.policy_name.clone().unwrap_or("unknown".to_string()),
                                            "arn": arn,
                                            "document": doc_json,
                                        }));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // ---------------- User Inline Policies ----------------
    if let Ok(inline_user) = client.list_user_policies().user_name(user_name).send().await {
        for name in inline_user.policy_names() {
            if let Ok(policy) = client
                .get_user_policy()
                .user_name(user_name)
                .policy_name(name)
                .send()
                .await
            {
                if let Ok(decoded) = decode(policy.policy_document()) {
                    let doc_json: Value =
                        serde_json::from_str(&decoded).unwrap_or(json!({"raw": decoded.to_string()}));

                    results["inline_user_policies"]
                        .as_array_mut()
                        .unwrap()
                        .push(json!({
                            "name": name,
                            "document": doc_json,
                        }));
                }
            }
        }
    }

    // ---------------- Group Policies ----------------
    if let Ok(groups) = client.list_groups_for_user().user_name(user_name).send().await {
        for g in groups.groups() {
            let group_name = g.group_name.clone();

            // Attached group policies
            if let Ok(attached_group) = client
                .list_attached_group_policies()
                .group_name(&group_name)
                .send()
                .await
            {
                for p in attached_group.attached_policies() {
                    if let Some(arn) = &p.policy_arn {
                        if let Ok(policy) = client.get_policy().policy_arn(arn).send().await {
                            if let Some(policy_obj) = policy.policy {
                                if let Some(version_id) = policy_obj.default_version_id {
                                    if let Ok(version) = client
                                        .get_policy_version()
                                        .policy_arn(arn)
                                        .version_id(version_id)
                                        .send()
                                        .await
                                    {
                                        if let Some(encoded) = &version.policy_version.unwrap().document {
                                            let decoded =
                                                decode(encoded).unwrap_or_else(|_| encoded.clone().into()).to_string();
                                            let doc_json: Value =
                                                serde_json::from_str(&decoded).unwrap_or(json!({"raw": decoded}));

                                            results["attached_group_policies"]
                                                .as_array_mut()
                                                .unwrap()
                                                .push(json!({
                                                    "group": group_name,
                                                    "name": p.policy_name.clone().unwrap_or("unknown".to_string()),
                                                    "arn": arn,
                                                    "document": doc_json,
                                                }));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Inline group policies
            if let Ok(inline_group) = client.list_group_policies().group_name(&group_name).send().await {
                for name in inline_group.policy_names() {
                    if let Ok(policy) = client
                        .get_group_policy()
                        .group_name(&group_name)
                        .policy_name(name)
                        .send()
                        .await
                    {
                        if let Ok(decoded) = decode(policy.policy_document()) {
                            let doc_json: Value =
                                serde_json::from_str(&decoded).unwrap_or(json!({"raw": decoded.to_string()}));

                            results["inline_group_policies"]
                                .as_array_mut()
                                .unwrap()
                                .push(json!({
                                    "group": group_name,
                                    "name": name,
                                    "document": doc_json,
                                }));
                        }
                    }
                }
            }
        }
    }

    Ok(results)
}