#![doc = "generated by AutoRust 0.1.0"]
#![allow(non_camel_case_types)]
#![allow(unused_imports)]
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConfluentAgreementProperties {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan: Option<String>,
    #[serde(rename = "licenseTextLink", skip_serializing_if = "Option::is_none")]
    pub license_text_link: Option<String>,
    #[serde(rename = "privacyPolicyLink", skip_serializing_if = "Option::is_none")]
    pub privacy_policy_link: Option<String>,
    #[serde(rename = "retrieveDatetime", skip_serializing_if = "Option::is_none")]
    pub retrieve_datetime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted: Option<bool>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConfluentAgreementResource {
    #[serde(skip_serializing)]
    pub id: Option<String>,
    #[serde(skip_serializing)]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing)]
    pub type_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<ConfluentAgreementProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConfluentAgreementResourceListResponse {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<ConfluentAgreementResource>,
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OperationDisplay {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OperationResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<OperationDisplay>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OperationListResult {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<OperationResult>,
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ErrorResponseBody {
    #[serde(skip_serializing)]
    pub code: Option<String>,
    #[serde(skip_serializing)]
    pub message: Option<String>,
    #[serde(skip_serializing)]
    pub target: Option<String>,
    #[serde(skip_serializing)]
    pub details: Vec<ErrorResponseBody>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceProviderDefaultErrorResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorResponseBody>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ProvisioningState {
    Accepted,
    Creating,
    Updating,
    Deleting,
    Succeeded,
    Failed,
    Canceled,
    Deleted,
    NotSpecified,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum SaaSOfferStatus {
    Started,
    PendingFulfillmentStart,
    InProgress,
    Subscribed,
    Suspended,
    Reinstated,
    Succeeded,
    Failed,
    Unsubscribed,
    Updating,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OfferDetail {
    #[serde(rename = "publisherId", skip_serializing_if = "Option::is_none")]
    pub publisher_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "planId", skip_serializing_if = "Option::is_none")]
    pub plan_id: Option<String>,
    #[serde(rename = "planName", skip_serializing_if = "Option::is_none")]
    pub plan_name: Option<String>,
    #[serde(rename = "termUnit", skip_serializing_if = "Option::is_none")]
    pub term_unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<SaaSOfferStatus>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UserDetail {
    #[serde(rename = "firstName", skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(rename = "lastName", skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(rename = "emailAddress", skip_serializing_if = "Option::is_none")]
    pub email_address: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OrganizationResourceProperties {
    #[serde(rename = "createdTime", skip_serializing)]
    pub created_time: Option<String>,
    #[serde(rename = "provisioningState", skip_serializing_if = "Option::is_none")]
    pub provisioning_state: Option<ProvisioningState>,
    #[serde(rename = "organizationId", skip_serializing)]
    pub organization_id: Option<String>,
    #[serde(rename = "ssoUrl", skip_serializing)]
    pub sso_url: Option<String>,
    #[serde(rename = "offerDetail", skip_serializing_if = "Option::is_none")]
    pub offer_detail: Option<serde_json::Value>,
    #[serde(rename = "userDetail", skip_serializing_if = "Option::is_none")]
    pub user_detail: Option<serde_json::Value>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OrganizationResource {
    #[serde(skip_serializing)]
    pub id: Option<String>,
    #[serde(skip_serializing)]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing)]
    pub type_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OrganizationResourceListResult {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<OrganizationResource>,
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OrganizationResourceUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
}
