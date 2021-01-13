#![doc = "generated by AutoRust 0.1.0"]
#![allow(non_camel_case_types)]
#![allow(unused_imports)]
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ErrorResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<error_response::Error>,
}
pub mod error_response {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub struct Error {
        #[serde(skip_serializing)]
        pub code: Option<String>,
        #[serde(skip_serializing)]
        pub message: Option<String>,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PrivateStoreList {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<PrivateStore>,
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum PrivateStoreOperation {
    DeletePrivateStoreOffer,
    Ping,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PrivateStore {
    #[serde(flatten)]
    pub resource: Resource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<PrivateStoreProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PrivateStoreProperties {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub availability: Option<private_store_properties::Availability>,
    #[serde(rename = "privateStoreId", skip_serializing_if = "Option::is_none")]
    pub private_store_id: Option<String>,
    #[serde(rename = "eTag", skip_serializing_if = "Option::is_none")]
    pub e_tag: Option<String>,
    #[serde(rename = "privateStoreName", skip_serializing_if = "Option::is_none")]
    pub private_store_name: Option<String>,
    #[serde(rename = "tenantTag", skip_serializing_if = "Option::is_none")]
    pub tenant_tag: Option<String>,
    #[serde(rename = "tenantIds", skip_serializing_if = "Vec::is_empty")]
    pub tenant_ids: Vec<String>,
    #[serde(rename = "customerTag", skip_serializing_if = "Option::is_none")]
    pub customer_tag: Option<String>,
    #[serde(rename = "hasCommercialAssociation", skip_serializing_if = "Option::is_none")]
    pub has_commercial_association: Option<bool>,
    #[serde(rename = "hasMultiTenantAssociation", skip_serializing_if = "Option::is_none")]
    pub has_multi_tenant_association: Option<bool>,
    #[serde(rename = "isGov", skip_serializing_if = "Option::is_none")]
    pub is_gov: Option<bool>,
}
pub mod private_store_properties {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Availability {
        #[serde(rename = "enabled")]
        Enabled,
        #[serde(rename = "disabled")]
        Disabled,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OfferListResponse {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<Offer>,
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Offer {
    #[serde(flatten)]
    pub resource: Resource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<OfferProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OfferProperties {
    #[serde(rename = "uniqueOfferId", skip_serializing)]
    pub unique_offer_id: Option<String>,
    #[serde(rename = "offerDisplayName", skip_serializing)]
    pub offer_display_name: Option<String>,
    #[serde(rename = "publisherDisplayName", skip_serializing)]
    pub publisher_display_name: Option<String>,
    #[serde(rename = "eTag", skip_serializing_if = "Option::is_none")]
    pub e_tag: Option<String>,
    #[serde(rename = "privateStoreId", skip_serializing)]
    pub private_store_id: Option<String>,
    #[serde(rename = "createdAt", skip_serializing)]
    pub created_at: Option<String>,
    #[serde(rename = "modifiedAt", skip_serializing)]
    pub modified_at: Option<String>,
    #[serde(rename = "specificPlanIdsLimitation", skip_serializing_if = "Vec::is_empty")]
    pub specific_plan_ids_limitation: Vec<String>,
    #[serde(rename = "updateSuppressedDueIdempotence", skip_serializing_if = "Option::is_none")]
    pub update_suppressed_due_idempotence: Option<bool>,
    #[serde(rename = "iconFileUris", skip_serializing_if = "Option::is_none")]
    pub icon_file_uris: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub plans: Vec<Plan>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Plan {
    #[serde(rename = "skuId", skip_serializing)]
    pub sku_id: Option<String>,
    #[serde(rename = "planId", skip_serializing)]
    pub plan_id: Option<String>,
    #[serde(rename = "planDisplayName", skip_serializing)]
    pub plan_display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accessibility: Option<plan::Accessibility>,
    #[serde(rename = "altStackReference", skip_serializing)]
    pub alt_stack_reference: Option<String>,
    #[serde(rename = "stackType", skip_serializing)]
    pub stack_type: Option<String>,
}
pub mod plan {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Accessibility {
        Unknown,
        Public,
        PrivateTenantOnLevel,
        PrivateSubscriptionOnLevel,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Operation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<operation::Display>,
}
pub mod operation {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub struct Display {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub provider: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub resource: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub operation: Option<String>,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OperationListResult {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<Operation>,
    #[serde(rename = "nextLink", skip_serializing)]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Resource {
    #[serde(skip_serializing)]
    pub id: Option<String>,
    #[serde(skip_serializing)]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing)]
    pub type_: Option<String>,
}
