#![doc = "generated by AutoRust 0.1.0"]
#![allow(non_camel_case_types)]
#![allow(unused_imports)]
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OperationListResult {
    #[serde(skip_serializing)]
    pub value: Vec<Operation>,
    #[serde(rename = "nextLink", skip_serializing)]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Operation {
    #[serde(skip_serializing)]
    pub name: Option<String>,
    #[serde(skip_serializing)]
    pub display: Option<operation::Display>,
}
pub mod operation {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub struct Display {
        #[serde(skip_serializing)]
        pub provider: Option<String>,
        #[serde(skip_serializing)]
        pub resource: Option<String>,
        #[serde(skip_serializing)]
        pub operation: Option<String>,
        #[serde(skip_serializing)]
        pub description: Option<String>,
    }
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TrackedResource {
    #[serde(flatten)]
    pub resource: Resource,
    pub location: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceProperties {
    #[serde(rename = "provisioningState", skip_serializing)]
    pub provisioning_state: Option<resource_properties::ProvisioningState>,
    #[serde(rename = "creationTime", skip_serializing)]
    pub creation_time: Option<String>,
}
pub mod resource_properties {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum ProvisioningState {
        Accepted,
        Creating,
        Updating,
        Succeeded,
        Failed,
        Deleting,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Sku {
    pub name: sku::Name,
    pub capacity: i32,
}
pub mod sku {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Name {
        S1,
        S2,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CreateOrUpdateTrackedResourceProperties {
    pub location: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EnvironmentCreateOrUpdateParameters {
    #[serde(flatten)]
    pub create_or_update_tracked_resource_properties: CreateOrUpdateTrackedResourceProperties,
    pub sku: Sku,
    pub properties: EnvironmentCreationProperties,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EnvironmentUpdateParameters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sku: Option<Sku>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<EnvironmentMutableProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EnvironmentListResponse {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<EnvironmentResource>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EnvironmentResource {
    #[serde(flatten)]
    pub tracked_resource: TrackedResource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sku: Option<Sku>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<EnvironmentResourceProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EnvironmentCreationProperties {
    #[serde(rename = "dataRetentionTime")]
    pub data_retention_time: String,
    #[serde(rename = "storageLimitExceededBehavior", skip_serializing_if = "Option::is_none")]
    pub storage_limit_exceeded_behavior: Option<environment_creation_properties::StorageLimitExceededBehavior>,
}
pub mod environment_creation_properties {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum StorageLimitExceededBehavior {
        PurgeOldData,
        PauseIngress,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EnvironmentResourceProperties {
    #[serde(flatten)]
    pub environment_creation_properties: EnvironmentCreationProperties,
    #[serde(flatten)]
    pub resource_properties: ResourceProperties,
    #[serde(rename = "dataAccessId", skip_serializing)]
    pub data_access_id: Option<String>,
    #[serde(rename = "dataAccessFqdn", skip_serializing)]
    pub data_access_fqdn: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EnvironmentMutableProperties {
    #[serde(rename = "dataRetentionTime", skip_serializing_if = "Option::is_none")]
    pub data_retention_time: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventSourceCreateOrUpdateParameters {
    #[serde(flatten)]
    pub create_or_update_tracked_resource_properties: CreateOrUpdateTrackedResourceProperties,
    pub kind: event_source_create_or_update_parameters::Kind,
}
pub mod event_source_create_or_update_parameters {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Kind {
        #[serde(rename = "Microsoft.EventHub")]
        MicrosoftEventHub,
        #[serde(rename = "Microsoft.IoTHub")]
        MicrosoftIoTHub,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventHubEventSourceCreateOrUpdateParameters {
    #[serde(flatten)]
    pub event_source_create_or_update_parameters: EventSourceCreateOrUpdateParameters,
    pub properties: EventHubEventSourceCreationProperties,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IoTHubEventSourceCreateOrUpdateParameters {
    #[serde(flatten)]
    pub event_source_create_or_update_parameters: EventSourceCreateOrUpdateParameters,
    pub properties: IoTHubEventSourceCreationProperties,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventSourceUpdateParameters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventHubEventSourceUpdateParameters {
    #[serde(flatten)]
    pub event_source_update_parameters: EventSourceUpdateParameters,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<EventHubEventSourceMutableProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IoTHubEventSourceUpdateParameters {
    #[serde(flatten)]
    pub event_source_update_parameters: EventSourceUpdateParameters,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<IoTHubEventSourceMutableProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventSourceListResponse {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<EventSourceResource>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventSourceResource {
    #[serde(flatten)]
    pub tracked_resource: TrackedResource,
    pub kind: event_source_resource::Kind,
}
pub mod event_source_resource {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Kind {
        #[serde(rename = "Microsoft.EventHub")]
        MicrosoftEventHub,
        #[serde(rename = "Microsoft.IoTHub")]
        MicrosoftIoTHub,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventHubEventSourceResource {
    #[serde(flatten)]
    pub event_source_resource: EventSourceResource,
    pub properties: EventHubEventSourceResourceProperties,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IoTHubEventSourceResource {
    #[serde(flatten)]
    pub event_source_resource: EventSourceResource,
    pub properties: IoTHubEventSourceResourceProperties,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventSourceCommonProperties {
    #[serde(flatten)]
    pub resource_properties: ResourceProperties,
    #[serde(rename = "timestampPropertyName", skip_serializing_if = "Option::is_none")]
    pub timestamp_property_name: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AzureEventSourceProperties {
    #[serde(flatten)]
    pub event_source_common_properties: EventSourceCommonProperties,
    #[serde(rename = "eventSourceResourceId")]
    pub event_source_resource_id: String,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventHubEventSourceCommonProperties {
    #[serde(flatten)]
    pub azure_event_source_properties: AzureEventSourceProperties,
    #[serde(rename = "serviceBusNamespace")]
    pub service_bus_namespace: String,
    #[serde(rename = "eventHubName")]
    pub event_hub_name: String,
    #[serde(rename = "consumerGroupName")]
    pub consumer_group_name: String,
    #[serde(rename = "keyName")]
    pub key_name: String,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventHubEventSourceCreationProperties {
    #[serde(flatten)]
    pub event_hub_event_source_common_properties: EventHubEventSourceCommonProperties,
    #[serde(rename = "sharedAccessKey")]
    pub shared_access_key: String,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventHubEventSourceResourceProperties {
    #[serde(flatten)]
    pub event_hub_event_source_common_properties: EventHubEventSourceCommonProperties,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IoTHubEventSourceCommonProperties {
    #[serde(flatten)]
    pub azure_event_source_properties: AzureEventSourceProperties,
    #[serde(rename = "iotHubName")]
    pub iot_hub_name: String,
    #[serde(rename = "consumerGroupName")]
    pub consumer_group_name: String,
    #[serde(rename = "keyName")]
    pub key_name: String,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IoTHubEventSourceCreationProperties {
    #[serde(flatten)]
    pub io_t_hub_event_source_common_properties: IoTHubEventSourceCommonProperties,
    #[serde(rename = "sharedAccessKey")]
    pub shared_access_key: String,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IoTHubEventSourceResourceProperties {
    #[serde(flatten)]
    pub io_t_hub_event_source_common_properties: IoTHubEventSourceCommonProperties,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LocalTimestamp {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<local_timestamp::Format>,
    #[serde(rename = "timeZoneOffset", skip_serializing_if = "Option::is_none")]
    pub time_zone_offset: Option<local_timestamp::TimeZoneOffset>,
}
pub mod local_timestamp {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Format {
        Embedded,
        Iana,
        TimeSpan,
    }
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub struct TimeZoneOffset {
        #[serde(rename = "propertyName", skip_serializing_if = "Option::is_none")]
        pub property_name: Option<String>,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventSourceMutableProperties {
    #[serde(rename = "timestampPropertyName", skip_serializing_if = "Option::is_none")]
    pub timestamp_property_name: Option<String>,
    #[serde(rename = "localTimestamp", skip_serializing_if = "Option::is_none")]
    pub local_timestamp: Option<LocalTimestamp>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventHubEventSourceMutableProperties {
    #[serde(flatten)]
    pub event_source_mutable_properties: EventSourceMutableProperties,
    #[serde(rename = "sharedAccessKey", skip_serializing_if = "Option::is_none")]
    pub shared_access_key: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IoTHubEventSourceMutableProperties {
    #[serde(flatten)]
    pub event_source_mutable_properties: EventSourceMutableProperties,
    #[serde(rename = "sharedAccessKey", skip_serializing_if = "Option::is_none")]
    pub shared_access_key: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReferenceDataSetCreateOrUpdateParameters {
    #[serde(flatten)]
    pub create_or_update_tracked_resource_properties: CreateOrUpdateTrackedResourceProperties,
    pub properties: ReferenceDataSetCreationProperties,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReferenceDataSetUpdateParameters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReferenceDataSetListResponse {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<ReferenceDataSetResource>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReferenceDataSetResource {
    #[serde(flatten)]
    pub tracked_resource: TrackedResource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<ReferenceDataSetResourceProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReferenceDataSetCreationProperties {
    #[serde(rename = "keyProperties")]
    pub key_properties: Vec<ReferenceDataSetKeyProperty>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReferenceDataSetResourceProperties {
    #[serde(flatten)]
    pub reference_data_set_creation_properties: ReferenceDataSetCreationProperties,
    #[serde(flatten)]
    pub resource_properties: ResourceProperties,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReferenceDataSetKeyProperty {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_: Option<reference_data_set_key_property::Type>,
}
pub mod reference_data_set_key_property {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Type {
        String,
        Double,
        Bool,
        DateTime,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AccessPolicyCreateOrUpdateParameters {
    pub properties: AccessPolicyResourceProperties,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AccessPolicyUpdateParameters {
    pub properties: AccessPolicyMutableProperties,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AccessPolicyListResponse {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<AccessPolicyResource>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AccessPolicyResource {
    #[serde(flatten)]
    pub resource: Resource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<AccessPolicyResourceProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AccessPolicyResourceProperties {
    #[serde(rename = "principalObjectId", skip_serializing_if = "Option::is_none")]
    pub principal_object_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AccessPolicyMutableProperties {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CloudError {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<CloudErrorBody>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CloudErrorBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<CloudErrorBody>,
}
