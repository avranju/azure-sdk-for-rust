#![doc = "generated by AutoRust 0.1.0"]
#![allow(non_camel_case_types)]
#![allow(unused_imports)]
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OperationList {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<Operation>,
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Operation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "isDataAction", skip_serializing_if = "Option::is_none")]
    pub is_data_action: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<OperationDisplay>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<OperationProperties>,
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
pub struct OperationProperties {
    #[serde(rename = "serviceSpecification", skip_serializing_if = "Option::is_none")]
    pub service_specification: Option<ServiceSpecification>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServiceSpecification {
    #[serde(rename = "metricSpecifications", skip_serializing_if = "Vec::is_empty")]
    pub metric_specifications: Vec<MetricSpecification>,
    #[serde(rename = "logSpecifications", skip_serializing_if = "Vec::is_empty")]
    pub log_specifications: Vec<LogSpecification>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MetricSpecification {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "displayName", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(rename = "displayDescription", skip_serializing_if = "Option::is_none")]
    pub display_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(rename = "aggregationType", skip_serializing_if = "Option::is_none")]
    pub aggregation_type: Option<String>,
    #[serde(rename = "fillGapWithZero", skip_serializing_if = "Option::is_none")]
    pub fill_gap_with_zero: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dimensions: Vec<Dimension>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LogSpecification {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "displayName", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Dimension {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "displayName", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(rename = "internalName", skip_serializing_if = "Option::is_none")]
    pub internal_name: Option<String>,
    #[serde(rename = "toBeExportedForShoebox", skip_serializing_if = "Option::is_none")]
    pub to_be_exported_for_shoebox: Option<bool>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ErrorResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorResponseBody>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ErrorResponseBody {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<ErrorResponseBody>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NameAvailabilityParameters {
    #[serde(rename = "type")]
    pub type_: String,
    pub name: String,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NameAvailability {
    #[serde(rename = "nameAvailable", skip_serializing_if = "Option::is_none")]
    pub name_available: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignalRResourceList {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<SignalRResource>,
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignalRResource {
    #[serde(flatten)]
    pub tracked_resource: TrackedResource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sku: Option<ResourceSku>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SignalRProperties>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<ServiceKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<ManagedIdentity>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ServiceKind {
    SignalR,
    RawWebSockets,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TrackedResource {
    #[serde(flatten)]
    pub resource: Resource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
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
pub struct ResourceSku {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<SignalRSkuTier>,
    #[serde(skip_serializing)]
    pub size: Option<String>,
    #[serde(skip_serializing)]
    pub family: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capacity: Option<i32>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum SignalRSkuTier {
    Free,
    Basic,
    Standard,
    Premium,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignalRProperties {
    #[serde(flatten)]
    pub signal_r_create_or_update_properties: SignalRCreateOrUpdateProperties,
    #[serde(rename = "provisioningState", skip_serializing_if = "Option::is_none")]
    pub provisioning_state: Option<ProvisioningState>,
    #[serde(rename = "externalIP", skip_serializing)]
    pub external_ip: Option<String>,
    #[serde(rename = "hostName", skip_serializing)]
    pub host_name: Option<String>,
    #[serde(rename = "publicPort", skip_serializing)]
    pub public_port: Option<i32>,
    #[serde(rename = "serverPort", skip_serializing)]
    pub server_port: Option<i32>,
    #[serde(skip_serializing)]
    pub version: Option<String>,
    #[serde(rename = "privateEndpointConnections", skip_serializing)]
    pub private_endpoint_connections: Vec<PrivateEndpointConnection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<SignalRTlsSettings>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ProvisioningState {
    Unknown,
    Succeeded,
    Failed,
    Canceled,
    Running,
    Creating,
    Updating,
    Deleting,
    Moving,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignalRCreateOrUpdateProperties {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<SignalRFeature>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cors: Option<SignalRCorsSettings>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream: Option<ServerlessUpstreamSettings>,
    #[serde(rename = "networkACLs", skip_serializing_if = "Option::is_none")]
    pub network_ac_ls: Option<SignalRNetworkAcLs>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignalRFeature {
    pub flag: FeatureFlags,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<serde_json::Value>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum FeatureFlags {
    ServiceMode,
    EnableConnectivityLogs,
    EnableMessagingLogs,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignalRCorsSettings {
    #[serde(rename = "allowedOrigins", skip_serializing_if = "Vec::is_empty")]
    pub allowed_origins: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServerlessUpstreamSettings {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub templates: Vec<UpstreamTemplate>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignalRNetworkAcLs {
    #[serde(rename = "defaultAction", skip_serializing_if = "Option::is_none")]
    pub default_action: Option<AclAction>,
    #[serde(rename = "publicNetwork", skip_serializing_if = "Option::is_none")]
    pub public_network: Option<NetworkAcl>,
    #[serde(rename = "privateEndpoints", skip_serializing_if = "Vec::is_empty")]
    pub private_endpoints: Vec<PrivateEndpointAcl>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum AclAction {
    Allow,
    Deny,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UpstreamTemplate {
    #[serde(rename = "hubPattern", skip_serializing_if = "Option::is_none")]
    pub hub_pattern: Option<String>,
    #[serde(rename = "eventPattern", skip_serializing_if = "Option::is_none")]
    pub event_pattern: Option<String>,
    #[serde(rename = "categoryPattern", skip_serializing_if = "Option::is_none")]
    pub category_pattern: Option<String>,
    #[serde(rename = "urlTemplate")]
    pub url_template: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<UpstreamAuthSettings>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NetworkAcl {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<SignalRRequestType>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<SignalRRequestType>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum SignalRRequestType {
    ClientConnection,
    ServerConnection,
    #[serde(rename = "RESTAPI")]
    Restapi,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PrivateEndpointAcl {
    #[serde(flatten)]
    pub network_acl: NetworkAcl,
    pub name: String,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UpstreamAuthSettings {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_: Option<UpstreamAuthType>,
    #[serde(rename = "managedIdentity", skip_serializing_if = "Option::is_none")]
    pub managed_identity: Option<ManagedIdentitySettings>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum UpstreamAuthType {
    None,
    ManagedIdentity,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ManagedIdentitySettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ManagedIdentity {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_: Option<ManagedIdentityType>,
    #[serde(rename = "userAssignedIdentities", skip_serializing_if = "Option::is_none")]
    pub user_assigned_identities: Option<serde_json::Value>,
    #[serde(rename = "principalId", skip_serializing)]
    pub principal_id: Option<String>,
    #[serde(rename = "tenantId", skip_serializing)]
    pub tenant_id: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ManagedIdentityType {
    None,
    SystemAssigned,
    UserAssigned,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PrivateEndpointConnection {
    #[serde(flatten)]
    pub proxy_resource: ProxyResource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<PrivateEndpointConnectionProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProxyResource {
    #[serde(flatten)]
    pub resource: Resource,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignalRTlsSettings {
    #[serde(rename = "clientCertEnabled", skip_serializing_if = "Option::is_none")]
    pub client_cert_enabled: Option<bool>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UserAssignedIdentityProperty {
    #[serde(rename = "principalId", skip_serializing)]
    pub principal_id: Option<String>,
    #[serde(rename = "clientId", skip_serializing)]
    pub client_id: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PrivateEndpointConnectionProperties {
    #[serde(rename = "provisioningState", skip_serializing_if = "Option::is_none")]
    pub provisioning_state: Option<ProvisioningState>,
    #[serde(rename = "privateEndpoint", skip_serializing_if = "Option::is_none")]
    pub private_endpoint: Option<PrivateEndpoint>,
    #[serde(rename = "privateLinkServiceConnectionState", skip_serializing_if = "Option::is_none")]
    pub private_link_service_connection_state: Option<PrivateLinkServiceConnectionState>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PrivateEndpoint {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PrivateLinkServiceConnectionState {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<PrivateLinkServiceConnectionStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "actionsRequired", skip_serializing_if = "Option::is_none")]
    pub actions_required: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum PrivateLinkServiceConnectionStatus {
    Pending,
    Approved,
    Rejected,
    Disconnected,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PrivateLinkResourceList {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<PrivateLinkResource>,
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PrivateLinkResource {
    #[serde(flatten)]
    pub proxy_resource: ProxyResource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<PrivateLinkResourceProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PrivateLinkResourceProperties {
    #[serde(rename = "groupId", skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    #[serde(rename = "requiredMembers", skip_serializing_if = "Vec::is_empty")]
    pub required_members: Vec<String>,
    #[serde(rename = "requiredZoneNames", skip_serializing_if = "Vec::is_empty")]
    pub required_zone_names: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignalRKeys {
    #[serde(rename = "primaryKey", skip_serializing_if = "Option::is_none")]
    pub primary_key: Option<String>,
    #[serde(rename = "secondaryKey", skip_serializing_if = "Option::is_none")]
    pub secondary_key: Option<String>,
    #[serde(rename = "primaryConnectionString", skip_serializing_if = "Option::is_none")]
    pub primary_connection_string: Option<String>,
    #[serde(rename = "secondaryConnectionString", skip_serializing_if = "Option::is_none")]
    pub secondary_connection_string: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RegenerateKeyParameters {
    #[serde(rename = "keyType", skip_serializing_if = "Option::is_none")]
    pub key_type: Option<KeyType>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum KeyType {
    Primary,
    Secondary,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignalRUsageList {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<SignalRUsage>,
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignalRUsage {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "currentValue", skip_serializing_if = "Option::is_none")]
    pub current_value: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<SignalRUsageName>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignalRUsageName {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(rename = "localizedValue", skip_serializing_if = "Option::is_none")]
    pub localized_value: Option<String>,
}
