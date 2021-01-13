#![doc = "generated by AutoRust 0.1.0"]
#![allow(non_camel_case_types)]
#![allow(unused_imports)]
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServiceResource {
    #[serde(flatten)]
    pub tracked_resource: TrackedResource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<ClusterResourceProperties>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sku: Option<Sku>,
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
pub struct ClusterResourceProperties {
    #[serde(rename = "provisioningState", skip_serializing)]
    pub provisioning_state: Option<cluster_resource_properties::ProvisioningState>,
    #[serde(rename = "networkProfile", skip_serializing_if = "Option::is_none")]
    pub network_profile: Option<NetworkProfile>,
    #[serde(skip_serializing)]
    pub version: Option<i32>,
    #[serde(rename = "serviceId", skip_serializing)]
    pub service_id: Option<String>,
}
pub mod cluster_resource_properties {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum ProvisioningState {
        Creating,
        Updating,
        Deleting,
        Deleted,
        Succeeded,
        Failed,
        Moving,
        Moved,
        MoveFailed,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ManagedIdentityProperties {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_: Option<managed_identity_properties::Type>,
    #[serde(rename = "principalId", skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    #[serde(rename = "tenantId", skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}
pub mod managed_identity_properties {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Type {
        None,
        SystemAssigned,
        UserAssigned,
        #[serde(rename = "SystemAssigned,UserAssigned")]
        SystemAssignedUserAssigned,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Sku {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capacity: Option<i32>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConfigServerSettingsValidateResult {
    #[serde(rename = "isValid", skip_serializing_if = "Option::is_none")]
    pub is_valid: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<ConfigServerSettingsErrorRecord>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConfigServerSettingsErrorRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub messages: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConfigServerResource {
    #[serde(flatten)]
    pub proxy_resource: ProxyResource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<ConfigServerProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConfigServerProperties {
    #[serde(rename = "provisioningState", skip_serializing)]
    pub provisioning_state: Option<config_server_properties::ProvisioningState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Error>,
    #[serde(rename = "configServer", skip_serializing_if = "Option::is_none")]
    pub config_server: Option<ConfigServerSettings>,
}
pub mod config_server_properties {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum ProvisioningState {
        NotAvailable,
        Deleted,
        Failed,
        Succeeded,
        Updating,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MonitoringSettingResource {
    #[serde(flatten)]
    pub proxy_resource: ProxyResource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<MonitoringSettingProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MonitoringSettingProperties {
    #[serde(rename = "provisioningState", skip_serializing)]
    pub provisioning_state: Option<monitoring_setting_properties::ProvisioningState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Error>,
    #[serde(rename = "traceEnabled", skip_serializing_if = "Option::is_none")]
    pub trace_enabled: Option<bool>,
    #[serde(rename = "appInsightsInstrumentationKey", skip_serializing_if = "Option::is_none")]
    pub app_insights_instrumentation_key: Option<String>,
    #[serde(rename = "appInsightsSamplingRate", skip_serializing_if = "Option::is_none")]
    pub app_insights_sampling_rate: Option<f64>,
    #[serde(rename = "appInsightsAgentVersions", skip_serializing_if = "Option::is_none")]
    pub app_insights_agent_versions: Option<ApplicationInsightsAgentVersions>,
}
pub mod monitoring_setting_properties {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum ProvisioningState {
        NotAvailable,
        Failed,
        Succeeded,
        Updating,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApplicationInsightsAgentVersions {
    #[serde(skip_serializing)]
    pub java: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NetworkProfile {
    #[serde(rename = "serviceRuntimeSubnetId", skip_serializing_if = "Option::is_none")]
    pub service_runtime_subnet_id: Option<String>,
    #[serde(rename = "appSubnetId", skip_serializing_if = "Option::is_none")]
    pub app_subnet_id: Option<String>,
    #[serde(rename = "serviceCidr", skip_serializing_if = "Option::is_none")]
    pub service_cidr: Option<String>,
    #[serde(rename = "serviceRuntimeNetworkResourceGroup", skip_serializing_if = "Option::is_none")]
    pub service_runtime_network_resource_group: Option<String>,
    #[serde(rename = "appNetworkResourceGroup", skip_serializing_if = "Option::is_none")]
    pub app_network_resource_group: Option<String>,
    #[serde(rename = "outboundIPs", skip_serializing)]
    pub outbound_i_ps: Option<network_profile::OutboundIPs>,
    #[serde(rename = "requiredTraffics", skip_serializing)]
    pub required_traffics: Vec<RequiredTraffic>,
}
pub mod network_profile {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub struct OutboundIPs {
        #[serde(rename = "publicIPs", skip_serializing)]
        pub public_i_ps: Vec<String>,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RequiredTraffic {
    #[serde(skip_serializing)]
    pub protocol: Option<String>,
    #[serde(skip_serializing)]
    pub port: Option<i32>,
    #[serde(skip_serializing)]
    pub ips: Vec<String>,
    #[serde(skip_serializing)]
    pub fqdns: Vec<String>,
    #[serde(skip_serializing)]
    pub direction: Option<required_traffic::Direction>,
}
pub mod required_traffic {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Direction {
        Inbound,
        Outbound,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Error {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConfigServerSettings {
    #[serde(rename = "gitProperty", skip_serializing_if = "Option::is_none")]
    pub git_property: Option<ConfigServerGitProperty>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConfigServerGitProperty {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub repositories: Vec<GitPatternRepository>,
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(rename = "searchPaths", skip_serializing_if = "Vec::is_empty")]
    pub search_paths: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(rename = "hostKey", skip_serializing_if = "Option::is_none")]
    pub host_key: Option<String>,
    #[serde(rename = "hostKeyAlgorithm", skip_serializing_if = "Option::is_none")]
    pub host_key_algorithm: Option<String>,
    #[serde(rename = "privateKey", skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(rename = "strictHostKeyChecking", skip_serializing_if = "Option::is_none")]
    pub strict_host_key_checking: Option<bool>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GitPatternRepository {
    pub name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pattern: Vec<String>,
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(rename = "searchPaths", skip_serializing_if = "Vec::is_empty")]
    pub search_paths: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(rename = "hostKey", skip_serializing_if = "Option::is_none")]
    pub host_key: Option<String>,
    #[serde(rename = "hostKeyAlgorithm", skip_serializing_if = "Option::is_none")]
    pub host_key_algorithm: Option<String>,
    #[serde(rename = "privateKey", skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(rename = "strictHostKeyChecking", skip_serializing_if = "Option::is_none")]
    pub strict_host_key_checking: Option<bool>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TestKeys {
    #[serde(rename = "primaryKey", skip_serializing_if = "Option::is_none")]
    pub primary_key: Option<String>,
    #[serde(rename = "secondaryKey", skip_serializing_if = "Option::is_none")]
    pub secondary_key: Option<String>,
    #[serde(rename = "primaryTestEndpoint", skip_serializing_if = "Option::is_none")]
    pub primary_test_endpoint: Option<String>,
    #[serde(rename = "secondaryTestEndpoint", skip_serializing_if = "Option::is_none")]
    pub secondary_test_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RegenerateTestKeyRequestPayload {
    #[serde(rename = "keyType")]
    pub key_type: regenerate_test_key_request_payload::KeyType,
}
pub mod regenerate_test_key_request_payload {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum KeyType {
        Primary,
        Secondary,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppResource {
    #[serde(flatten)]
    pub proxy_resource: ProxyResource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<AppResourceProperties>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<ManagedIdentityProperties>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProxyResource {
    #[serde(flatten)]
    pub resource: Resource,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppResourceProperties {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public: Option<bool>,
    #[serde(skip_serializing)]
    pub url: Option<String>,
    #[serde(rename = "provisioningState", skip_serializing)]
    pub provisioning_state: Option<app_resource_properties::ProvisioningState>,
    #[serde(rename = "activeDeploymentName", skip_serializing_if = "Option::is_none")]
    pub active_deployment_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fqdn: Option<String>,
    #[serde(rename = "httpsOnly", skip_serializing_if = "Option::is_none")]
    pub https_only: Option<bool>,
    #[serde(rename = "createdTime", skip_serializing)]
    pub created_time: Option<String>,
    #[serde(rename = "temporaryDisk", skip_serializing_if = "Option::is_none")]
    pub temporary_disk: Option<TemporaryDisk>,
    #[serde(rename = "persistentDisk", skip_serializing_if = "Option::is_none")]
    pub persistent_disk: Option<PersistentDisk>,
}
pub mod app_resource_properties {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum ProvisioningState {
        Succeeded,
        Failed,
        Creating,
        Updating,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TemporaryDisk {
    #[serde(rename = "sizeInGB", skip_serializing_if = "Option::is_none")]
    pub size_in_gb: Option<i32>,
    #[serde(rename = "mountPath", skip_serializing_if = "Option::is_none")]
    pub mount_path: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PersistentDisk {
    #[serde(rename = "sizeInGB", skip_serializing_if = "Option::is_none")]
    pub size_in_gb: Option<i32>,
    #[serde(rename = "usedInGB", skip_serializing)]
    pub used_in_gb: Option<i32>,
    #[serde(rename = "mountPath", skip_serializing_if = "Option::is_none")]
    pub mount_path: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppResourceCollection {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<AppResource>,
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceUploadDefinition {
    #[serde(rename = "relativePath", skip_serializing_if = "Option::is_none")]
    pub relative_path: Option<String>,
    #[serde(rename = "uploadUrl", skip_serializing_if = "Option::is_none")]
    pub upload_url: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BindingResource {
    #[serde(flatten)]
    pub proxy_resource: ProxyResource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<BindingResourceProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BindingResourceProperties {
    #[serde(rename = "resourceName", skip_serializing)]
    pub resource_name: Option<String>,
    #[serde(rename = "resourceType", skip_serializing)]
    pub resource_type: Option<String>,
    #[serde(rename = "resourceId", skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(rename = "bindingParameters", skip_serializing_if = "Option::is_none")]
    pub binding_parameters: Option<serde_json::Value>,
    #[serde(rename = "generatedProperties", skip_serializing)]
    pub generated_properties: Option<String>,
    #[serde(rename = "createdAt", skip_serializing)]
    pub created_at: Option<String>,
    #[serde(rename = "updatedAt", skip_serializing)]
    pub updated_at: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BindingResourceCollection {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<BindingResource>,
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CertificateResource {
    #[serde(flatten)]
    pub proxy_resource: ProxyResource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<CertificateProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CertificateProperties {
    #[serde(skip_serializing)]
    pub thumbprint: Option<String>,
    #[serde(rename = "vaultUri")]
    pub vault_uri: String,
    #[serde(rename = "keyVaultCertName")]
    pub key_vault_cert_name: String,
    #[serde(rename = "certVersion", skip_serializing_if = "Option::is_none")]
    pub cert_version: Option<String>,
    #[serde(skip_serializing)]
    pub issuer: Option<String>,
    #[serde(rename = "issuedDate", skip_serializing)]
    pub issued_date: Option<String>,
    #[serde(rename = "expirationDate", skip_serializing)]
    pub expiration_date: Option<String>,
    #[serde(rename = "activateDate", skip_serializing)]
    pub activate_date: Option<String>,
    #[serde(rename = "subjectName", skip_serializing)]
    pub subject_name: Option<String>,
    #[serde(rename = "dnsNames", skip_serializing)]
    pub dns_names: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CertificateResourceCollection {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<CertificateResource>,
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
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
pub struct CustomDomainResource {
    #[serde(flatten)]
    pub proxy_resource: ProxyResource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<CustomDomainProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CustomDomainProperties {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(rename = "appName", skip_serializing)]
    pub app_name: Option<String>,
    #[serde(rename = "certName", skip_serializing_if = "Option::is_none")]
    pub cert_name: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CustomDomainResourceCollection {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<CustomDomainResource>,
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CustomDomainValidatePayload {
    pub name: String,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CustomDomainValidateResult {
    #[serde(rename = "isValid", skip_serializing_if = "Option::is_none")]
    pub is_valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeploymentResource {
    #[serde(flatten)]
    pub proxy_resource: ProxyResource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<DeploymentResourceProperties>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sku: Option<Sku>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeploymentResourceProperties {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<UserSourceInfo>,
    #[serde(rename = "appName", skip_serializing)]
    pub app_name: Option<String>,
    #[serde(rename = "deploymentSettings", skip_serializing_if = "Option::is_none")]
    pub deployment_settings: Option<DeploymentSettings>,
    #[serde(rename = "provisioningState", skip_serializing)]
    pub provisioning_state: Option<deployment_resource_properties::ProvisioningState>,
    #[serde(skip_serializing)]
    pub status: Option<deployment_resource_properties::Status>,
    #[serde(skip_serializing)]
    pub active: Option<bool>,
    #[serde(rename = "createdTime", skip_serializing)]
    pub created_time: Option<String>,
    #[serde(skip_serializing)]
    pub instances: Vec<DeploymentInstance>,
}
pub mod deployment_resource_properties {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum ProvisioningState {
        Creating,
        Updating,
        Succeeded,
        Failed,
    }
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Status {
        Unknown,
        Stopped,
        Running,
        Failed,
        Allocating,
        Upgrading,
        Compiling,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UserSourceInfo {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_: Option<user_source_info::Type>,
    #[serde(rename = "relativePath", skip_serializing_if = "Option::is_none")]
    pub relative_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(rename = "artifactSelector", skip_serializing_if = "Option::is_none")]
    pub artifact_selector: Option<String>,
}
pub mod user_source_info {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Type {
        Jar,
        NetCoreZip,
        Source,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeploymentSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<i32>,
    #[serde(rename = "memoryInGB", skip_serializing_if = "Option::is_none")]
    pub memory_in_gb: Option<i32>,
    #[serde(rename = "jvmOptions", skip_serializing_if = "Option::is_none")]
    pub jvm_options: Option<String>,
    #[serde(rename = "netCoreMainEntryPath", skip_serializing_if = "Option::is_none")]
    pub net_core_main_entry_path: Option<String>,
    #[serde(rename = "environmentVariables", skip_serializing_if = "Option::is_none")]
    pub environment_variables: Option<serde_json::Value>,
    #[serde(rename = "runtimeVersion", skip_serializing_if = "Option::is_none")]
    pub runtime_version: Option<deployment_settings::RuntimeVersion>,
}
pub mod deployment_settings {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum RuntimeVersion {
        #[serde(rename = "Java_8")]
        Java8,
        #[serde(rename = "Java_11")]
        Java11,
        #[serde(rename = "NetCore_31")]
        NetCore31,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeploymentInstance {
    #[serde(skip_serializing)]
    pub name: Option<String>,
    #[serde(skip_serializing)]
    pub status: Option<String>,
    #[serde(skip_serializing)]
    pub reason: Option<String>,
    #[serde(rename = "discoveryStatus", skip_serializing)]
    pub discovery_status: Option<String>,
    #[serde(rename = "startTime", skip_serializing)]
    pub start_time: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeploymentResourceCollection {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<DeploymentResource>,
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LogFileUrlResponse {
    pub url: String,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServiceResourceList {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<ServiceResource>,
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AvailableOperations {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<OperationDetail>,
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OperationDetail {
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
    #[serde(rename = "logSpecifications", skip_serializing_if = "Vec::is_empty")]
    pub log_specifications: Vec<LogSpecification>,
    #[serde(rename = "metricSpecifications", skip_serializing_if = "Vec::is_empty")]
    pub metric_specifications: Vec<MetricSpecification>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LogSpecification {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "displayName", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(rename = "blobDuration", skip_serializing_if = "Option::is_none")]
    pub blob_duration: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(rename = "aggregationType", skip_serializing_if = "Option::is_none")]
    pub aggregation_type: Option<String>,
    #[serde(rename = "supportedAggregationTypes", skip_serializing_if = "Vec::is_empty")]
    pub supported_aggregation_types: Vec<String>,
    #[serde(rename = "supportedTimeGrainTypes", skip_serializing_if = "Vec::is_empty")]
    pub supported_time_grain_types: Vec<String>,
    #[serde(rename = "fillGapWithZero", skip_serializing_if = "Option::is_none")]
    pub fill_gap_with_zero: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dimensions: Vec<MetricDimension>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MetricDimension {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "displayName", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceSkuCollection {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<ResourceSku>,
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceSku {
    #[serde(rename = "resourceType", skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capacity: Option<SkuCapacity>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<String>,
    #[serde(rename = "locationInfo", skip_serializing_if = "Vec::is_empty")]
    pub location_info: Vec<ResourceSkuLocationInfo>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub restrictions: Vec<ResourceSkuRestrictions>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SkuCapacity {
    pub minimum: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<i32>,
    #[serde(rename = "scaleType", skip_serializing_if = "Option::is_none")]
    pub scale_type: Option<sku_capacity::ScaleType>,
}
pub mod sku_capacity {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum ScaleType {
        None,
        Manual,
        Automatic,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceSkuLocationInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub zones: Vec<String>,
    #[serde(rename = "zoneDetails", skip_serializing_if = "Vec::is_empty")]
    pub zone_details: Vec<ResourceSkuZoneDetails>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceSkuRestrictions {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_: Option<resource_sku_restrictions::Type>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
    #[serde(rename = "restrictionInfo", skip_serializing_if = "Option::is_none")]
    pub restriction_info: Option<ResourceSkuRestrictionInfo>,
    #[serde(rename = "reasonCode", skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<resource_sku_restrictions::ReasonCode>,
}
pub mod resource_sku_restrictions {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Type {
        Location,
        Zone,
    }
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum ReasonCode {
        QuotaId,
        NotAvailableForSubscription,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceSkuZoneDetails {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub name: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<ResourceSkuCapabilities>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceSkuRestrictionInfo {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub zones: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceSkuCapabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AvailableRuntimeVersions {
    #[serde(skip_serializing)]
    pub value: Vec<SupportedRuntimeVersion>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SupportedRuntimeVersion {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<supported_runtime_version::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<supported_runtime_version::Platform>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}
pub mod supported_runtime_version {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Value {
        #[serde(rename = "Java_8")]
        Java8,
        #[serde(rename = "Java_11")]
        Java11,
        #[serde(rename = "NetCore_31")]
        NetCore31,
    }
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Platform {
        Java,
        #[serde(rename = ".NET Core")]
        NetCore,
    }
}
