#![doc = "generated by AutoRust 0.1.0"]
#![allow(non_camel_case_types)]
#![allow(unused_imports)]
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FrontDoor {
    #[serde(flatten)]
    pub resource: Resource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<FrontDoorProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FrontDoorUpdateParameters {
    #[serde(rename = "friendlyName", skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    #[serde(rename = "routingRules", skip_serializing_if = "Vec::is_empty")]
    pub routing_rules: Vec<RoutingRule>,
    #[serde(rename = "loadBalancingSettings", skip_serializing_if = "Vec::is_empty")]
    pub load_balancing_settings: Vec<LoadBalancingSettingsModel>,
    #[serde(rename = "healthProbeSettings", skip_serializing_if = "Vec::is_empty")]
    pub health_probe_settings: Vec<HealthProbeSettingsModel>,
    #[serde(rename = "backendPools", skip_serializing_if = "Vec::is_empty")]
    pub backend_pools: Vec<BackendPool>,
    #[serde(rename = "frontendEndpoints", skip_serializing_if = "Vec::is_empty")]
    pub frontend_endpoints: Vec<FrontendEndpoint>,
    #[serde(rename = "backendPoolsSettings", skip_serializing_if = "Option::is_none")]
    pub backend_pools_settings: Option<BackendPoolsSettings>,
    #[serde(rename = "enabledState", skip_serializing_if = "Option::is_none")]
    pub enabled_state: Option<front_door_update_parameters::EnabledState>,
}
pub mod front_door_update_parameters {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum EnabledState {
        Enabled,
        Disabled,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FrontDoorProperties {
    #[serde(flatten)]
    pub front_door_update_parameters: FrontDoorUpdateParameters,
    #[serde(rename = "resourceState", skip_serializing)]
    pub resource_state: Option<ResourceState>,
    #[serde(rename = "provisioningState", skip_serializing)]
    pub provisioning_state: Option<String>,
    #[serde(skip_serializing)]
    pub cname: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FrontDoorListResult {
    #[serde(skip_serializing)]
    pub value: Vec<FrontDoor>,
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PurgeParameters {
    #[serde(rename = "contentPaths")]
    pub content_paths: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RoutingRule {
    #[serde(flatten)]
    pub sub_resource: SubResource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<RoutingRuleProperties>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing)]
    pub type_: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RoutingRuleProperties {
    #[serde(flatten)]
    pub routing_rule_update_parameters: RoutingRuleUpdateParameters,
    #[serde(rename = "resourceState", skip_serializing)]
    pub resource_state: Option<ResourceState>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RoutingRuleListResult {
    #[serde(skip_serializing)]
    pub value: Vec<RoutingRule>,
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RoutingRuleUpdateParameters {
    #[serde(rename = "frontendEndpoints", skip_serializing_if = "Vec::is_empty")]
    pub frontend_endpoints: Vec<SubResource>,
    #[serde(rename = "acceptedProtocols", skip_serializing_if = "Vec::is_empty")]
    pub accepted_protocols: Vec<String>,
    #[serde(rename = "patternsToMatch", skip_serializing_if = "Vec::is_empty")]
    pub patterns_to_match: Vec<String>,
    #[serde(rename = "enabledState", skip_serializing_if = "Option::is_none")]
    pub enabled_state: Option<routing_rule_update_parameters::EnabledState>,
    #[serde(rename = "routeConfiguration", skip_serializing_if = "Option::is_none")]
    pub route_configuration: Option<RouteConfiguration>,
}
pub mod routing_rule_update_parameters {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum EnabledState {
        Enabled,
        Disabled,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RouteConfiguration {
    #[serde(rename = "@odata.type")]
    pub odata_type: String,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ForwardingConfiguration {
    #[serde(flatten)]
    pub route_configuration: RouteConfiguration,
    #[serde(rename = "customForwardingPath", skip_serializing_if = "Option::is_none")]
    pub custom_forwarding_path: Option<String>,
    #[serde(rename = "forwardingProtocol", skip_serializing_if = "Option::is_none")]
    pub forwarding_protocol: Option<forwarding_configuration::ForwardingProtocol>,
    #[serde(rename = "cacheConfiguration", skip_serializing_if = "Option::is_none")]
    pub cache_configuration: Option<CacheConfiguration>,
    #[serde(rename = "backendPool", skip_serializing_if = "Option::is_none")]
    pub backend_pool: Option<SubResource>,
}
pub mod forwarding_configuration {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum ForwardingProtocol {
        HttpOnly,
        HttpsOnly,
        MatchRequest,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RedirectConfiguration {
    #[serde(flatten)]
    pub route_configuration: RouteConfiguration,
    #[serde(rename = "redirectType", skip_serializing_if = "Option::is_none")]
    pub redirect_type: Option<redirect_configuration::RedirectType>,
    #[serde(rename = "redirectProtocol", skip_serializing_if = "Option::is_none")]
    pub redirect_protocol: Option<redirect_configuration::RedirectProtocol>,
    #[serde(rename = "customHost", skip_serializing_if = "Option::is_none")]
    pub custom_host: Option<String>,
    #[serde(rename = "customPath", skip_serializing_if = "Option::is_none")]
    pub custom_path: Option<String>,
    #[serde(rename = "customFragment", skip_serializing_if = "Option::is_none")]
    pub custom_fragment: Option<String>,
    #[serde(rename = "customQueryString", skip_serializing_if = "Option::is_none")]
    pub custom_query_string: Option<String>,
}
pub mod redirect_configuration {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum RedirectType {
        Moved,
        Found,
        TemporaryRedirect,
        PermanentRedirect,
    }
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum RedirectProtocol {
        HttpOnly,
        HttpsOnly,
        MatchRequest,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Backend {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(rename = "httpPort", skip_serializing_if = "Option::is_none")]
    pub http_port: Option<i64>,
    #[serde(rename = "httpsPort", skip_serializing_if = "Option::is_none")]
    pub https_port: Option<i64>,
    #[serde(rename = "enabledState", skip_serializing_if = "Option::is_none")]
    pub enabled_state: Option<backend::EnabledState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weight: Option<i64>,
    #[serde(rename = "backendHostHeader", skip_serializing_if = "Option::is_none")]
    pub backend_host_header: Option<String>,
}
pub mod backend {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum EnabledState {
        Enabled,
        Disabled,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LoadBalancingSettingsModel {
    #[serde(flatten)]
    pub sub_resource: SubResource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<LoadBalancingSettingsProperties>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing)]
    pub type_: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LoadBalancingSettingsProperties {
    #[serde(flatten)]
    pub load_balancing_settings_update_parameters: LoadBalancingSettingsUpdateParameters,
    #[serde(rename = "resourceState", skip_serializing)]
    pub resource_state: Option<ResourceState>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LoadBalancingSettingsListResult {
    #[serde(skip_serializing)]
    pub value: Vec<LoadBalancingSettingsModel>,
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LoadBalancingSettingsUpdateParameters {
    #[serde(rename = "sampleSize", skip_serializing_if = "Option::is_none")]
    pub sample_size: Option<i64>,
    #[serde(rename = "successfulSamplesRequired", skip_serializing_if = "Option::is_none")]
    pub successful_samples_required: Option<i64>,
    #[serde(rename = "additionalLatencyMilliseconds", skip_serializing_if = "Option::is_none")]
    pub additional_latency_milliseconds: Option<i64>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HealthProbeSettingsModel {
    #[serde(flatten)]
    pub sub_resource: SubResource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<HealthProbeSettingsProperties>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing)]
    pub type_: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HealthProbeSettingsProperties {
    #[serde(flatten)]
    pub health_probe_settings_update_parameters: HealthProbeSettingsUpdateParameters,
    #[serde(rename = "resourceState", skip_serializing)]
    pub resource_state: Option<ResourceState>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HealthProbeSettingsListResult {
    #[serde(skip_serializing)]
    pub value: Vec<HealthProbeSettingsModel>,
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HealthProbeSettingsUpdateParameters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<health_probe_settings_update_parameters::Protocol>,
    #[serde(rename = "intervalInSeconds", skip_serializing_if = "Option::is_none")]
    pub interval_in_seconds: Option<i64>,
    #[serde(rename = "healthProbeMethod", skip_serializing_if = "Option::is_none")]
    pub health_probe_method: Option<health_probe_settings_update_parameters::HealthProbeMethod>,
    #[serde(rename = "enabledState", skip_serializing_if = "Option::is_none")]
    pub enabled_state: Option<health_probe_settings_update_parameters::EnabledState>,
}
pub mod health_probe_settings_update_parameters {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Protocol {
        Http,
        Https,
    }
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum HealthProbeMethod {
        #[serde(rename = "GET")]
        Get,
        #[serde(rename = "HEAD")]
        Head,
    }
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum EnabledState {
        Enabled,
        Disabled,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BackendPool {
    #[serde(flatten)]
    pub sub_resource: SubResource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<BackendPoolProperties>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing)]
    pub type_: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BackendPoolUpdateParameters {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub backends: Vec<Backend>,
    #[serde(rename = "loadBalancingSettings", skip_serializing_if = "Option::is_none")]
    pub load_balancing_settings: Option<SubResource>,
    #[serde(rename = "healthProbeSettings", skip_serializing_if = "Option::is_none")]
    pub health_probe_settings: Option<SubResource>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BackendPoolProperties {
    #[serde(flatten)]
    pub backend_pool_update_parameters: BackendPoolUpdateParameters,
    #[serde(rename = "resourceState", skip_serializing)]
    pub resource_state: Option<ResourceState>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BackendPoolListResult {
    #[serde(skip_serializing)]
    pub value: Vec<BackendPool>,
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CacheConfiguration {
    #[serde(rename = "queryParameterStripDirective", skip_serializing_if = "Option::is_none")]
    pub query_parameter_strip_directive: Option<cache_configuration::QueryParameterStripDirective>,
    #[serde(rename = "dynamicCompression", skip_serializing_if = "Option::is_none")]
    pub dynamic_compression: Option<cache_configuration::DynamicCompression>,
}
pub mod cache_configuration {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum QueryParameterStripDirective {
        StripNone,
        StripAll,
    }
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum DynamicCompression {
        Enabled,
        Disabled,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeyVaultCertificateSourceParameters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault: Option<key_vault_certificate_source_parameters::Vault>,
    #[serde(rename = "secretName", skip_serializing_if = "Option::is_none")]
    pub secret_name: Option<String>,
    #[serde(rename = "secretVersion", skip_serializing_if = "Option::is_none")]
    pub secret_version: Option<String>,
}
pub mod key_vault_certificate_source_parameters {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub struct Vault {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FrontDoorCertificateSourceParameters {
    #[serde(rename = "certificateType", skip_serializing_if = "Option::is_none")]
    pub certificate_type: Option<front_door_certificate_source_parameters::CertificateType>,
}
pub mod front_door_certificate_source_parameters {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum CertificateType {
        Dedicated,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CustomHttpsConfiguration {
    #[serde(rename = "certificateSource")]
    pub certificate_source: custom_https_configuration::CertificateSource,
    #[serde(rename = "protocolType")]
    pub protocol_type: custom_https_configuration::ProtocolType,
    #[serde(rename = "minimumTlsVersion")]
    pub minimum_tls_version: custom_https_configuration::MinimumTlsVersion,
    #[serde(rename = "keyVaultCertificateSourceParameters", skip_serializing_if = "Option::is_none")]
    pub key_vault_certificate_source_parameters: Option<KeyVaultCertificateSourceParameters>,
    #[serde(rename = "frontDoorCertificateSourceParameters", skip_serializing_if = "Option::is_none")]
    pub front_door_certificate_source_parameters: Option<FrontDoorCertificateSourceParameters>,
}
pub mod custom_https_configuration {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum CertificateSource {
        AzureKeyVault,
        FrontDoor,
    }
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum ProtocolType {
        ServerNameIndication,
    }
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum MinimumTlsVersion {
        #[serde(rename = "1.0")]
        _1_0,
        #[serde(rename = "1.2")]
        _1_2,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FrontendEndpoint {
    #[serde(flatten)]
    pub sub_resource: SubResource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<FrontendEndpointProperties>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing)]
    pub type_: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FrontendEndpointProperties {
    #[serde(flatten)]
    pub frontend_endpoint_update_parameters: FrontendEndpointUpdateParameters,
    #[serde(rename = "resourceState", skip_serializing)]
    pub resource_state: Option<ResourceState>,
    #[serde(rename = "customHttpsProvisioningState", skip_serializing)]
    pub custom_https_provisioning_state: Option<frontend_endpoint_properties::CustomHttpsProvisioningState>,
    #[serde(rename = "customHttpsProvisioningSubstate", skip_serializing)]
    pub custom_https_provisioning_substate: Option<frontend_endpoint_properties::CustomHttpsProvisioningSubstate>,
    #[serde(rename = "customHttpsConfiguration", skip_serializing_if = "Option::is_none")]
    pub custom_https_configuration: Option<CustomHttpsConfiguration>,
}
pub mod frontend_endpoint_properties {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum CustomHttpsProvisioningState {
        Enabling,
        Enabled,
        Disabling,
        Disabled,
        Failed,
    }
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum CustomHttpsProvisioningSubstate {
        SubmittingDomainControlValidationRequest,
        PendingDomainControlValidationREquestApproval,
        DomainControlValidationRequestApproved,
        DomainControlValidationRequestRejected,
        DomainControlValidationRequestTimedOut,
        IssuingCertificate,
        DeployingCertificate,
        CertificateDeployed,
        DeletingCertificate,
        CertificateDeleted,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FrontendEndpointUpdateParameters {
    #[serde(rename = "hostName", skip_serializing_if = "Option::is_none")]
    pub host_name: Option<String>,
    #[serde(rename = "sessionAffinityEnabledState", skip_serializing_if = "Option::is_none")]
    pub session_affinity_enabled_state: Option<frontend_endpoint_update_parameters::SessionAffinityEnabledState>,
    #[serde(rename = "sessionAffinityTtlSeconds", skip_serializing_if = "Option::is_none")]
    pub session_affinity_ttl_seconds: Option<i64>,
    #[serde(rename = "webApplicationFirewallPolicyLink", skip_serializing_if = "Option::is_none")]
    pub web_application_firewall_policy_link: Option<frontend_endpoint_update_parameters::WebApplicationFirewallPolicyLink>,
}
pub mod frontend_endpoint_update_parameters {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum SessionAffinityEnabledState {
        Enabled,
        Disabled,
    }
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub struct WebApplicationFirewallPolicyLink {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FrontendEndpointsListResult {
    #[serde(skip_serializing)]
    pub value: Vec<FrontendEndpoint>,
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BackendPoolsSettings {
    #[serde(rename = "enforceCertificateNameCheck", skip_serializing_if = "Option::is_none")]
    pub enforce_certificate_name_check: Option<backend_pools_settings::EnforceCertificateNameCheck>,
    #[serde(rename = "sendRecvTimeoutSeconds", skip_serializing_if = "Option::is_none")]
    pub send_recv_timeout_seconds: Option<i64>,
}
pub mod backend_pools_settings {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum EnforceCertificateNameCheck {
        Enabled,
        Disabled,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ResourceState {
    Creating,
    Enabling,
    Enabled,
    Disabling,
    Disabled,
    Deleting,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ValidateCustomDomainInput {
    #[serde(rename = "hostName")]
    pub host_name: String,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ValidateCustomDomainOutput {
    #[serde(rename = "customDomainValidated", skip_serializing)]
    pub custom_domain_validated: Option<bool>,
    #[serde(skip_serializing)]
    pub reason: Option<String>,
    #[serde(skip_serializing)]
    pub message: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ErrorResponse {
    #[serde(skip_serializing)]
    pub code: Option<String>,
    #[serde(skip_serializing)]
    pub message: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CheckNameAvailabilityInput {
    pub name: String,
    #[serde(rename = "type")]
    pub type_: ResourceType,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CheckNameAvailabilityOutput {
    #[serde(rename = "nameAvailability", skip_serializing)]
    pub name_availability: Option<check_name_availability_output::NameAvailability>,
    #[serde(skip_serializing)]
    pub reason: Option<String>,
    #[serde(skip_serializing)]
    pub message: Option<String>,
}
pub mod check_name_availability_output {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum NameAvailability {
        Available,
        Unavailable,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ResourceType {
    #[serde(rename = "Microsoft.Network/frontDoors")]
    MicrosoftNetworkFrontDoors,
    #[serde(rename = "Microsoft.Network/frontDoors/frontendEndpoints")]
    MicrosoftNetworkFrontDoorsFrontendEndpoints,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ErrorDetails {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Error {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<ErrorDetails>,
    #[serde(rename = "innerError", skip_serializing_if = "Option::is_none")]
    pub inner_error: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AzureAsyncOperationResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<azure_async_operation_result::Status>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Error>,
}
pub mod azure_async_operation_result {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Status {
        InProgress,
        Succeeded,
        Failed,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SubResource {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TagsObject {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WebApplicationFirewallPolicy {
    #[serde(flatten)]
    pub resource: Resource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<WebApplicationFirewallPolicyProperties>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WebApplicationFirewallPolicyProperties {
    #[serde(rename = "policySettings", skip_serializing_if = "Option::is_none")]
    pub policy_settings: Option<PolicySettings>,
    #[serde(rename = "customRules", skip_serializing_if = "Option::is_none")]
    pub custom_rules: Option<CustomRuleList>,
    #[serde(rename = "managedRules", skip_serializing_if = "Option::is_none")]
    pub managed_rules: Option<ManagedRuleSetList>,
    #[serde(rename = "frontendEndpointLinks", skip_serializing)]
    pub frontend_endpoint_links: Vec<FrontendEndpointLink>,
    #[serde(rename = "provisioningState", skip_serializing)]
    pub provisioning_state: Option<String>,
    #[serde(rename = "resourceState", skip_serializing)]
    pub resource_state: Option<web_application_firewall_policy_properties::ResourceState>,
}
pub mod web_application_firewall_policy_properties {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum ResourceState {
        Creating,
        Enabling,
        Enabled,
        Disabling,
        Disabled,
        Deleting,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WebApplicationFirewallPolicyList {
    #[serde(skip_serializing)]
    pub value: Vec<WebApplicationFirewallPolicy>,
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PolicySettings {
    #[serde(rename = "enabledState", skip_serializing_if = "Option::is_none")]
    pub enabled_state: Option<policy_settings::EnabledState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<policy_settings::Mode>,
    #[serde(rename = "redirectUrl", skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
    #[serde(rename = "customBlockResponseStatusCode", skip_serializing_if = "Option::is_none")]
    pub custom_block_response_status_code: Option<i64>,
    #[serde(rename = "customBlockResponseBody", skip_serializing_if = "Option::is_none")]
    pub custom_block_response_body: Option<String>,
}
pub mod policy_settings {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum EnabledState {
        Disabled,
        Enabled,
    }
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Mode {
        Prevention,
        Detection,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CustomRuleList {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<CustomRule>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CustomRule {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub priority: i64,
    #[serde(rename = "enabledState", skip_serializing_if = "Option::is_none")]
    pub enabled_state: Option<custom_rule::EnabledState>,
    #[serde(rename = "ruleType")]
    pub rule_type: custom_rule::RuleType,
    #[serde(rename = "rateLimitDurationInMinutes", skip_serializing_if = "Option::is_none")]
    pub rate_limit_duration_in_minutes: Option<i64>,
    #[serde(rename = "rateLimitThreshold", skip_serializing_if = "Option::is_none")]
    pub rate_limit_threshold: Option<i64>,
    #[serde(rename = "matchConditions")]
    pub match_conditions: Vec<MatchCondition>,
    pub action: ActionType,
}
pub mod custom_rule {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum EnabledState {
        Disabled,
        Enabled,
    }
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum RuleType {
        MatchRule,
        RateLimitRule,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum TransformType {
    Lowercase,
    Uppercase,
    Trim,
    UrlDecode,
    UrlEncode,
    RemoveNulls,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MatchCondition {
    #[serde(rename = "matchVariable")]
    pub match_variable: match_condition::MatchVariable,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
    pub operator: match_condition::Operator,
    #[serde(rename = "negateCondition", skip_serializing_if = "Option::is_none")]
    pub negate_condition: Option<bool>,
    #[serde(rename = "matchValue")]
    pub match_value: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub transforms: Vec<TransformType>,
}
pub mod match_condition {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum MatchVariable {
        RemoteAddr,
        RequestMethod,
        QueryString,
        PostArgs,
        RequestUri,
        RequestHeader,
        RequestBody,
        Cookies,
        SocketAddr,
    }
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Operator {
        Any,
        #[serde(rename = "IPMatch")]
        IpMatch,
        GeoMatch,
        Equal,
        Contains,
        LessThan,
        GreaterThan,
        LessThanOrEqual,
        GreaterThanOrEqual,
        BeginsWith,
        EndsWith,
        RegEx,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ManagedRuleSetList {
    #[serde(rename = "managedRuleSets", skip_serializing_if = "Vec::is_empty")]
    pub managed_rule_sets: Vec<ManagedRuleSet>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ManagedRuleSet {
    #[serde(rename = "ruleSetType")]
    pub rule_set_type: String,
    #[serde(rename = "ruleSetVersion")]
    pub rule_set_version: String,
    #[serde(rename = "ruleGroupOverrides", skip_serializing_if = "Vec::is_empty")]
    pub rule_group_overrides: Vec<ManagedRuleGroupOverride>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ManagedRuleGroupOverride {
    #[serde(rename = "ruleGroupName")]
    pub rule_group_name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<ManagedRuleOverride>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ManagedRuleOverride {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    #[serde(rename = "enabledState", skip_serializing_if = "Option::is_none")]
    pub enabled_state: Option<ManagedRuleEnabledState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<ActionType>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ManagedRuleSetDefinitionList {
    #[serde(skip_serializing)]
    pub value: Vec<ManagedRuleSetDefinition>,
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ManagedRuleSetDefinition {
    #[serde(flatten)]
    pub resource: Resource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<ManagedRuleSetDefinitionProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ManagedRuleSetDefinitionProperties {
    #[serde(rename = "provisioningState", skip_serializing)]
    pub provisioning_state: Option<String>,
    #[serde(rename = "ruleSetId", skip_serializing)]
    pub rule_set_id: Option<String>,
    #[serde(rename = "ruleSetType", skip_serializing)]
    pub rule_set_type: Option<String>,
    #[serde(rename = "ruleSetVersion", skip_serializing)]
    pub rule_set_version: Option<String>,
    #[serde(rename = "ruleGroups", skip_serializing)]
    pub rule_groups: Vec<ManagedRuleGroupDefinition>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ManagedRuleGroupDefinition {
    #[serde(rename = "ruleGroupName", skip_serializing)]
    pub rule_group_name: Option<String>,
    #[serde(skip_serializing)]
    pub description: Option<String>,
    #[serde(skip_serializing)]
    pub rules: Vec<ManagedRuleDefinition>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ManagedRuleDefinition {
    #[serde(rename = "ruleId", skip_serializing)]
    pub rule_id: Option<String>,
    #[serde(rename = "defaultState", skip_serializing_if = "Option::is_none")]
    pub default_state: Option<ManagedRuleEnabledState>,
    #[serde(rename = "defaultAction", skip_serializing_if = "Option::is_none")]
    pub default_action: Option<ActionType>,
    #[serde(skip_serializing)]
    pub description: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ActionType {
    Allow,
    Block,
    Log,
    Redirect,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ManagedRuleEnabledState {
    Disabled,
    Enabled,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FrontendEndpointLink {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}
