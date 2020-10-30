#![doc = "generated by AutoRust 0.1.0"]
#![allow(non_camel_case_types)]
#![allow(unused_imports)]
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OperationsListResult {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<Operation>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Operation {
    #[serde(skip_serializing)]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<operation::Display>,
}
pub mod operation {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub struct Display {
        #[serde(skip_serializing)]
        pub description: Option<String>,
        #[serde(skip_serializing)]
        pub operation: Option<String>,
        #[serde(skip_serializing)]
        pub provider: Option<String>,
        #[serde(skip_serializing)]
        pub resource: Option<String>,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServicesListResult {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<Service>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Service {
    #[serde(skip_serializing)]
    pub id: Option<String>,
    #[serde(skip_serializing)]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing)]
    pub type_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<ServiceProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServiceProperties {
    #[serde(rename = "displayName", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProblemClassificationsListResult {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<ProblemClassification>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProblemClassification {
    #[serde(skip_serializing)]
    pub id: Option<String>,
    #[serde(skip_serializing)]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing)]
    pub type_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<ProblemClassificationProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProblemClassificationProperties {
    #[serde(rename = "displayName", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CheckNameAvailabilityInput {
    pub name: String,
    #[serde(rename = "type")]
    pub type_: check_name_availability_input::Type,
}
pub mod check_name_availability_input {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Type {
        #[serde(rename = "Microsoft.Support/supportTickets")]
        MicrosoftSupportSupportTickets,
        #[serde(rename = "Microsoft.Support/communications")]
        MicrosoftSupportCommunications,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CheckNameAvailabilityOutput {
    #[serde(rename = "nameAvailable", skip_serializing)]
    pub name_available: Option<bool>,
    #[serde(skip_serializing)]
    pub reason: Option<String>,
    #[serde(skip_serializing)]
    pub message: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SupportTicketsListResult {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<SupportTicketDetails>,
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SupportTicketDetails {
    #[serde(skip_serializing)]
    pub id: Option<String>,
    #[serde(skip_serializing)]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing)]
    pub type_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SupportTicketDetailsProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CommunicationsListResult {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<CommunicationDetails>,
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CommunicationDetails {
    #[serde(skip_serializing)]
    pub id: Option<String>,
    #[serde(skip_serializing)]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing)]
    pub type_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<CommunicationDetailsProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CommunicationDetailsProperties {
    #[serde(rename = "communicationType", skip_serializing)]
    pub communication_type: Option<communication_details_properties::CommunicationType>,
    #[serde(rename = "communicationDirection", skip_serializing)]
    pub communication_direction: Option<communication_details_properties::CommunicationDirection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
    pub subject: String,
    pub body: String,
    #[serde(rename = "createdDate", skip_serializing)]
    pub created_date: Option<String>,
}
pub mod communication_details_properties {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum CommunicationType {
        #[serde(rename = "web")]
        Web,
        #[serde(rename = "phone")]
        Phone,
    }
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum CommunicationDirection {
        #[serde(rename = "inbound")]
        Inbound,
        #[serde(rename = "outbound")]
        Outbound,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SupportTicketDetailsProperties {
    #[serde(rename = "supportTicketId", skip_serializing_if = "Option::is_none")]
    pub support_ticket_id: Option<String>,
    pub description: String,
    #[serde(rename = "problemClassificationId")]
    pub problem_classification_id: String,
    #[serde(rename = "problemClassificationDisplayName", skip_serializing)]
    pub problem_classification_display_name: Option<String>,
    pub severity: support_ticket_details_properties::Severity,
    #[serde(rename = "enrollmentId", skip_serializing)]
    pub enrollment_id: Option<String>,
    #[serde(rename = "productionOutage", skip_serializing)]
    pub production_outage: Option<bool>,
    #[serde(rename = "require24X7Response", skip_serializing_if = "Option::is_none")]
    pub require24_x7_response: Option<bool>,
    #[serde(rename = "contactDetails")]
    pub contact_details: ContactProfile,
    #[serde(rename = "serviceLevelAgreement", skip_serializing_if = "Option::is_none")]
    pub service_level_agreement: Option<ServiceLevelAgreement>,
    #[serde(rename = "supportEngineer", skip_serializing_if = "Option::is_none")]
    pub support_engineer: Option<SupportEngineer>,
    #[serde(rename = "supportPlanType", skip_serializing)]
    pub support_plan_type: Option<String>,
    pub title: String,
    #[serde(rename = "problemStartTime", skip_serializing_if = "Option::is_none")]
    pub problem_start_time: Option<String>,
    #[serde(rename = "serviceId")]
    pub service_id: String,
    #[serde(rename = "serviceDisplayName", skip_serializing)]
    pub service_display_name: Option<String>,
    #[serde(skip_serializing)]
    pub status: Option<String>,
    #[serde(rename = "createdDate", skip_serializing)]
    pub created_date: Option<String>,
    #[serde(rename = "modifiedDate", skip_serializing)]
    pub modified_date: Option<String>,
    #[serde(rename = "technicalTicketDetails", skip_serializing_if = "Option::is_none")]
    pub technical_ticket_details: Option<TechnicalTicketDetails>,
    #[serde(rename = "quotaTicketDetails", skip_serializing_if = "Option::is_none")]
    pub quota_ticket_details: Option<QuotaTicketDetails>,
}
pub mod support_ticket_details_properties {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Severity {
        #[serde(rename = "minimal")]
        Minimal,
        #[serde(rename = "moderate")]
        Moderate,
        #[serde(rename = "critical")]
        Critical,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServiceLevelAgreement {
    #[serde(rename = "startTime", skip_serializing)]
    pub start_time: Option<String>,
    #[serde(rename = "expirationTime", skip_serializing)]
    pub expiration_time: Option<String>,
    #[serde(rename = "slaMinutes", skip_serializing)]
    pub sla_minutes: Option<i64>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SupportEngineer {
    #[serde(rename = "emailAddress", skip_serializing)]
    pub email_address: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExceptionResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ServiceError>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServiceError {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing)]
    pub details: Vec<ServiceErrorDetail>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServiceErrorDetail {
    #[serde(skip_serializing)]
    pub code: Option<String>,
    #[serde(skip_serializing)]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ContactProfile {
    #[serde(rename = "firstName")]
    pub first_name: String,
    #[serde(rename = "lastName")]
    pub last_name: String,
    #[serde(rename = "preferredContactMethod")]
    pub preferred_contact_method: contact_profile::PreferredContactMethod,
    #[serde(rename = "primaryEmailAddress")]
    pub primary_email_address: String,
    #[serde(rename = "additionalEmailAddresses", skip_serializing_if = "Vec::is_empty")]
    pub additional_email_addresses: Vec<String>,
    #[serde(rename = "phoneNumber", skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    #[serde(rename = "preferredTimeZone")]
    pub preferred_time_zone: String,
    pub country: String,
    #[serde(rename = "preferredSupportLanguage")]
    pub preferred_support_language: String,
}
pub mod contact_profile {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum PreferredContactMethod {
        #[serde(rename = "email")]
        Email,
        #[serde(rename = "phone")]
        Phone,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UpdateContactProfile {
    #[serde(rename = "firstName", skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(rename = "lastName", skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(rename = "preferredContactMethod", skip_serializing_if = "Option::is_none")]
    pub preferred_contact_method: Option<update_contact_profile::PreferredContactMethod>,
    #[serde(rename = "primaryEmailAddress", skip_serializing_if = "Option::is_none")]
    pub primary_email_address: Option<String>,
    #[serde(rename = "additionalEmailAddresses", skip_serializing_if = "Vec::is_empty")]
    pub additional_email_addresses: Vec<String>,
    #[serde(rename = "phoneNumber", skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    #[serde(rename = "preferredTimeZone", skip_serializing_if = "Option::is_none")]
    pub preferred_time_zone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(rename = "preferredSupportLanguage", skip_serializing_if = "Option::is_none")]
    pub preferred_support_language: Option<String>,
}
pub mod update_contact_profile {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum PreferredContactMethod {
        #[serde(rename = "email")]
        Email,
        #[serde(rename = "phone")]
        Phone,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TechnicalTicketDetails {
    #[serde(rename = "resourceId", skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct QuotaTicketDetails {
    #[serde(rename = "quotaChangeRequestSubType", skip_serializing_if = "Option::is_none")]
    pub quota_change_request_sub_type: Option<String>,
    #[serde(rename = "quotaChangeRequestVersion", skip_serializing_if = "Option::is_none")]
    pub quota_change_request_version: Option<String>,
    #[serde(rename = "quotaChangeRequests", skip_serializing_if = "Vec::is_empty")]
    pub quota_change_requests: Vec<QuotaChangeRequest>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct QuotaChangeRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UpdateSupportTicket {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<update_support_ticket::Severity>,
    #[serde(rename = "contactDetails", skip_serializing_if = "Option::is_none")]
    pub contact_details: Option<UpdateContactProfile>,
}
pub mod update_support_ticket {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Severity {
        #[serde(rename = "minimal")]
        Minimal,
        #[serde(rename = "moderate")]
        Moderate,
        #[serde(rename = "critical")]
        Critical,
    }
}
