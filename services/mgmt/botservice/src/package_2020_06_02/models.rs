#![doc = "generated by AutoRust 0.1.0"]
#![allow(non_camel_case_types)]
#![allow(unused_imports)]
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Resource {
    #[serde(skip_serializing)]
    pub id: Option<String>,
    #[serde(skip_serializing)]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(rename = "type", skip_serializing)]
    pub type_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sku: Option<Sku>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<Kind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Sku {
    pub name: SkuName,
    #[serde(skip_serializing)]
    pub tier: Option<sku::Tier>,
}
pub mod sku {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Tier {
        Free,
        Standard,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum SkuName {
    F0,
    S1,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Kind {
    #[serde(rename = "sdk")]
    Sdk,
    #[serde(rename = "designer")]
    Designer,
    #[serde(rename = "bot")]
    Bot,
    #[serde(rename = "function")]
    Function,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Bot {
    #[serde(flatten)]
    pub resource: Resource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<BotProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BotProperties {
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "iconUrl", skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,
    pub endpoint: String,
    #[serde(rename = "endpointVersion", skip_serializing)]
    pub endpoint_version: Option<String>,
    #[serde(rename = "msaAppId")]
    pub msa_app_id: String,
    #[serde(rename = "configuredChannels", skip_serializing)]
    pub configured_channels: Vec<String>,
    #[serde(rename = "enabledChannels", skip_serializing)]
    pub enabled_channels: Vec<String>,
    #[serde(rename = "developerAppInsightKey", skip_serializing_if = "Option::is_none")]
    pub developer_app_insight_key: Option<String>,
    #[serde(rename = "developerAppInsightsApiKey", skip_serializing_if = "Option::is_none")]
    pub developer_app_insights_api_key: Option<String>,
    #[serde(rename = "developerAppInsightsApplicationId", skip_serializing_if = "Option::is_none")]
    pub developer_app_insights_application_id: Option<String>,
    #[serde(rename = "luisAppIds", skip_serializing_if = "Vec::is_empty")]
    pub luis_app_ids: Vec<String>,
    #[serde(rename = "luisKey", skip_serializing_if = "Option::is_none")]
    pub luis_key: Option<String>,
    #[serde(rename = "isCmekEnabled", skip_serializing_if = "Option::is_none")]
    pub is_cmek_enabled: Option<bool>,
    #[serde(rename = "cmekKeyVaultUrl", skip_serializing_if = "Option::is_none")]
    pub cmek_key_vault_url: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BotResponseList {
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
    #[serde(skip_serializing)]
    pub value: Vec<Bot>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BotChannel {
    #[serde(flatten)]
    pub resource: Resource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<Channel>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Channel {
    #[serde(rename = "channelName")]
    pub channel_name: String,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AlexaChannel {
    #[serde(flatten)]
    pub channel: Channel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<AlexaChannelProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AlexaChannelProperties {
    #[serde(rename = "alexaSkillId")]
    pub alexa_skill_id: String,
    #[serde(rename = "urlFragment", skip_serializing)]
    pub url_fragment: Option<String>,
    #[serde(rename = "serviceEndpointUri", skip_serializing)]
    pub service_endpoint_uri: Option<String>,
    #[serde(rename = "isEnabled")]
    pub is_enabled: bool,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FacebookChannel {
    #[serde(flatten)]
    pub channel: Channel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<FacebookChannelProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FacebookChannelProperties {
    #[serde(rename = "verifyToken", skip_serializing)]
    pub verify_token: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pages: Vec<FacebookPage>,
    #[serde(rename = "appId")]
    pub app_id: String,
    #[serde(rename = "appSecret", skip_serializing_if = "Option::is_none")]
    pub app_secret: Option<String>,
    #[serde(rename = "callbackUrl", skip_serializing)]
    pub callback_url: Option<String>,
    #[serde(rename = "isEnabled")]
    pub is_enabled: bool,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FacebookPage {
    pub id: String,
    #[serde(rename = "accessToken", skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EmailChannel {
    #[serde(flatten)]
    pub channel: Channel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<EmailChannelProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EmailChannelProperties {
    #[serde(rename = "emailAddress")]
    pub email_address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(rename = "isEnabled")]
    pub is_enabled: bool,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MsTeamsChannel {
    #[serde(flatten)]
    pub channel: Channel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<MsTeamsChannelProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MsTeamsChannelProperties {
    #[serde(rename = "enableCalling", skip_serializing_if = "Option::is_none")]
    pub enable_calling: Option<bool>,
    #[serde(rename = "callingWebHook", skip_serializing_if = "Option::is_none")]
    pub calling_web_hook: Option<String>,
    #[serde(rename = "isEnabled")]
    pub is_enabled: bool,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SkypeChannel {
    #[serde(flatten)]
    pub channel: Channel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SkypeChannelProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SkypeChannelProperties {
    #[serde(rename = "enableMessaging", skip_serializing_if = "Option::is_none")]
    pub enable_messaging: Option<bool>,
    #[serde(rename = "enableMediaCards", skip_serializing_if = "Option::is_none")]
    pub enable_media_cards: Option<bool>,
    #[serde(rename = "enableVideo", skip_serializing_if = "Option::is_none")]
    pub enable_video: Option<bool>,
    #[serde(rename = "enableCalling", skip_serializing_if = "Option::is_none")]
    pub enable_calling: Option<bool>,
    #[serde(rename = "enableScreenSharing", skip_serializing_if = "Option::is_none")]
    pub enable_screen_sharing: Option<bool>,
    #[serde(rename = "enableGroups", skip_serializing_if = "Option::is_none")]
    pub enable_groups: Option<bool>,
    #[serde(rename = "groupsMode", skip_serializing_if = "Option::is_none")]
    pub groups_mode: Option<String>,
    #[serde(rename = "callingWebHook", skip_serializing_if = "Option::is_none")]
    pub calling_web_hook: Option<String>,
    #[serde(rename = "isEnabled")]
    pub is_enabled: bool,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KikChannel {
    #[serde(flatten)]
    pub channel: Channel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<KikChannelProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KikChannelProperties {
    #[serde(rename = "userName")]
    pub user_name: String,
    #[serde(rename = "apiKey", skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    #[serde(rename = "isValidated", skip_serializing_if = "Option::is_none")]
    pub is_validated: Option<bool>,
    #[serde(rename = "isEnabled")]
    pub is_enabled: bool,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WebChatChannel {
    #[serde(flatten)]
    pub channel: Channel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<WebChatChannelProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WebChatChannelProperties {
    #[serde(rename = "webChatEmbedCode", skip_serializing)]
    pub web_chat_embed_code: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sites: Vec<WebChatSite>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DirectLineChannel {
    #[serde(flatten)]
    pub channel: Channel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<DirectLineChannelProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DirectLineChannelProperties {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sites: Vec<DirectLineSite>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TelegramChannel {
    #[serde(flatten)]
    pub channel: Channel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<TelegramChannelProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TelegramChannelProperties {
    #[serde(rename = "accessToken", skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(rename = "isValidated", skip_serializing_if = "Option::is_none")]
    pub is_validated: Option<bool>,
    #[serde(rename = "isEnabled")]
    pub is_enabled: bool,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SmsChannel {
    #[serde(flatten)]
    pub channel: Channel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SmsChannelProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SmsChannelProperties {
    pub phone: String,
    #[serde(rename = "accountSID")]
    pub account_sid: String,
    #[serde(rename = "authToken", skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
    #[serde(rename = "isValidated", skip_serializing_if = "Option::is_none")]
    pub is_validated: Option<bool>,
    #[serde(rename = "isEnabled")]
    pub is_enabled: bool,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SlackChannel {
    #[serde(flatten)]
    pub channel: Channel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SlackChannelProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SlackChannelProperties {
    #[serde(rename = "clientId", skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(rename = "clientSecret", skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(rename = "verificationToken", skip_serializing_if = "Option::is_none")]
    pub verification_token: Option<String>,
    #[serde(rename = "landingPageUrl", skip_serializing_if = "Option::is_none")]
    pub landing_page_url: Option<String>,
    #[serde(rename = "redirectAction", skip_serializing)]
    pub redirect_action: Option<String>,
    #[serde(rename = "lastSubmissionId", skip_serializing)]
    pub last_submission_id: Option<String>,
    #[serde(rename = "registerBeforeOAuthFlow", skip_serializing)]
    pub register_before_o_auth_flow: Option<bool>,
    #[serde(rename = "isValidated", skip_serializing)]
    pub is_validated: Option<bool>,
    #[serde(rename = "signingSecret", skip_serializing_if = "Option::is_none")]
    pub signing_secret: Option<String>,
    #[serde(rename = "isEnabled")]
    pub is_enabled: bool,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LineChannel {
    #[serde(flatten)]
    pub channel: Channel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<LineChannelProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LineChannelProperties {
    #[serde(rename = "lineRegistrations")]
    pub line_registrations: Vec<LineRegistration>,
    #[serde(rename = "callbackUrl", skip_serializing)]
    pub callback_url: Option<String>,
    #[serde(rename = "isValidated", skip_serializing)]
    pub is_validated: Option<bool>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LineRegistration {
    #[serde(rename = "generatedId", skip_serializing)]
    pub generated_id: Option<String>,
    #[serde(rename = "channelSecret", skip_serializing_if = "Option::is_none")]
    pub channel_secret: Option<String>,
    #[serde(rename = "channelAccessToken", skip_serializing_if = "Option::is_none")]
    pub channel_access_token: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DirectLineSpeechChannel {
    #[serde(flatten)]
    pub channel: Channel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<DirectLineSpeechChannelProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DirectLineSpeechChannelProperties {
    #[serde(rename = "cognitiveServicesSubscriptionId")]
    pub cognitive_services_subscription_id: String,
    #[serde(rename = "isEnabled", skip_serializing_if = "Option::is_none")]
    pub is_enabled: Option<bool>,
    #[serde(rename = "customVoiceDeploymentId", skip_serializing_if = "Option::is_none")]
    pub custom_voice_deployment_id: Option<String>,
    #[serde(rename = "customSpeechModelId", skip_serializing_if = "Option::is_none")]
    pub custom_speech_model_id: Option<String>,
    #[serde(rename = "isDefaultBotForCogSvcAccount", skip_serializing_if = "Option::is_none")]
    pub is_default_bot_for_cog_svc_account: Option<bool>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ChannelResponseList {
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
    #[serde(skip_serializing)]
    pub value: Vec<BotChannel>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WebChatSite {
    #[serde(rename = "siteId", skip_serializing)]
    pub site_id: Option<String>,
    #[serde(rename = "siteName")]
    pub site_name: String,
    #[serde(skip_serializing)]
    pub key: Option<String>,
    #[serde(skip_serializing)]
    pub key2: Option<String>,
    #[serde(rename = "isEnabled")]
    pub is_enabled: bool,
    #[serde(rename = "enablePreview")]
    pub enable_preview: bool,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DirectLineSite {
    #[serde(rename = "siteId", skip_serializing)]
    pub site_id: Option<String>,
    #[serde(rename = "siteName")]
    pub site_name: String,
    #[serde(skip_serializing)]
    pub key: Option<String>,
    #[serde(skip_serializing)]
    pub key2: Option<String>,
    #[serde(rename = "isEnabled")]
    pub is_enabled: bool,
    #[serde(rename = "isV1Enabled")]
    pub is_v1_enabled: bool,
    #[serde(rename = "isV3Enabled")]
    pub is_v3_enabled: bool,
    #[serde(rename = "isSecureSiteEnabled", skip_serializing_if = "Option::is_none")]
    pub is_secure_site_enabled: Option<bool>,
    #[serde(rename = "trustedOrigins", skip_serializing_if = "Vec::is_empty")]
    pub trusted_origins: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SiteInfo {
    #[serde(rename = "siteName")]
    pub site_name: String,
    pub key: site_info::Key,
}
pub mod site_info {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Key {
        #[serde(rename = "key1")]
        Key1,
        #[serde(rename = "key2")]
        Key2,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConnectionItemName {
    #[serde(skip_serializing)]
    pub name: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConnectionSettingParameter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConnectionSettingProperties {
    #[serde(rename = "clientId", skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(rename = "settingId", skip_serializing)]
    pub setting_id: Option<String>,
    #[serde(rename = "clientSecret", skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<String>,
    #[serde(rename = "serviceProviderId", skip_serializing_if = "Option::is_none")]
    pub service_provider_id: Option<String>,
    #[serde(rename = "serviceProviderDisplayName", skip_serializing_if = "Option::is_none")]
    pub service_provider_display_name: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub parameters: Vec<ConnectionSettingParameter>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConnectionSetting {
    #[serde(flatten)]
    pub resource: Resource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<ConnectionSettingProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConnectionSettingResponseList {
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
    #[serde(skip_serializing)]
    pub value: Vec<ConnectionSetting>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServiceProviderResponseList {
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
    #[serde(skip_serializing)]
    pub value: Vec<ServiceProvider>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServiceProviderParameter {
    #[serde(skip_serializing)]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing)]
    pub type_: Option<String>,
    #[serde(rename = "displayName", skip_serializing)]
    pub display_name: Option<String>,
    #[serde(skip_serializing)]
    pub description: Option<String>,
    #[serde(rename = "helpUrl", skip_serializing)]
    pub help_url: Option<String>,
    #[serde(skip_serializing)]
    pub default: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServiceProviderProperties {
    #[serde(skip_serializing)]
    pub id: Option<String>,
    #[serde(rename = "displayName", skip_serializing)]
    pub display_name: Option<String>,
    #[serde(rename = "serviceProviderName", skip_serializing)]
    pub service_provider_name: Option<String>,
    #[serde(rename = "devPortalUrl", skip_serializing)]
    pub dev_portal_url: Option<String>,
    #[serde(rename = "iconUrl", skip_serializing)]
    pub icon_url: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub parameters: Vec<ServiceProviderParameter>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServiceProvider {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<ServiceProviderProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Error {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OperationEntityListResult {
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<OperationEntity>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OperationEntity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<OperationDisplayInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<serde_json::Value>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OperationDisplayInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CheckNameAvailabilityRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CheckNameAvailabilityResponseBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}
