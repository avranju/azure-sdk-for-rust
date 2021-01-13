#![doc = "generated by AutoRust 0.1.0"]
#[cfg(feature = "package-2020-12")]
mod package_2020_12;
#[cfg(feature = "package-2020-12")]
pub use package_2020_12::{models, operations, API_VERSION};
#[cfg(feature = "package-2020-02")]
mod package_2020_02;
#[cfg(feature = "package-2020-02")]
pub use package_2020_02::{models, operations, API_VERSION};
#[cfg(feature = "package-2019-06")]
mod package_2019_06;
#[cfg(feature = "package-2019-06")]
pub use package_2019_06::{models, operations, API_VERSION};
#[cfg(feature = "package-2019-05")]
mod package_2019_05;
#[cfg(feature = "package-2019-05")]
pub use package_2019_05::{models, operations, API_VERSION};
#[cfg(feature = "package-2017-07")]
mod package_2017_07;
#[cfg(feature = "package-2017-07")]
pub use package_2017_07::{models, operations, API_VERSION};
#[cfg(feature = "package-2016-06")]
mod package_2016_06;
#[cfg(feature = "package-2016-06")]
pub use package_2016_06::{models, operations, API_VERSION};
#[cfg(feature = "package-2016-08")]
mod package_2016_08;
#[cfg(feature = "package-2016-08")]
pub use package_2016_08::{models, operations, API_VERSION};
#[cfg(feature = "package-2016-12")]
mod package_2016_12;
#[cfg(feature = "package-2016-12")]
pub use package_2016_12::{models, operations, API_VERSION};
#[cfg(feature = "package-2017-07-only")]
mod package_2017_07_only;
#[cfg(feature = "package-2017-07-only")]
pub use package_2017_07_only::{models, operations, API_VERSION};
pub struct OperationConfig {
    pub api_version: String,
    pub client: reqwest::Client,
    pub base_path: String,
    pub token_credential: Option<Box<dyn azure_core::TokenCredential>>,
    pub token_credential_resource: String,
}
impl OperationConfig {
    pub fn new(token_credential: Box<dyn azure_core::TokenCredential>) -> Self {
        Self {
            token_credential: Some(token_credential),
            ..Default::default()
        }
    }
}
impl Default for OperationConfig {
    fn default() -> Self {
        Self {
            api_version: API_VERSION.to_owned(),
            client: reqwest::Client::new(),
            base_path: "https://management.azure.com".to_owned(),
            token_credential: None,
            token_credential_resource: "https://management.azure.com/".to_owned(),
        }
    }
}
