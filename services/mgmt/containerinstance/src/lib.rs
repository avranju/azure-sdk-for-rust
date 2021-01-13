#![doc = "generated by AutoRust 0.1.0"]
#[cfg(feature = "package-2020-11")]
mod package_2020_11;
#[cfg(feature = "package-2020-11")]
pub use package_2020_11::{models, operations, API_VERSION};
#[cfg(feature = "package-2019-12")]
mod package_2019_12;
#[cfg(feature = "package-2019-12")]
pub use package_2019_12::{models, operations, API_VERSION};
#[cfg(feature = "package-2018-10")]
mod package_2018_10;
#[cfg(feature = "package-2018-10")]
pub use package_2018_10::{models, operations, API_VERSION};
#[cfg(feature = "package-2018-09")]
mod package_2018_09;
#[cfg(feature = "package-2018-09")]
pub use package_2018_09::{models, operations, API_VERSION};
#[cfg(feature = "package-2018-06")]
mod package_2018_06;
#[cfg(feature = "package-2018-06")]
pub use package_2018_06::{models, operations, API_VERSION};
#[cfg(feature = "package-2018-04")]
mod package_2018_04;
#[cfg(feature = "package-2018-04")]
pub use package_2018_04::{models, operations, API_VERSION};
#[cfg(feature = "package-2018-02-preview")]
mod package_2018_02_preview;
#[cfg(feature = "package-2018-02-preview")]
pub use package_2018_02_preview::{models, operations, API_VERSION};
#[cfg(feature = "package-2017-12-preview")]
mod package_2017_12_preview;
#[cfg(feature = "package-2017-12-preview")]
pub use package_2017_12_preview::{models, operations, API_VERSION};
#[cfg(feature = "package-2017-10-preview")]
mod package_2017_10_preview;
#[cfg(feature = "package-2017-10-preview")]
pub use package_2017_10_preview::{models, operations, API_VERSION};
#[cfg(feature = "package-2017-08-preview")]
mod package_2017_08_preview;
#[cfg(feature = "package-2017-08-preview")]
pub use package_2017_08_preview::{models, operations, API_VERSION};
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
