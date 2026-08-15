//! cdylib sync bridge — adapts the async [`OpenapiBackendPlugin`]
//! ([`mcpg_plugin_protocol::BackendPlugin`]) onto the sync FFI trait the
//! cdylib vtable expects ([`SyncBackendPlugin`]).
//!
//! Unlike mock, openapi consumes plugin-level config: `config_json` carries
//! the `sources` registry, so the factory forwards it to
//! [`OpenapiBackendPlugin::from_config_json`]. `input_schema` /
//! `output_schema` are forwarded too — the gateway reads them at boot to
//! populate the tool descriptor from the operation, so the operator does
//! not hand-write the schema. The make-time [`HostHandle`] is wrapped as an
//! `Arc<dyn BackendHost>` for per-call `cred://` resolution.

use std::sync::Arc;

use mcpg_plugin_protocol::{
    BackendError, BackendPlugin, BackendRequest, BackendResponse, PluginManifest,
};
use mcpg_plugin_sdk::ffi::SyncBackendPlugin;
use mcpg_plugin_sdk::{HostHandle, HostHandleBackendHost};
use serde_json::Value;

use crate::OpenapiBackendPlugin;

/// `SyncBackendPlugin` bridge over [`OpenapiBackendPlugin`].
pub struct OpenapiBackendCdylib {
    inner: OpenapiBackendPlugin,
    host: Arc<dyn mcpg_plugin_protocol::BackendHost>,
    rt: tokio::runtime::Runtime,
}

impl OpenapiBackendCdylib {
    /// Infallible cdylib factory. `config_json` is the plugin config
    /// (`sources`); spec parse errors are deferred to `register_profile`.
    pub fn from_host_config(config_json: &str, host: HostHandle) -> Self {
        Self {
            inner: OpenapiBackendPlugin::from_config_json(config_json),
            host: Arc::new(HostHandleBackendHost::new(host)),
            rt: tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_name("mcpg-backend-openapi".to_owned())
                .enable_all()
                .build()
                .unwrap_or_else(|e| panic!("openapi cdylib: tokio runtime init failed: {e}")),
        }
    }
}

impl SyncBackendPlugin for OpenapiBackendCdylib {
    fn manifest(&self) -> &PluginManifest {
        BackendPlugin::manifest(&self.inner)
    }

    fn kind(&self) -> &str {
        BackendPlugin::kind(&self.inner)
    }

    fn register_profile(&self, profile_name: &str, spec: &Value) -> Result<(), BackendError> {
        self.rt.block_on(BackendPlugin::register_profile(
            &self.inner,
            profile_name,
            spec,
            Arc::clone(&self.host),
        ))
    }

    fn execute(
        &self,
        profile_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError> {
        self.rt
            .block_on(BackendPlugin::execute(&self.inner, profile_name, request))
    }

    fn input_schema(&self, profile_name: &str) -> Option<Value> {
        BackendPlugin::input_schema(&self.inner, profile_name)
    }

    fn output_schema(&self, profile_name: &str) -> Option<Value> {
        BackendPlugin::output_schema(&self.inner, profile_name)
    }

    fn expand_capabilities(&self) -> Result<mcpg_plugin_protocol::CapabilitySet, BackendError> {
        self.rt
            .block_on(BackendPlugin::expand_capabilities(&self.inner))
    }

    fn audit_metadata(&self, profile_name: &str) -> serde_json::Map<String, Value> {
        BackendPlugin::audit_metadata(&self.inner, profile_name)
    }
}

// cdylib export — one `backend` entity under `dev.mcpg.backend.openapi`.
mcpg_plugin_sdk::declare_plugin! {
    plugin_id: "dev.mcpg.backend.openapi",
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[::mcpg_plugin_protocol::capability::Capability::NetworkOutbound],
    // Residual per-kind facts the gateway reads back by kind — every value
    // mirrors the gateway's current hardcoded openapi handling 1:1:
    //   * health_probe = Skip — the upstream base URL lives in the plugin's
    //     own `sources` config, not the binding, so the gateway has no
    //     address to probe (matches `probe_binding`'s `Openapi => Skip`).
    //   * type_label = None ⇒ the kind string "openapi" (matches the
    //     `binding_type_label`/host-mode label).
    //   * dynamic_list = false — openapi is NOT in the gateway's per-request
    //     `extract_dynamic_list_bindings` set (it falls to `_ => None`). Its
    //     synthetic catalog is minted at boot via `expand_capabilities`,
    //     which is a separate mechanism from the resources/list dynamic-list
    //     path this flag gates. Setting it true would make the gateway pay
    //     for per-binding dynamic-list calls openapi never serviced.
    //   * pipeline_capable = false — there is no `PipelineOpenapiStepConfig`
    //     variant today; openapi cannot appear as a backend pipeline step.
    //   * transport_only_fields = [] — the binding spec is only the
    //     `{ source, operation }` selector (identifiers, not transport
    //     facts); the gateway's openapi binding has no `cred://`-misplacement
    //     field policy (creds live in the plugin's `sources[].headers/auth`).
    backend_profile: ::mcpg_plugin_protocol::manifest::BackendProfile {
        ..::core::default::Default::default()
    },
    entities: [
        backend as binding {
            inner_name: "",
            plugin_type: OpenapiBackendCdylib,
            factory: |cfg, host: ::mcpg_plugin_sdk::HostHandle|
                OpenapiBackendCdylib::from_host_config(cfg, host),
        },
    ],
}
