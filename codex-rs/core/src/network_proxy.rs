#[cfg(feature = "managed-network-proxy")]
pub use codex_network_proxy::*;

#[cfg(not(feature = "managed-network-proxy"))]
mod shim {
    use anyhow::Result;
    use async_trait::async_trait;
    use serde::Deserialize;
    use serde::Serialize;
    use std::collections::HashMap;
    use std::future::Future;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use url::Url;

    #[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
    pub struct NetworkProxyConfig {
        #[serde(default)]
        pub network: NetworkProxySettings,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(default)]
    pub struct NetworkProxySettings {
        #[serde(default)]
        pub enabled: bool,
        #[serde(default = "default_proxy_url")]
        pub proxy_url: String,
        #[serde(default = "default_admin_url")]
        pub admin_url: String,
        pub enable_socks5: bool,
        #[serde(default = "default_socks_url")]
        pub socks_url: String,
        pub enable_socks5_udp: bool,
        pub allow_upstream_proxy: bool,
        #[serde(default)]
        pub dangerously_allow_non_loopback_proxy: bool,
        #[serde(default)]
        pub dangerously_allow_non_loopback_admin: bool,
        #[serde(default)]
        pub dangerously_allow_all_unix_sockets: bool,
        #[serde(default)]
        pub mode: NetworkMode,
        #[serde(default)]
        pub allowed_domains: Vec<String>,
        #[serde(default)]
        pub denied_domains: Vec<String>,
        #[serde(default)]
        pub allow_unix_sockets: Vec<String>,
        pub allow_local_binding: bool,
        #[serde(default)]
        pub mitm: bool,
    }

    impl Default for NetworkProxySettings {
        fn default() -> Self {
            Self {
                enabled: false,
                proxy_url: default_proxy_url(),
                admin_url: default_admin_url(),
                enable_socks5: true,
                socks_url: default_socks_url(),
                enable_socks5_udp: true,
                allow_upstream_proxy: true,
                dangerously_allow_non_loopback_proxy: false,
                dangerously_allow_non_loopback_admin: false,
                dangerously_allow_all_unix_sockets: false,
                mode: NetworkMode::default(),
                allowed_domains: Vec::new(),
                denied_domains: Vec::new(),
                allow_unix_sockets: Vec::new(),
                allow_local_binding: true,
                mitm: false,
            }
        }
    }

    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
    #[serde(rename_all = "lowercase")]
    pub enum NetworkMode {
        Limited,
        #[default]
        Full,
    }

    impl NetworkMode {
        pub fn allows_method(self, method: &str) -> bool {
            match self {
                Self::Full => true,
                Self::Limited => matches!(method, "GET" | "HEAD" | "OPTIONS"),
            }
        }
    }

    fn default_proxy_url() -> String {
        "http://127.0.0.1:3128".to_string()
    }

    fn default_admin_url() -> String {
        "http://127.0.0.1:8080".to_string()
    }

    fn default_socks_url() -> String {
        "http://127.0.0.1:8081".to_string()
    }

    #[derive(Debug, Default, Clone, PartialEq, Eq)]
    pub struct NetworkProxyConstraints {
        pub enabled: Option<bool>,
        pub mode: Option<NetworkMode>,
        pub allow_upstream_proxy: Option<bool>,
        pub dangerously_allow_non_loopback_proxy: Option<bool>,
        pub dangerously_allow_non_loopback_admin: Option<bool>,
        pub dangerously_allow_all_unix_sockets: Option<bool>,
        pub allowed_domains: Option<Vec<String>>,
        pub denied_domains: Option<Vec<String>>,
        pub allow_unix_sockets: Option<Vec<String>>,
        pub allow_local_binding: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
    pub enum NetworkProxyConstraintError {
        #[error("invalid value for {field_name}: {candidate} (allowed {allowed})")]
        InvalidValue {
            field_name: &'static str,
            candidate: String,
            allowed: String,
        },
    }

    impl NetworkProxyConstraintError {
        pub fn into_anyhow(self) -> anyhow::Error {
            anyhow::anyhow!(self)
        }
    }

    pub fn validate_policy_against_constraints(
        config: &NetworkProxyConfig,
        constraints: &NetworkProxyConstraints,
    ) -> Result<(), NetworkProxyConstraintError> {
        if let Some(enabled) = constraints.enabled
            && config.network.enabled
            && !enabled
        {
            return Err(NetworkProxyConstraintError::InvalidValue {
                field_name: "network.enabled",
                candidate: "true".to_string(),
                allowed: "false (disabled by managed config)".to_string(),
            });
        }
        if let Some(mode) = constraints.mode
            && config.network.mode == NetworkMode::Full
            && mode == NetworkMode::Limited
        {
            return Err(NetworkProxyConstraintError::InvalidValue {
                field_name: "network.mode",
                candidate: "Full".to_string(),
                allowed: "Limited or more restrictive".to_string(),
            });
        }
        Ok(())
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct NetworkProxyAuditMetadata {
        pub conversation_id: Option<String>,
        pub app_version: Option<String>,
        pub user_account_id: Option<String>,
        pub auth_mode: Option<String>,
        pub originator: Option<String>,
        pub user_email: Option<String>,
        pub terminal_type: Option<String>,
        pub model: Option<String>,
        pub slug: Option<String>,
    }

    #[derive(Clone)]
    pub struct ConfigState {
        pub config: NetworkProxyConfig,
        pub constraints: NetworkProxyConstraints,
    }

    #[async_trait]
    pub trait ConfigReloader: Send + Sync {
        fn source_label(&self) -> String;
        async fn maybe_reload(&self) -> anyhow::Result<Option<ConfigState>>;
        async fn reload_now(&self) -> anyhow::Result<ConfigState>;
    }

    #[async_trait]
    pub trait BlockedRequestObserver: Send + Sync + 'static {
        async fn on_blocked_request(&self, request: BlockedRequest);
    }

    #[async_trait]
    impl<O: BlockedRequestObserver + ?Sized> BlockedRequestObserver for Arc<O> {
        async fn on_blocked_request(&self, request: BlockedRequest) {
            (**self).on_blocked_request(request).await;
        }
    }

    #[async_trait]
    impl<F, Fut> BlockedRequestObserver for F
    where
        F: Fn(BlockedRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send,
    {
        async fn on_blocked_request(&self, request: BlockedRequest) {
            (self)(request).await;
        }
    }

    pub struct NetworkProxyState {
        state: Arc<RwLock<ConfigState>>,
        _reloader: Arc<dyn ConfigReloader>,
        audit_metadata: NetworkProxyAuditMetadata,
        blocked_request_observer: Arc<RwLock<Option<Arc<dyn BlockedRequestObserver>>>>,
    }

    impl std::fmt::Debug for NetworkProxyState {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("NetworkProxyState").finish_non_exhaustive()
        }
    }

    impl Clone for NetworkProxyState {
        fn clone(&self) -> Self {
            Self {
                state: self.state.clone(),
                _reloader: self._reloader.clone(),
                audit_metadata: self.audit_metadata.clone(),
                blocked_request_observer: self.blocked_request_observer.clone(),
            }
        }
    }

    impl NetworkProxyState {
        pub fn with_reloader(state: ConfigState, reloader: Arc<dyn ConfigReloader>) -> Self {
            Self::with_reloader_and_audit_metadata(
                state,
                reloader,
                NetworkProxyAuditMetadata::default(),
            )
        }

        pub fn with_reloader_and_audit_metadata(
            state: ConfigState,
            reloader: Arc<dyn ConfigReloader>,
            audit_metadata: NetworkProxyAuditMetadata,
        ) -> Self {
            Self {
                state: Arc::new(RwLock::new(state)),
                _reloader: reloader,
                audit_metadata,
                blocked_request_observer: Arc::new(RwLock::new(None)),
            }
        }

        pub fn audit_metadata(&self) -> &NetworkProxyAuditMetadata {
            &self.audit_metadata
        }

        pub async fn current_cfg(&self) -> anyhow::Result<NetworkProxyConfig> {
            let guard = self.state.read().await;
            Ok(guard.config.clone())
        }

        pub async fn set_blocked_request_observer(
            &self,
            observer: Option<Arc<dyn BlockedRequestObserver>>,
        ) {
            let mut guard = self.blocked_request_observer.write().await;
            *guard = observer;
        }

        pub async fn add_allowed_domain(&self, host: &str) -> anyhow::Result<()> {
            let normalized = normalize_host(host);
            let mut guard = self.state.write().await;
            guard
                .config
                .network
                .allowed_domains
                .retain(|entry| normalize_host(entry) != normalized);
            guard
                .config
                .network
                .allowed_domains
                .push(normalized.clone());
            guard
                .config
                .network
                .denied_domains
                .retain(|entry| normalize_host(entry) != normalized);
            Ok(())
        }

        pub async fn add_denied_domain(&self, host: &str) -> anyhow::Result<()> {
            let normalized = normalize_host(host);
            let mut guard = self.state.write().await;
            guard
                .config
                .network
                .denied_domains
                .retain(|entry| normalize_host(entry) != normalized);
            guard.config.network.denied_domains.push(normalized.clone());
            guard
                .config
                .network
                .allowed_domains
                .retain(|entry| normalize_host(entry) != normalized);
            Ok(())
        }
    }

    pub fn build_config_state(
        config: NetworkProxyConfig,
        constraints: NetworkProxyConstraints,
    ) -> anyhow::Result<ConfigState> {
        Ok(ConfigState {
            config,
            constraints,
        })
    }

    #[derive(Clone, Default)]
    pub struct NetworkProxyBuilder {
        state: Option<Arc<NetworkProxyState>>,
        http_addr: Option<SocketAddr>,
        socks_addr: Option<SocketAddr>,
        admin_addr: Option<SocketAddr>,
        _policy_decider: Option<Arc<dyn NetworkPolicyDecider>>,
        blocked_request_observer: Option<Arc<dyn BlockedRequestObserver>>,
    }

    impl NetworkProxyBuilder {
        pub fn state(mut self, state: Arc<NetworkProxyState>) -> Self {
            self.state = Some(state);
            self
        }

        pub fn http_addr(mut self, addr: SocketAddr) -> Self {
            self.http_addr = Some(addr);
            self
        }

        pub fn socks_addr(mut self, addr: SocketAddr) -> Self {
            self.socks_addr = Some(addr);
            self
        }

        pub fn admin_addr(mut self, addr: SocketAddr) -> Self {
            self.admin_addr = Some(addr);
            self
        }

        pub fn managed_by_codex(self, _managed_by_codex: bool) -> Self {
            self
        }

        pub fn policy_decider<D>(mut self, decider: D) -> Self
        where
            D: NetworkPolicyDecider,
        {
            self._policy_decider = Some(Arc::new(decider));
            self
        }

        pub fn policy_decider_arc(mut self, decider: Arc<dyn NetworkPolicyDecider>) -> Self {
            self._policy_decider = Some(decider);
            self
        }

        pub fn blocked_request_observer<O>(mut self, observer: O) -> Self
        where
            O: BlockedRequestObserver,
        {
            self.blocked_request_observer = Some(Arc::new(observer));
            self
        }

        pub fn blocked_request_observer_arc(
            mut self,
            observer: Arc<dyn BlockedRequestObserver>,
        ) -> Self {
            self.blocked_request_observer = Some(observer);
            self
        }

        pub async fn build(self) -> anyhow::Result<NetworkProxy> {
            let state = self.state.ok_or_else(|| {
                anyhow::anyhow!(
                    "NetworkProxyBuilder requires a state; supply one via builder.state(...)"
                )
            })?;
            state
                .set_blocked_request_observer(self.blocked_request_observer)
                .await;
            let cfg = state.current_cfg().await?;
            let default_http = parse_socket_addr(&cfg.network.proxy_url, 3128);
            let default_socks = parse_socket_addr(&cfg.network.socks_url, 8081);
            let default_admin = parse_socket_addr(&cfg.network.admin_url, 8080);
            Ok(NetworkProxy {
                state,
                http_addr: self.http_addr.unwrap_or(default_http),
                socks_addr: self.socks_addr.unwrap_or(default_socks),
                admin_addr: self.admin_addr.unwrap_or(default_admin),
                socks_enabled: cfg.network.enable_socks5,
                allow_local_binding: cfg.network.allow_local_binding,
                allow_unix_sockets: cfg.network.allow_unix_sockets.clone(),
                dangerously_allow_all_unix_sockets: cfg.network.dangerously_allow_all_unix_sockets,
            })
        }
    }

    fn parse_socket_addr(value: &str, default_port: u16) -> SocketAddr {
        let formatted = host_and_port_from_network_addr(value, default_port);
        formatted
            .parse::<SocketAddr>()
            .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], default_port)))
    }

    #[derive(Clone, Debug)]
    pub struct NetworkProxy {
        state: Arc<NetworkProxyState>,
        http_addr: SocketAddr,
        socks_addr: SocketAddr,
        admin_addr: SocketAddr,
        socks_enabled: bool,
        allow_local_binding: bool,
        allow_unix_sockets: Vec<String>,
        dangerously_allow_all_unix_sockets: bool,
    }

    impl PartialEq for NetworkProxy {
        fn eq(&self, other: &Self) -> bool {
            self.http_addr == other.http_addr
                && self.socks_addr == other.socks_addr
                && self.admin_addr == other.admin_addr
                && self.allow_local_binding == other.allow_local_binding
                && self.allow_unix_sockets == other.allow_unix_sockets
                && self.dangerously_allow_all_unix_sockets
                    == other.dangerously_allow_all_unix_sockets
        }
    }

    impl Eq for NetworkProxy {}

    impl NetworkProxy {
        pub fn builder() -> NetworkProxyBuilder {
            NetworkProxyBuilder::default()
        }

        pub fn http_addr(&self) -> SocketAddr {
            self.http_addr
        }

        pub fn socks_addr(&self) -> SocketAddr {
            self.socks_addr
        }

        pub fn admin_addr(&self) -> SocketAddr {
            self.admin_addr
        }

        pub fn allow_local_binding(&self) -> bool {
            self.allow_local_binding
        }

        pub fn allow_unix_sockets(&self) -> &[String] {
            &self.allow_unix_sockets
        }

        pub fn dangerously_allow_all_unix_sockets(&self) -> bool {
            self.dangerously_allow_all_unix_sockets
        }

        pub fn apply_to_env(&self, _env: &mut HashMap<String, String>) {}

        pub async fn run(&self) -> anyhow::Result<NetworkProxyHandle> {
            let _ = &self.state;
            let _ = self.socks_enabled;
            Ok(NetworkProxyHandle {})
        }

        pub async fn add_allowed_domain(&self, host: &str) -> anyhow::Result<()> {
            self.state.add_allowed_domain(host).await
        }

        pub async fn add_denied_domain(&self, host: &str) -> anyhow::Result<()> {
            self.state.add_denied_domain(host).await
        }
    }

    pub struct NetworkProxyHandle {}

    impl NetworkProxyHandle {
        pub async fn wait(self) -> anyhow::Result<()> {
            Ok(())
        }

        pub async fn shutdown(self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    pub const PROXY_URL_ENV_KEYS: &[&str] = &[
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "WS_PROXY",
        "WSS_PROXY",
        "ALL_PROXY",
        "FTP_PROXY",
        "YARN_HTTP_PROXY",
        "YARN_HTTPS_PROXY",
        "NPM_CONFIG_HTTP_PROXY",
        "NPM_CONFIG_HTTPS_PROXY",
        "NPM_CONFIG_PROXY",
        "BUNDLE_HTTP_PROXY",
        "BUNDLE_HTTPS_PROXY",
        "PIP_PROXY",
        "DOCKER_HTTP_PROXY",
        "DOCKER_HTTPS_PROXY",
    ];

    pub fn proxy_url_env_value<'a>(
        env: &'a HashMap<String, String>,
        canonical_key: &str,
    ) -> Option<&'a str> {
        if let Some(value) = env.get(canonical_key) {
            return Some(value.as_str());
        }
        let lower_key = canonical_key.to_ascii_lowercase();
        env.get(lower_key.as_str()).map(String::as_str)
    }

    pub fn has_proxy_url_env_vars(env: &HashMap<String, String>) -> bool {
        PROXY_URL_ENV_KEYS
            .iter()
            .any(|key| proxy_url_env_value(env, key).is_some_and(|value| !value.trim().is_empty()))
    }

    pub fn host_and_port_from_network_addr(value: &str, default_port: u16) -> String {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return "<missing>".to_string();
        }

        if let Ok(url) = Url::parse(trimmed)
            && let Some(host) = url.host_str()
        {
            let port = url.port().unwrap_or(default_port);
            return if host.contains(':') {
                format!("[{host}]:{port}")
            } else {
                format!("{host}:{port}")
            };
        }

        if trimmed.contains(':') && !trimmed.contains("://") {
            return trimmed.to_string();
        }

        format!("{trimmed}:{default_port}")
    }

    #[derive(Clone, Copy, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
    #[serde(rename_all = "lowercase")]
    pub enum NetworkPolicyDecision {
        Deny,
        Ask,
    }

    impl NetworkPolicyDecision {
        pub const fn as_str(self) -> &'static str {
            match self {
                Self::Deny => "deny",
                Self::Ask => "ask",
            }
        }
    }

    #[derive(Clone, Copy, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum NetworkDecisionSource {
        BaselinePolicy,
        ModeGuard,
        ProxyState,
        Decider,
    }

    impl NetworkDecisionSource {
        pub const fn as_str(self) -> &'static str {
            match self {
                Self::BaselinePolicy => "baseline_policy",
                Self::ModeGuard => "mode_guard",
                Self::ProxyState => "proxy_state",
                Self::Decider => "decider",
            }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum NetworkProtocol {
        Http,
        HttpsConnect,
        Socks5Tcp,
        Socks5Udp,
    }

    impl NetworkProtocol {
        pub const fn as_policy_protocol(self) -> &'static str {
            match self {
                Self::Http => "http",
                Self::HttpsConnect => "https_connect",
                Self::Socks5Tcp => "socks5_tcp",
                Self::Socks5Udp => "socks5_udp",
            }
        }
    }

    #[derive(Clone, Debug)]
    pub struct NetworkPolicyRequest {
        pub protocol: NetworkProtocol,
        pub host: String,
        pub port: u16,
        pub client_addr: Option<String>,
        pub method: Option<String>,
        pub command: Option<String>,
        pub exec_policy_hint: Option<String>,
    }

    pub struct NetworkPolicyRequestArgs {
        pub protocol: NetworkProtocol,
        pub host: String,
        pub port: u16,
        pub client_addr: Option<String>,
        pub method: Option<String>,
        pub command: Option<String>,
        pub exec_policy_hint: Option<String>,
    }

    impl NetworkPolicyRequest {
        pub fn new(args: NetworkPolicyRequestArgs) -> Self {
            let NetworkPolicyRequestArgs {
                protocol,
                host,
                port,
                client_addr,
                method,
                command,
                exec_policy_hint,
            } = args;
            Self {
                protocol,
                host,
                port,
                client_addr,
                method,
                command,
                exec_policy_hint,
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum NetworkDecision {
        Allow,
        Deny {
            reason: String,
            source: NetworkDecisionSource,
            decision: NetworkPolicyDecision,
        },
    }

    impl NetworkDecision {
        pub fn ask(reason: impl Into<String>) -> Self {
            Self::Deny {
                reason: reason.into(),
                source: NetworkDecisionSource::Decider,
                decision: NetworkPolicyDecision::Ask,
            }
        }

        pub fn deny(reason: impl Into<String>) -> Self {
            Self::Deny {
                reason: reason.into(),
                source: NetworkDecisionSource::Decider,
                decision: NetworkPolicyDecision::Deny,
            }
        }
    }

    #[async_trait]
    pub trait NetworkPolicyDecider: Send + Sync + 'static {
        async fn decide(&self, req: NetworkPolicyRequest) -> NetworkDecision;
    }

    #[async_trait]
    impl<D: NetworkPolicyDecider + ?Sized> NetworkPolicyDecider for Arc<D> {
        async fn decide(&self, req: NetworkPolicyRequest) -> NetworkDecision {
            (**self).decide(req).await
        }
    }

    #[async_trait]
    impl<F, Fut> NetworkPolicyDecider for F
    where
        F: Fn(NetworkPolicyRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = NetworkDecision> + Send,
    {
        async fn decide(&self, req: NetworkPolicyRequest) -> NetworkDecision {
            (self)(req).await
        }
    }

    #[derive(Clone, Debug, Serialize)]
    pub struct BlockedRequest {
        pub host: String,
        pub reason: String,
        pub client: Option<String>,
        pub method: Option<String>,
        pub mode: Option<NetworkMode>,
        pub protocol: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub decision: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub source: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub port: Option<u16>,
        pub timestamp: i64,
    }

    pub struct BlockedRequestArgs {
        pub host: String,
        pub reason: String,
        pub client: Option<String>,
        pub method: Option<String>,
        pub mode: Option<NetworkMode>,
        pub protocol: String,
        pub decision: Option<String>,
        pub source: Option<String>,
        pub port: Option<u16>,
    }

    impl BlockedRequest {
        pub fn new(args: BlockedRequestArgs) -> Self {
            let BlockedRequestArgs {
                host,
                reason,
                client,
                method,
                mode,
                protocol,
                decision,
                source,
                port,
            } = args;
            Self {
                host,
                reason,
                client,
                method,
                mode,
                protocol,
                decision,
                source,
                port,
                timestamp: chrono::Utc::now().timestamp(),
            }
        }
    }

    pub fn normalize_host(host: &str) -> String {
        let host = host.trim();
        if host.starts_with('[')
            && let Some(end) = host.find(']')
        {
            return host[1..end]
                .to_ascii_lowercase()
                .trim_end_matches('.')
                .to_string();
        }

        if host.bytes().filter(|b| *b == b':').count() == 1 {
            let prefix = host.split(':').next().unwrap_or_default();
            return prefix
                .to_ascii_lowercase()
                .trim_end_matches('.')
                .to_string();
        }

        host.to_ascii_lowercase().trim_end_matches('.').to_string()
    }
}

#[cfg(not(feature = "managed-network-proxy"))]
pub use shim::*;
