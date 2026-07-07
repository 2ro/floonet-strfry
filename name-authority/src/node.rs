// Grin node foreign-API client for transfer claims (spec section 5, check 9;
// section 8 config). A port of grin-proof-watcher/src/node.rs: the foreign-API
// JSON-RPC `get_kernel` + `get_tip` calls, matching the wallet's own
// `w2n_client().get_kernel(excess, min_height, max_height)`.
//
// The [`ChainSource`] trait abstracts the node so handlers can be driven in
// tests without a live node (see [`TestChainSource`]); production uses
// [`NodeClient`] over reqwest.

use async_trait::async_trait;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::HashMap;

/// Outcome of a kernel lookup against the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelResult {
    /// The kernel was found on chain.
    pub found: bool,
    /// Confirmation depth (`tip - height + 1`), 0 when not found.
    pub confirmations: u64,
    /// Inclusion height when found.
    pub height: Option<u64>,
}

impl KernelResult {
    fn not_found() -> Self {
        KernelResult {
            found: false,
            confirmations: 0,
            height: None,
        }
    }
}

/// The chain queries a transfer claim needs: a kernel lookup (with depth) and
/// the current tip (recorded as an offer's `end_height` when it dies).
#[async_trait]
pub trait ChainSource: Send + Sync {
    /// Look up a kernel by excess and compute its confirmation depth.
    async fn kernel(&self, excess_hex: &str) -> Result<KernelResult, String>;
    /// Current chain tip height.
    async fn tip_height(&self) -> Result<u64, String>;
}

/// The real foreign-API client over reqwest. Holds an ordered list of endpoints
/// and fails over to the next on a transport error.
#[derive(Debug, Clone)]
pub struct NodeClient {
    endpoints: Vec<String>,
    http: reqwest::Client,
}

impl NodeClient {
    /// Build a client from a comma-or-whitespace list of foreign-API base URLs.
    pub fn new(endpoints: Vec<String>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .user_agent("floonet-name-authority")
            .build()
            .expect("reqwest client");
        NodeClient { endpoints, http }
    }

    /// One foreign-API JSON-RPC call, unwrapping the `{ Ok | Err }` result
    /// envelope. Returns the inner `Ok` value (or the bare result).
    async fn rpc(&self, endpoint: &str, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let resp = self
            .http
            .post(endpoint)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("{method} transport: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("{method} HTTP {}", resp.status()));
        }
        let value: Value = resp
            .json()
            .await
            .map_err(|e| format!("{method} decode: {e}"))?;
        if let Some(err) = value.get("error") {
            if !err.is_null() {
                return Err(format!("{method} error: {err}"));
            }
        }
        let result = value.get("result").cloned().unwrap_or(Value::Null);
        if let Some(inner_err) = result.get("Err") {
            return Err(format!("{method} Err: {inner_err}"));
        }
        Ok(result.get("Ok").cloned().unwrap_or(result))
    }

    async fn kernel_one(&self, endpoint: &str, excess_hex: &str) -> Result<KernelResult, String> {
        let kernel = self
            .rpc(endpoint, "get_kernel", json!([excess_hex, null, null]))
            .await?;
        if kernel.is_null() {
            return Ok(KernelResult::not_found());
        }
        // get_kernel returns [TxKernelPrintable, height, mmr_index].
        let height = kernel
            .get(1)
            .and_then(|v| v.as_u64())
            .or_else(|| kernel.get("height").and_then(|v| v.as_u64()));
        let tip = self.rpc(endpoint, "get_tip", json!([])).await?;
        let tip_height = tip.get("height").and_then(|v| v.as_u64());
        match (height, tip_height) {
            (Some(h), Some(tip_h)) => Ok(KernelResult {
                found: true,
                confirmations: (tip_h.saturating_sub(h) + 1).max(1),
                height: Some(h),
            }),
            // Kernel present but heights unreadable: at least one confirmation.
            (h, _) => Ok(KernelResult {
                found: true,
                confirmations: 1,
                height: h,
            }),
        }
    }
}

#[async_trait]
impl ChainSource for NodeClient {
    async fn kernel(&self, excess_hex: &str) -> Result<KernelResult, String> {
        let mut last_err = String::from("no node endpoints configured");
        for endpoint in &self.endpoints {
            match self.kernel_one(endpoint, excess_hex).await {
                Ok(res) => return Ok(res),
                Err(e) => {
                    tracing::warn!(node = %endpoint, error = %e, "grin node query failed, trying next");
                    last_err = e;
                }
            }
        }
        Err(last_err)
    }

    async fn tip_height(&self) -> Result<u64, String> {
        let mut last_err = String::from("no node endpoints configured");
        for endpoint in &self.endpoints {
            match self.rpc(endpoint, "get_tip", json!([])).await {
                Ok(tip) => {
                    if let Some(h) = tip.get("height").and_then(|v| v.as_u64()) {
                        return Ok(h);
                    }
                    last_err = "get_tip: height missing".into();
                }
                Err(e) => {
                    tracing::warn!(node = %endpoint, error = %e, "grin get_tip failed, trying next");
                    last_err = e;
                }
            }
        }
        Err(last_err)
    }
}

/// A scriptable in-process [`ChainSource`] for tests: a settable tip plus a map
/// of excess hex to `(height, confirmations)`. Unknown excesses read as
/// not-found. Exposed (hidden from docs) so integration tests, which compile as
/// a separate crate, can drive the claim path without a live node.
#[doc(hidden)]
pub struct TestChainSource {
    tip: Mutex<u64>,
    kernels: Mutex<HashMap<String, (u64, u64)>>,
    tip_fails: Mutex<bool>,
}

#[doc(hidden)]
impl TestChainSource {
    pub fn new(tip: u64) -> Self {
        TestChainSource {
            tip: Mutex::new(tip),
            kernels: Mutex::new(HashMap::new()),
            tip_fails: Mutex::new(false),
        }
    }

    /// Record a kernel as on chain at `height` with `confirmations` depth.
    pub fn set_kernel(&self, excess_hex: &str, height: u64, confirmations: u64) {
        self.kernels
            .lock()
            .insert(excess_hex.to_lowercase(), (height, confirmations));
    }

    /// Move the reported tip height.
    pub fn set_tip(&self, tip: u64) {
        *self.tip.lock() = tip;
    }

    /// Make `tip_height` return a transport error (to test fail-closed expiry).
    pub fn fail_tip(&self, fail: bool) {
        *self.tip_fails.lock() = fail;
    }
}

#[async_trait]
impl ChainSource for TestChainSource {
    async fn kernel(&self, excess_hex: &str) -> Result<KernelResult, String> {
        match self.kernels.lock().get(&excess_hex.to_lowercase()) {
            Some(&(height, confirmations)) => Ok(KernelResult {
                found: true,
                confirmations,
                height: Some(height),
            }),
            None => Ok(KernelResult::not_found()),
        }
    }

    async fn tip_height(&self) -> Result<u64, String> {
        if *self.tip_fails.lock() {
            return Err("test node tip unreachable".into());
        }
        Ok(*self.tip.lock())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_source_reports_kernels_and_tip() {
        let node = TestChainSource::new(1000);
        node.set_kernel("ab", 900, 101);
        let k = node.kernel("AB").await.unwrap();
        assert!(k.found);
        assert_eq!(k.height, Some(900));
        assert_eq!(k.confirmations, 101);
        assert_eq!(node.tip_height().await.unwrap(), 1000);
        // Unknown excess reads as not found.
        assert!(!node.kernel("cd").await.unwrap().found);
        // Tip can be made to fail for fail-closed expiry tests.
        node.fail_tip(true);
        assert!(node.tip_height().await.is_err());
    }
}
