use crate::executors::Executor;
use alloy_primitives::{Address, Bytes, U256};
use foundry_evm_core::evm::FoundryEvmNetwork;
use foundry_evm_fuzz::HybridFuzzIncompleteKind;
use std::{
    cmp,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

/// A comparison reached by concrete fuzzing that symbolic execution can try to flip.
#[derive(Clone, Debug)]
pub struct HybridFuzzTarget {
    address: Address,
    pc: usize,
    opcode: u8,
    observed_result: bool,
    operand_delta: U256,
    calldata: Bytes,
}

impl HybridFuzzTarget {
    pub(super) const fn new(
        address: Address,
        pc: usize,
        opcode: u8,
        observed_result: bool,
        operand_delta: U256,
        calldata: Bytes,
    ) -> Self {
        Self { address, pc, opcode, observed_result, operand_delta, calldata }
    }

    pub const fn address(&self) -> Address {
        self.address
    }

    pub const fn pc(&self) -> usize {
        self.pc
    }

    pub const fn opcode(&self) -> u8 {
        self.opcode
    }

    pub const fn observed_result(&self) -> bool {
        self.observed_result
    }

    pub const fn operand_delta(&self) -> U256 {
        self.operand_delta
    }

    pub const fn calldata(&self) -> &Bytes {
        &self.calldata
    }

    pub(super) const fn key(&self) -> HybridFuzzTargetKey {
        HybridFuzzTargetKey::new(self.address, self.pc, self.opcode, self.observed_result)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct HybridFuzzTargetKey {
    address: Address,
    pc: usize,
    opcode: u8,
    observed_result: bool,
}

impl HybridFuzzTargetKey {
    pub(super) const fn new(
        address: Address,
        pc: usize,
        opcode: u8,
        observed_result: bool,
    ) -> Self {
        Self { address, pc, opcode, observed_result }
    }
}

/// Result of one bounded symbolic assist attempt.
#[derive(Debug)]
pub enum HybridFuzzSolve {
    /// Symbolic execution produced calldata to replay through the concrete fuzz worker.
    Candidate(Bytes),
    /// The target could not be solved within the managed budget.
    Incomplete(HybridFuzzIncompleteKind),
}

/// Symbolic target solver used by a managed hybrid fuzz campaign.
pub trait HybridFuzzSolver<FEN: FoundryEvmNetwork>: Send + Sync {
    fn solve(&self, executor: &Executor<FEN>, target: HybridFuzzTarget) -> HybridFuzzSolve;
}

impl<FEN, F> HybridFuzzSolver<FEN> for F
where
    FEN: FoundryEvmNetwork,
    F: Fn(&Executor<FEN>, HybridFuzzTarget) -> HybridFuzzSolve + Send + Sync,
{
    fn solve(&self, executor: &Executor<FEN>, target: HybridFuzzTarget) -> HybridFuzzSolve {
        self(executor, target)
    }
}

/// Scheduling policy for managed symbolic assistance.
#[derive(Clone, Copy, Debug)]
pub struct HybridFuzzPolicy {
    pub(super) warmup_runs: u32,
    pub(super) plateau: Duration,
    pub(super) cooldown: Duration,
    pub(super) max_cooldown: Duration,
    pub(super) frontier_limit: usize,
    pub(super) attempt_frontier_limit: usize,
    pub(super) max_attempts: u32,
}

const DEFAULT_HYBRID_WARMUP_RUNS: u32 = 2_000_000;
const DEFAULT_HYBRID_PLATEAU_SECS: u64 = 15 * 60;
const DEFAULT_HYBRID_MAX_COOLDOWN_SECS: u64 = 30 * 60;
const DEFAULT_HYBRID_ATTEMPT_FRONTIERS: usize = 8;

impl Default for HybridFuzzPolicy {
    fn default() -> Self {
        Self {
            // Hybrid assists are for long campaigns after concrete fuzzing has stopped moving.
            warmup_runs: DEFAULT_HYBRID_WARMUP_RUNS,
            // Long enough to avoid reacting to normal corpus synchronization and mutation pauses.
            plateau: Duration::from_secs(DEFAULT_HYBRID_PLATEAU_SECS),
            // Require another long concrete window before trying another symbolic target.
            cooldown: Duration::from_secs(DEFAULT_HYBRID_PLATEAU_SECS),
            // Bounds exponential backoff after repeated incomplete assists.
            max_cooldown: Duration::from_secs(DEFAULT_HYBRID_MAX_COOLDOWN_SECS),
            // Bounds retained target metadata independently of artifact persistence settings.
            frontier_limit: 64,
            // Try a small ranked burst so one noisy frontier does not consume a full plateau.
            attempt_frontier_limit: DEFAULT_HYBRID_ATTEMPT_FRONTIERS,
            // Cooldown and solver timeout bound long campaigns; do not stop after one burst.
            max_attempts: u32::MAX,
        }
    }
}

impl HybridFuzzPolicy {
    pub(super) fn should_attempt(
        &self,
        total_runs: u32,
        stalled_for: Duration,
        attempts: u32,
        cooldown_elapsed: bool,
    ) -> bool {
        let warm_enough = total_runs >= self.warmup_runs || stalled_for >= self.plateau;
        attempts < self.max_attempts
            && cooldown_elapsed
            && warm_enough
            && stalled_for >= self.plateau
    }

    pub(super) fn incomplete_cooldown(&self, attempt: u32) -> Duration {
        let multiplier = 1_u32 << attempt.saturating_sub(1).min(3);
        cmp::min(self.cooldown.saturating_mul(multiplier), self.max_cooldown)
    }
}

/// One managed symbolic assistant attached to a fuzz campaign.
#[derive(Clone)]
pub struct HybridFuzzAssist<FEN: FoundryEvmNetwork> {
    solver: Arc<dyn HybridFuzzSolver<FEN>>,
    policy: HybridFuzzPolicy,
}

impl<FEN: FoundryEvmNetwork> HybridFuzzAssist<FEN> {
    pub fn new(solver: Arc<dyn HybridFuzzSolver<FEN>>) -> Self {
        Self { solver, policy: HybridFuzzPolicy::default() }
    }

    pub(super) fn solver(&self) -> &dyn HybridFuzzSolver<FEN> {
        self.solver.as_ref()
    }

    pub(super) const fn policy(&self) -> HybridFuzzPolicy {
        self.policy
    }
}

// Contract suites run in parallel. A process-wide gate prevents separate tests from starting
// symbolic assists concurrently and bounds the additional solver memory to one job.
static HYBRID_ASSIST_BUSY: AtomicBool = AtomicBool::new(false);

pub(super) struct HybridAssistLease;

impl HybridAssistLease {
    pub(super) fn try_acquire() -> Option<Self> {
        HYBRID_ASSIST_BUSY
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
            .then_some(Self)
    }
}

impl Drop for HybridAssistLease {
    fn drop(&mut self) {
        HYBRID_ASSIST_BUSY.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_gate_prevents_concurrent_symbolic_assists() {
        let lease = HybridAssistLease::try_acquire().expect("process gate should be available");
        assert!(HybridAssistLease::try_acquire().is_none());
        drop(lease);
        assert!(HybridAssistLease::try_acquire().is_some());
    }

    #[test]
    fn activation_policy_requires_long_campaign_plateau() {
        let policy = HybridFuzzPolicy::default();

        assert_eq!(policy.warmup_runs, DEFAULT_HYBRID_WARMUP_RUNS);
        assert_eq!(policy.plateau, Duration::from_secs(DEFAULT_HYBRID_PLATEAU_SECS));
        assert_eq!(policy.cooldown, Duration::from_secs(DEFAULT_HYBRID_PLATEAU_SECS));
        assert_eq!(policy.max_cooldown, Duration::from_secs(DEFAULT_HYBRID_MAX_COOLDOWN_SECS));
        assert_eq!(policy.frontier_limit, 64);
        assert_eq!(policy.attempt_frontier_limit, DEFAULT_HYBRID_ATTEMPT_FRONTIERS);
        assert_eq!(policy.max_attempts, u32::MAX);
        assert!(!policy.should_attempt(policy.warmup_runs, policy.plateau / 2, 0, true));
        assert!(!policy.should_attempt(
            policy.warmup_runs,
            policy.plateau,
            policy.max_attempts,
            true
        ));
        assert!(!policy.should_attempt(policy.warmup_runs, policy.plateau, 0, false));
        assert!(policy.should_attempt(policy.warmup_runs, policy.plateau, 0, true));
        assert!(policy.should_attempt(policy.warmup_runs - 1, policy.plateau, 0, true));
    }

    #[test]
    fn incomplete_cooldown_backs_off_and_caps() {
        let policy = HybridFuzzPolicy::default();

        assert_eq!(policy.incomplete_cooldown(1), Duration::from_secs(DEFAULT_HYBRID_PLATEAU_SECS));
        assert_eq!(
            policy.incomplete_cooldown(2),
            Duration::from_secs(DEFAULT_HYBRID_MAX_COOLDOWN_SECS)
        );
        assert_eq!(
            policy.incomplete_cooldown(3),
            Duration::from_secs(DEFAULT_HYBRID_MAX_COOLDOWN_SECS)
        );
        assert_eq!(
            policy.incomplete_cooldown(4),
            Duration::from_secs(DEFAULT_HYBRID_MAX_COOLDOWN_SECS)
        );
        assert_eq!(
            policy.incomplete_cooldown(5),
            Duration::from_secs(DEFAULT_HYBRID_MAX_COOLDOWN_SECS)
        );
    }
}
