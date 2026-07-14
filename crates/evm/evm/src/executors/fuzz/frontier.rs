use super::{HybridFuzzTarget, HybridFuzzTargetKey};
use crate::inspectors::CmpOperands;
use alloy_json_abi::Function;
use alloy_primitives::{
    Address, Bytes, I256, U256,
    map::{HashMap, HashSet},
};
use foundry_common::fs;
use foundry_evm_fuzz::{BasicTxDetails, CallDetails, FuzzRunMetadata};
use revm::bytecode::opcode;
use serde::{Serialize, Serializer};
use std::{
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

const FRONTIER_SCHEMA: &str = "foundry:fuzz.branch-frontiers@v1";
pub(super) const FRONTIER_FILE: &str = "branch-frontiers.json";

#[derive(Debug, Serialize)]
pub(super) struct FuzzBranchFrontierArtifact {
    /// Stable artifact schema identifier for downstream symbolic consumers.
    schema: &'static str,
    /// Schema version for consumers that prefer numeric dispatch.
    version: u32,
    /// Unix timestamp, in seconds, when the artifact was written.
    generated_at: u64,
    /// Fuzz test signature that produced the frontier records.
    test: String,
    /// Configured maximum number of records retained for this test.
    limit: usize,
    /// Captured comparison frontiers.
    frontiers: Vec<FuzzBranchFrontier>,
}

impl FuzzBranchFrontierArtifact {
    pub(super) fn new(
        func: &Function,
        limit: usize,
        mut frontiers: Vec<FuzzBranchFrontier>,
    ) -> Self {
        for (id, frontier) in frontiers.iter_mut().enumerate() {
            frontier.id = id as u64;
        }

        Self {
            schema: FRONTIER_SCHEMA,
            version: 1,
            generated_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time went backwards")
                .as_secs(),
            test: func.signature(),
            limit,
            frontiers,
        }
    }
}

#[derive(Debug, Serialize)]
pub(super) struct FuzzBranchFrontier {
    /// Unique record identifier.
    id: u64,
    /// Reproducible fuzz seed, if configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    seed: Option<U256>,
    /// 1-based fuzz run number, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    run: Option<u32>,
    /// Fuzz worker that produced the record, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    worker: Option<u32>,
    /// Whether this call also expanded coverage from the worker's current map. Only present when
    /// edge coverage is collected (corpus, edge-coverage metrics, or sancov); omitted otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    new_coverage: Option<bool>,
    /// Index of the call in the recorded sequence. Stateless fuzzing records one call.
    call_index: usize,
    /// Concrete call sequence that reached the frontier.
    #[serde(serialize_with = "serialize_sequence")]
    sequence: Arc<[BasicTxDetails]>,
    /// EVM comparison site to target symbolically.
    site: FuzzBranchFrontierSite,
    /// Concrete operands observed at the site.
    operands: FuzzBranchFrontierOperands,
    /// Whether this site observed different operands during the campaign. Constant comparisons
    /// are ABI dispatch and setup checks rather than useful fuzz-input targets.
    #[serde(skip)]
    variable_operands: bool,
    /// Whether concrete fuzzing already exercised both outcomes at this comparison site.
    #[serde(skip)]
    opposite_observed: bool,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct FuzzBranchFrontierSite {
    address: Address,
    pc: usize,
    opcode: u8,
    opcode_name: &'static str,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct FuzzBranchFrontierOperands {
    lhs: U256,
    rhs: U256,
    /// Result of evaluating the captured comparison with these concrete operands.
    result: bool,
    /// Absolute operand delta interpreted according to the comparison opcode's signedness.
    operand_delta: U256,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FuzzBranchFrontierKey {
    address: Address,
    pc: usize,
    opcode: u8,
}

impl FuzzBranchFrontierKey {
    const fn new(cmp: &CmpOperands) -> Self {
        Self { address: cmp.address, pc: cmp.pc, opcode: cmp.opcode }
    }
}

#[derive(Debug, Default)]
pub(super) struct FuzzFrontierRecorder {
    limit: usize,
    frontiers: Vec<FuzzBranchFrontier>,
    indexes: HashMap<FuzzBranchFrontierKey, usize>,
    observed_false: HashSet<FuzzBranchFrontierKey>,
    observed_true: HashSet<FuzzBranchFrontierKey>,
}

impl FuzzFrontierRecorder {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            limit,
            frontiers: Vec::with_capacity(limit.min(32)),
            indexes: HashMap::default(),
            observed_false: HashSet::default(),
            observed_true: HashSet::default(),
        }
    }

    pub(super) fn capture_stateless_call(
        &mut self,
        run: Option<&FuzzRunMetadata>,
        sender: Address,
        target: Address,
        calldata: &Bytes,
        cmp_values: &[CmpOperands],
        new_coverage: Option<bool>,
    ) {
        if self.limit == 0 || cmp_values.is_empty() {
            return;
        }

        let mut sequence = None;
        let mut new_frontier = |cmp: &CmpOperands, result, operand_delta| {
            let sequence = sequence.get_or_insert_with(|| {
                let call = BasicTxDetails {
                    warp: None,
                    roll: None,
                    sender,
                    call_details: CallDetails { target, calldata: calldata.clone(), value: None },
                };
                Arc::from(Vec::from([call]).into_boxed_slice())
            });
            FuzzBranchFrontier::new(
                run,
                Arc::clone(sequence),
                *cmp,
                result,
                operand_delta,
                new_coverage,
                0,
            )
        };

        for cmp in cmp_values {
            let result = cmp.result();
            let key = FuzzBranchFrontierKey::new(cmp);
            let operand_delta = operand_delta(cmp);
            let opposite_observed = record_observed_result(
                &mut self.observed_false,
                &mut self.observed_true,
                key,
                result,
            );

            if let Some(&index) = self.indexes.get(&key) {
                let variable_operands = self.frontiers[index].variable_operands
                    || self.frontiers[index].operands.lhs != cmp.op1
                    || self.frontiers[index].operands.rhs != cmp.op2;
                let opposite_observed = self.frontiers[index].opposite_observed
                    || opposite_observed
                    || self.frontiers[index].operands.result != result;
                let merged_new_coverage =
                    merge_new_coverage(self.frontiers[index].new_coverage, new_coverage);
                if opposite_observed {
                    self.remove_frontier(index);
                    continue;
                }
                if operand_delta < self.frontiers[index].operands.operand_delta {
                    let mut frontier = new_frontier(cmp, result, operand_delta);
                    frontier.variable_operands = variable_operands;
                    frontier.opposite_observed = opposite_observed;
                    frontier.new_coverage = merged_new_coverage;
                    self.frontiers[index] = frontier;
                } else {
                    self.frontiers[index].variable_operands = variable_operands;
                    self.frontiers[index].opposite_observed = opposite_observed;
                    self.frontiers[index].new_coverage = merged_new_coverage;
                }
            } else if !opposite_observed {
                let frontier = new_frontier(cmp, result, operand_delta);
                self.insert_frontier(key, frontier);
            }
        }
    }

    pub(super) fn into_frontiers(self) -> Vec<FuzzBranchFrontier> {
        self.frontiers
    }

    #[cfg(test)]
    pub(super) fn best_hybrid_target(&self) -> Option<HybridFuzzTarget> {
        self.best_hybrid_targets_excluding(1, |_, _| false).into_iter().next()
    }

    #[cfg(test)]
    pub(super) fn best_hybrid_target_excluding(
        &self,
        is_excluded: impl FnMut(HybridFuzzTargetKey, U256) -> bool,
    ) -> Option<HybridFuzzTarget> {
        self.best_hybrid_targets_excluding(1, is_excluded).into_iter().next()
    }

    pub(super) fn best_hybrid_targets_excluding(
        &self,
        limit: usize,
        mut is_excluded: impl FnMut(HybridFuzzTargetKey, U256) -> bool,
    ) -> Vec<HybridFuzzTarget> {
        if limit == 0 {
            return Vec::new();
        }

        let mut frontiers = self
            .frontiers
            .iter()
            .filter(|frontier| {
                frontier.variable_operands
                    && !frontier.opposite_observed
                    && !frontier.operands.operand_delta.is_zero()
            })
            .filter(|frontier| {
                !is_excluded(frontier.hybrid_target_key(), frontier.operands.operand_delta)
            })
            .collect::<Vec<_>>();
        frontiers.sort_by_key(|frontier| hybrid_target_score(frontier));
        frontiers
            .into_iter()
            .filter_map(|frontier| {
                let calldata =
                    frontier.sequence.get(frontier.call_index)?.call_details.calldata.clone();
                Some(HybridFuzzTarget::new(
                    frontier.site.address,
                    frontier.site.pc,
                    frontier.site.opcode,
                    frontier.operands.result,
                    frontier.operands.operand_delta,
                    calldata,
                ))
            })
            .take(limit)
            .collect()
    }

    pub(super) fn replayed_target_flipped(&self, target: &HybridFuzzTarget) -> bool {
        let key = FuzzBranchFrontierKey {
            address: target.address(),
            pc: target.pc(),
            opcode: target.opcode(),
        };
        if target.observed_result() {
            self.observed_false.contains(&key)
        } else {
            self.observed_true.contains(&key)
        }
    }

    fn insert_frontier(&mut self, key: FuzzBranchFrontierKey, frontier: FuzzBranchFrontier) {
        if self.frontiers.len() < self.limit {
            self.indexes.insert(key, self.frontiers.len());
            self.frontiers.push(frontier);
        } else if let Some(index) = self.worst_frontier_index()
            && frontier_retention_score(&frontier)
                < frontier_retention_score(&self.frontiers[index])
        {
            let old_key = self.frontiers[index].key();
            self.indexes.remove(&old_key);
            self.indexes.insert(key, index);
            self.frontiers[index] = frontier;
        }
    }

    fn remove_frontier(&mut self, index: usize) {
        let old_key = self.frontiers[index].key();
        self.indexes.remove(&old_key);
        self.frontiers.swap_remove(index);
        if let Some(frontier) = self.frontiers.get(index) {
            self.indexes.insert(frontier.key(), index);
        }
    }

    fn worst_frontier_index(&self) -> Option<usize> {
        self.frontiers
            .iter()
            .enumerate()
            .max_by_key(|(_, frontier)| frontier_retention_score(frontier))
            .map(|(index, _)| index)
    }
}

impl FuzzBranchFrontier {
    const fn key(&self) -> FuzzBranchFrontierKey {
        FuzzBranchFrontierKey {
            address: self.site.address,
            pc: self.site.pc,
            opcode: self.site.opcode,
        }
    }

    const fn hybrid_target_key(&self) -> HybridFuzzTargetKey {
        HybridFuzzTargetKey::new(
            self.site.address,
            self.site.pc,
            self.site.opcode,
            self.operands.result,
        )
    }

    fn new(
        run: Option<&FuzzRunMetadata>,
        sequence: Arc<[BasicTxDetails]>,
        cmp: CmpOperands,
        result: bool,
        operand_delta: U256,
        new_coverage: Option<bool>,
        call_index: usize,
    ) -> Self {
        Self {
            id: 0,
            seed: run.and_then(|run| run.seed),
            run: run.and_then(|run| run.run),
            worker: run.and_then(|run| run.worker),
            new_coverage,
            call_index,
            sequence,
            site: FuzzBranchFrontierSite {
                address: cmp.address,
                pc: cmp.pc,
                opcode: cmp.opcode,
                opcode_name: opcode_name(cmp.opcode),
            },
            operands: FuzzBranchFrontierOperands {
                lhs: cmp.op1,
                rhs: cmp.op2,
                result,
                operand_delta,
            },
            variable_operands: false,
            opposite_observed: false,
        }
    }
}

/// Merges per-worker frontier records into a single bounded, globally deduplicated set.
///
/// Each worker deduplicates its own records by comparison site while keeping the smallest
/// `operand_delta`, but workers run independently, so the same site can appear in several workers'
/// records with different observed deltas or outcomes. This applies the same site dedup and
/// smallest-delta policy across all workers, then removes sites where the concrete campaign
/// already exercised both outcomes.
pub(super) fn merge_frontiers(
    limit: usize,
    frontiers: impl IntoIterator<Item = FuzzBranchFrontier>,
) -> Vec<FuzzBranchFrontier> {
    if limit == 0 {
        return Vec::new();
    }

    let mut merged = Vec::<FuzzBranchFrontier>::with_capacity(limit.min(32));
    let mut indexes = HashMap::<FuzzBranchFrontierKey, usize>::default();
    let mut observed_false = HashSet::<FuzzBranchFrontierKey>::default();
    let mut observed_true = HashSet::<FuzzBranchFrontierKey>::default();
    for mut frontier in frontiers {
        let key = frontier.key();
        frontier.opposite_observed |= record_observed_result(
            &mut observed_false,
            &mut observed_true,
            key,
            frontier.operands.result,
        );
        if let Some(&index) = indexes.get(&key) {
            let mut frontier = frontier;
            let merged_new_coverage =
                merge_new_coverage(merged[index].new_coverage, frontier.new_coverage);
            let variable_operands = merged[index].variable_operands || frontier.variable_operands;
            let opposite_observed = merged[index].opposite_observed
                || frontier.opposite_observed
                || merged[index].operands.result != frontier.operands.result;
            if frontier.operands.operand_delta < merged[index].operands.operand_delta {
                frontier.new_coverage = merged_new_coverage;
                frontier.variable_operands = variable_operands;
                frontier.opposite_observed = opposite_observed;
                merged[index] = frontier;
            } else {
                merged[index].new_coverage = merged_new_coverage;
                merged[index].variable_operands = variable_operands;
                merged[index].opposite_observed = opposite_observed;
            }
        } else if !frontier.opposite_observed && merged.len() < limit {
            indexes.insert(key, merged.len());
            merged.push(frontier);
        } else if !frontier.opposite_observed
            && let Some(index) = merged
                .iter()
                .enumerate()
                .max_by_key(|(_, retained)| frontier_retention_score(retained))
                .map(|(index, _)| index)
            && frontier_retention_score(&frontier) < frontier_retention_score(&merged[index])
        {
            let old_key = merged[index].key();
            indexes.remove(&old_key);
            indexes.insert(key, index);
            merged[index] = frontier;
        }
    }

    merged.retain(|frontier| !frontier.opposite_observed);
    merged
}

fn frontier_retention_score(frontier: &FuzzBranchFrontier) -> (bool, bool, bool, U256) {
    (
        frontier.opposite_observed,
        !frontier.new_coverage.unwrap_or(false),
        !frontier.variable_operands,
        frontier.operands.operand_delta,
    )
}

fn hybrid_target_score(frontier: &FuzzBranchFrontier) -> (bool, U256) {
    (!frontier.new_coverage.unwrap_or(false), frontier.operands.operand_delta)
}

fn record_observed_result(
    observed_false: &mut HashSet<FuzzBranchFrontierKey>,
    observed_true: &mut HashSet<FuzzBranchFrontierKey>,
    key: FuzzBranchFrontierKey,
    result: bool,
) -> bool {
    if result {
        observed_true.insert(key);
        observed_false.contains(&key)
    } else {
        observed_false.insert(key);
        observed_true.contains(&key)
    }
}

const fn merge_new_coverage(current: Option<bool>, next: Option<bool>) -> Option<bool> {
    match (current, next) {
        (Some(true), _) | (_, Some(true)) => Some(true),
        (Some(false), _) | (_, Some(false)) => Some(false),
        (None, None) => None,
    }
}

pub(super) fn write_frontier_artifact(
    dir: &Path,
    artifact: &FuzzBranchFrontierArtifact,
) -> fs::Result<()> {
    fs::create_dir_all(dir)?;
    fs::write_json_file(&dir.join(FRONTIER_FILE), artifact)
}

fn serialize_sequence<S>(sequence: &Arc<[BasicTxDetails]>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    Serialize::serialize(sequence.as_ref(), serializer)
}

fn operand_delta(cmp: &CmpOperands) -> U256 {
    match cmp.opcode {
        opcode::LT => {
            if cmp.op1 < cmp.op2 {
                cmp.op2 - cmp.op1
            } else {
                add_one_saturating(cmp.op1 - cmp.op2)
            }
        }
        opcode::GT => {
            if cmp.op1 > cmp.op2 {
                cmp.op1 - cmp.op2
            } else {
                add_one_saturating(cmp.op2 - cmp.op1)
            }
        }
        opcode::SLT => {
            let distance = signed_operand_delta(cmp.op1, cmp.op2);
            if I256::from_raw(cmp.op1) < I256::from_raw(cmp.op2) {
                distance
            } else {
                add_one_saturating(distance)
            }
        }
        opcode::SGT => {
            let distance = signed_operand_delta(cmp.op1, cmp.op2);
            if I256::from_raw(cmp.op1) > I256::from_raw(cmp.op2) {
                distance
            } else {
                add_one_saturating(distance)
            }
        }
        _ => unsigned_operand_delta(cmp.op1, cmp.op2),
    }
}

fn add_one_saturating(value: U256) -> U256 {
    if value == U256::MAX { value } else { value + U256::from(1) }
}

fn unsigned_operand_delta(left: U256, right: U256) -> U256 {
    if left >= right { left - right } else { right - left }
}

fn signed_operand_delta(left: U256, right: U256) -> U256 {
    let (left_negative, left_magnitude) = signed_magnitude(left);
    let (right_negative, right_magnitude) = signed_magnitude(right);

    if left_negative == right_negative {
        unsigned_operand_delta(left_magnitude, right_magnitude)
    } else {
        left_magnitude + right_magnitude
    }
}

fn signed_magnitude(value: U256) -> (bool, U256) {
    let negative = I256::from_raw(value) < I256::ZERO;
    let magnitude = if negative { U256::ZERO.wrapping_sub(value) } else { value };
    (negative, magnitude)
}

const fn opcode_name(op: u8) -> &'static str {
    match op {
        opcode::EQ => "EQ",
        opcode::LT => "LT",
        opcode::GT => "GT",
        opcode::SLT => "SLT",
        opcode::SGT => "SGT",
        opcode::ISZERO => "ISZERO",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operand_delta_uses_signed_distance_for_signed_comparisons() {
        let unsigned = CmpOperands {
            op1: U256::MAX,
            op2: U256::from(1),
            pc: 0,
            address: Address::ZERO,
            opcode: opcode::LT,
        };
        assert_eq!(operand_delta(&unsigned), U256::MAX);

        let signed = CmpOperands { opcode: opcode::SLT, ..unsigned };
        assert_eq!(operand_delta(&signed), U256::from(2));
    }

    #[test]
    fn signed_operand_delta_handles_full_int256_range() {
        let min = I256::MIN.into_raw();
        let max = I256::MAX.into_raw();

        assert_eq!(signed_operand_delta(min, max), U256::MAX);
    }

    #[test]
    fn operand_delta_counts_strict_equality_boundaries_as_one_step() {
        let mut cmp = CmpOperands {
            op1: U256::from(5),
            op2: U256::from(5),
            pc: 0,
            address: Address::ZERO,
            opcode: opcode::LT,
        };
        assert_eq!(operand_delta(&cmp), U256::from(1));

        cmp.opcode = opcode::GT;
        assert_eq!(operand_delta(&cmp), U256::from(1));

        cmp.opcode = opcode::SLT;
        assert_eq!(operand_delta(&cmp), U256::from(1));

        cmp.opcode = opcode::SGT;
        assert_eq!(operand_delta(&cmp), U256::from(1));
    }

    fn frontier(pc: usize, result: bool, operand_delta: u64) -> FuzzBranchFrontier {
        frontier_at(Address::ZERO, pc, result, operand_delta)
    }

    fn frontier_at(
        address: Address,
        pc: usize,
        result: bool,
        operand_delta: u64,
    ) -> FuzzBranchFrontier {
        let cmp = CmpOperands { op1: U256::ZERO, op2: U256::ZERO, pc, address, opcode: opcode::LT };
        FuzzBranchFrontier::new(
            None,
            Arc::from(Vec::<BasicTxDetails>::new().into_boxed_slice()),
            cmp,
            result,
            U256::from(operand_delta),
            None,
            0,
        )
    }

    #[test]
    fn merge_frontiers_dedupes_across_workers_keeping_smallest_delta() {
        let merged = merge_frontiers(
            8,
            [frontier(1, false, 30), frontier(1, false, 10), frontier(1, false, 20)],
        );

        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].operands.operand_delta, U256::from(10));
    }

    #[test]
    fn merge_frontiers_drops_sites_with_both_results_observed() {
        let merged = merge_frontiers(8, [frontier(1, false, 5), frontier(1, true, 5)]);

        assert!(merged.is_empty());
    }

    #[test]
    fn merge_frontiers_replaces_worst_frontier_after_limit_is_full() {
        // The first two unique keys fill the limit; later closer frontiers should still displace
        // worse retained keys instead of being dropped just because they appeared late.
        let merged = merge_frontiers(
            2,
            [
                frontier(1, false, 30),
                frontier(2, false, 30),
                frontier(3, false, 5),
                frontier(1, false, 10),
            ],
        );

        assert_eq!(merged.len(), 2);
        let retained = merged.iter().find(|f| f.site.pc == 1).unwrap();
        assert_eq!(retained.operands.operand_delta, U256::from(10));
        assert!(merged.iter().any(|f| f.site.pc == 3));
    }

    #[test]
    fn merge_frontiers_does_not_spend_limit_on_duplicates() {
        // A duplicate of a retained key must not count against the limit, so a later distinct key
        // still fits. This guards against counting processed records instead of unique keys.
        let merged = merge_frontiers(
            2,
            [frontier(1, false, 30), frontier(1, false, 10), frontier(2, false, 5)],
        );

        assert_eq!(merged.len(), 2);
        assert_eq!(
            merged.iter().find(|f| f.site.pc == 1).unwrap().operands.operand_delta,
            U256::from(10)
        );
        assert!(merged.iter().any(|f| f.site.pc == 2));
    }

    #[test]
    fn merge_frontiers_distinguishes_by_address() {
        // Same pc/opcode at different addresses are distinct sites.
        let other = Address::with_last_byte(1);
        let merged = merge_frontiers(
            8,
            [frontier_at(Address::ZERO, 1, false, 5), frontier_at(other, 1, false, 5)],
        );

        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn merge_frontiers_with_zero_limit_is_empty() {
        assert!(merge_frontiers(0, [frontier(1, false, 1)]).is_empty());
    }

    #[test]
    fn hybrid_target_uses_closest_recorded_frontier() {
        let mut recorder = FuzzFrontierRecorder::new(8);
        let calldata = Bytes::from_static(b"target");
        recorder.capture_stateless_call(
            None,
            Address::ZERO,
            Address::ZERO,
            &calldata,
            &[
                CmpOperands {
                    op1: U256::from(10),
                    op2: U256::ZERO,
                    pc: 1,
                    address: Address::ZERO,
                    opcode: opcode::EQ,
                },
                CmpOperands {
                    op1: U256::from(2),
                    op2: U256::ZERO,
                    pc: 2,
                    address: Address::ZERO,
                    opcode: opcode::EQ,
                },
            ],
            Some(false),
        );
        recorder.capture_stateless_call(
            None,
            Address::ZERO,
            Address::ZERO,
            &calldata,
            &[
                CmpOperands {
                    op1: U256::from(10),
                    op2: U256::ZERO,
                    pc: 1,
                    address: Address::ZERO,
                    opcode: opcode::EQ,
                },
                CmpOperands {
                    op1: U256::from(1),
                    op2: U256::ZERO,
                    pc: 2,
                    address: Address::ZERO,
                    opcode: opcode::EQ,
                },
            ],
            Some(false),
        );

        let target = recorder.best_hybrid_target().unwrap();
        assert_eq!(target.pc(), 2);
        assert_eq!(target.calldata(), &calldata);
    }

    #[test]
    fn hybrid_target_prefers_coverage_frontier_over_closest_delta() {
        let mut recorder = FuzzFrontierRecorder::new(8);
        let calldata = Bytes::from_static(b"target");
        recorder.capture_stateless_call(
            None,
            Address::ZERO,
            Address::ZERO,
            &calldata,
            &[CmpOperands {
                op1: U256::from(2),
                op2: U256::ZERO,
                pc: 1,
                address: Address::ZERO,
                opcode: opcode::EQ,
            }],
            Some(false),
        );
        recorder.capture_stateless_call(
            None,
            Address::ZERO,
            Address::ZERO,
            &calldata,
            &[CmpOperands {
                op1: U256::from(1),
                op2: U256::ZERO,
                pc: 1,
                address: Address::ZERO,
                opcode: opcode::EQ,
            }],
            Some(false),
        );
        recorder.capture_stateless_call(
            None,
            Address::ZERO,
            Address::ZERO,
            &calldata,
            &[CmpOperands {
                op1: U256::from(20),
                op2: U256::ZERO,
                pc: 2,
                address: Address::ZERO,
                opcode: opcode::EQ,
            }],
            Some(true),
        );
        recorder.capture_stateless_call(
            None,
            Address::ZERO,
            Address::ZERO,
            &calldata,
            &[CmpOperands {
                op1: U256::from(19),
                op2: U256::ZERO,
                pc: 2,
                address: Address::ZERO,
                opcode: opcode::EQ,
            }],
            Some(false),
        );

        let target = recorder.best_hybrid_target().unwrap();
        assert_eq!(target.pc(), 2);
    }

    #[test]
    fn hybrid_target_skips_attempted_frontiers() {
        let mut recorder = FuzzFrontierRecorder::new(8);
        let calldata = Bytes::from_static(b"target");
        for value in [U256::from(2), U256::from(1)] {
            recorder.capture_stateless_call(
                None,
                Address::ZERO,
                Address::ZERO,
                &calldata,
                &[
                    CmpOperands {
                        op1: value,
                        op2: U256::ZERO,
                        pc: 1,
                        address: Address::ZERO,
                        opcode: opcode::EQ,
                    },
                    CmpOperands {
                        op1: value + U256::from(9),
                        op2: U256::ZERO,
                        pc: 2,
                        address: Address::ZERO,
                        opcode: opcode::EQ,
                    },
                ],
                Some(false),
            );
        }

        let first = recorder.best_hybrid_target().unwrap();
        assert_eq!(first.pc(), 1);
        let second = recorder.best_hybrid_target_excluding(|key, _| key == first.key()).unwrap();
        assert_eq!(second.pc(), 2);
    }

    #[test]
    fn hybrid_target_requires_concrete_opposite_result() {
        let mut recorder = FuzzFrontierRecorder::new(8);
        let calldata = Bytes::from_static(b"target");
        for value in [U256::from(2), U256::from(1)] {
            recorder.capture_stateless_call(
                None,
                Address::ZERO,
                Address::ZERO,
                &calldata,
                &[CmpOperands {
                    op1: value,
                    op2: U256::ZERO,
                    pc: 1,
                    address: Address::ZERO,
                    opcode: opcode::EQ,
                }],
                Some(false),
            );
        }

        let target = recorder.best_hybrid_target().unwrap();
        assert!(!recorder.replayed_target_flipped(&target));

        recorder.capture_stateless_call(
            None,
            Address::ZERO,
            Address::ZERO,
            &calldata,
            &[CmpOperands {
                op1: U256::ZERO,
                op2: U256::ZERO,
                pc: 1,
                address: Address::ZERO,
                opcode: opcode::EQ,
            }],
            Some(false),
        );
        assert!(recorder.replayed_target_flipped(&target));
    }

    #[test]
    fn hybrid_targets_returns_ranked_bounded_burst() {
        let mut recorder = FuzzFrontierRecorder::new(8);
        let calldata = Bytes::from_static(b"target");
        for (pc, delta, new_coverage) in [(1, 5, false), (2, 3, true), (3, 1, false), (4, 2, true)]
        {
            for observed_delta in [delta + 10, delta] {
                recorder.capture_stateless_call(
                    None,
                    Address::ZERO,
                    Address::ZERO,
                    &calldata,
                    &[CmpOperands {
                        op1: U256::from(observed_delta),
                        op2: U256::ZERO,
                        pc,
                        address: Address::ZERO,
                        opcode: opcode::EQ,
                    }],
                    Some(new_coverage),
                );
            }
        }

        let skipped_key = recorder
            .frontiers
            .iter()
            .find(|frontier| frontier.site.pc == 2)
            .unwrap()
            .hybrid_target_key();
        let targets = recorder.best_hybrid_targets_excluding(3, |key, _| key == skipped_key);
        assert_eq!(targets.iter().map(|target| target.pc()).collect::<Vec<_>>(), vec![4, 3, 1]);
    }

    #[test]
    fn hybrid_target_retries_attempted_frontier_after_delta_improves() {
        let mut recorder = FuzzFrontierRecorder::new(8);
        let calldata = Bytes::from_static(b"target");
        for value in [U256::from(10), U256::from(5)] {
            recorder.capture_stateless_call(
                None,
                Address::ZERO,
                Address::ZERO,
                &calldata,
                &[CmpOperands {
                    op1: value,
                    op2: U256::ZERO,
                    pc: 1,
                    address: Address::ZERO,
                    opcode: opcode::EQ,
                }],
                Some(false),
            );
        }

        let first = recorder.best_hybrid_target().unwrap();
        assert_eq!(first.operand_delta(), U256::from(5));
        assert!(
            recorder
                .best_hybrid_target_excluding(|key, delta| {
                    key == first.key() && delta >= first.operand_delta()
                })
                .is_none()
        );

        recorder.capture_stateless_call(
            None,
            Address::ZERO,
            Address::ZERO,
            &calldata,
            &[CmpOperands {
                op1: U256::from(3),
                op2: U256::ZERO,
                pc: 1,
                address: Address::ZERO,
                opcode: opcode::EQ,
            }],
            Some(false),
        );

        let improved = recorder
            .best_hybrid_target_excluding(|key, delta| {
                key == first.key() && delta >= first.operand_delta()
            })
            .unwrap();
        assert_eq!(improved.pc(), 1);
        assert_eq!(improved.operand_delta(), U256::from(3));
    }

    #[test]
    fn hybrid_target_skips_sites_after_concrete_observes_both_results() {
        let mut recorder = FuzzFrontierRecorder::new(8);
        let calldata = Bytes::from_static(b"target");
        for value in [U256::from(10), U256::from(5)] {
            recorder.capture_stateless_call(
                None,
                Address::ZERO,
                Address::ZERO,
                &calldata,
                &[CmpOperands {
                    op1: value,
                    op2: U256::ZERO,
                    pc: 1,
                    address: Address::ZERO,
                    opcode: opcode::EQ,
                }],
                Some(false),
            );
        }
        assert_eq!(recorder.best_hybrid_target().unwrap().pc(), 1);

        recorder.capture_stateless_call(
            None,
            Address::ZERO,
            Address::ZERO,
            &calldata,
            &[CmpOperands {
                op1: U256::ZERO,
                op2: U256::ZERO,
                pc: 1,
                address: Address::ZERO,
                opcode: opcode::EQ,
            }],
            Some(false),
        );
        assert!(recorder.best_hybrid_target().is_none());

        recorder.capture_stateless_call(
            None,
            Address::ZERO,
            Address::ZERO,
            &calldata,
            &[CmpOperands {
                op1: U256::from(3),
                op2: U256::ZERO,
                pc: 1,
                address: Address::ZERO,
                opcode: opcode::EQ,
            }],
            Some(false),
        );
        assert!(recorder.best_hybrid_target().is_none());
    }

    #[test]
    fn recorder_replaces_worst_frontier_when_limit_is_full() {
        let mut recorder = FuzzFrontierRecorder::new(2);
        for (pc, operand_delta, new_coverage) in [
            (1, U256::from(30), Some(false)),
            (2, U256::from(20), Some(false)),
            (3, U256::from(10), Some(true)),
        ] {
            recorder.capture_stateless_call(
                None,
                Address::ZERO,
                Address::ZERO,
                &Bytes::new(),
                &[CmpOperands {
                    op1: operand_delta,
                    op2: U256::ZERO,
                    pc,
                    address: Address::ZERO,
                    opcode: opcode::EQ,
                }],
                new_coverage,
            );
        }

        let retained = recorder.into_frontiers();
        assert_eq!(retained.len(), 2);
        assert!(retained.iter().any(|frontier| frontier.site.pc == 3));
    }

    #[test]
    fn hybrid_target_ignores_constant_setup_comparisons() {
        let mut recorder = FuzzFrontierRecorder::new(8);
        let cmp = CmpOperands {
            op1: U256::ZERO,
            op2: U256::ZERO,
            pc: 1,
            address: Address::ZERO,
            opcode: opcode::ISZERO,
        };
        for _ in 0..2 {
            recorder.capture_stateless_call(
                None,
                Address::ZERO,
                Address::ZERO,
                &Bytes::new(),
                &[cmp],
                Some(false),
            );
        }

        assert!(recorder.best_hybrid_target().is_none());
    }

    #[test]
    fn hybrid_target_ignores_variable_identity_comparisons() {
        let mut recorder = FuzzFrontierRecorder::new(8);
        let calldata = Bytes::from_static(b"target");
        for value in [U256::from(1), U256::from(2)] {
            recorder.capture_stateless_call(
                None,
                Address::ZERO,
                Address::ZERO,
                &calldata,
                &[
                    CmpOperands {
                        op1: value,
                        op2: value,
                        pc: 1,
                        address: Address::ZERO,
                        opcode: opcode::EQ,
                    },
                    CmpOperands {
                        op1: value,
                        op2: U256::from(10),
                        pc: 2,
                        address: Address::ZERO,
                        opcode: opcode::EQ,
                    },
                ],
                Some(false),
            );
        }

        let target = recorder.best_hybrid_target().unwrap();
        assert_eq!(target.pc(), 2);
    }
}
