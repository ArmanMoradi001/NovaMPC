//! Compiler from the canonical v2 circuit into the LPPC instance used by
//! TCitH-ΠLigero (FR25b §6.3–6.4).
//!
//! Each multiplication contributes one `(a, b, c)` triple. Groups of `s`
//! triples are checked with the coordinate-wise quadratic relation
//! `c - a*b = 0`; global linear constraints bind `a` and `b` to the circuit's
//! affine wire expressions and enforce every `AssertEq`.
//!
//! Ordering audit (P3.1, against FR25b §6.3–6.4): the paper defines the
//! witness as the concatenation `w = a || b || c` (`|w| = 3|C|`) arranged
//! row-wise into packs of `s`, with one quadratic polynomial `f = c - a·b`
//! applied per pack-slot lane and `m2 = 2|C| + |y|` global linear constraints
//! (`a = A1·w`, `b = A2·w`, `y = A3·w`). This compiler lays each `s`-gate
//! group out as consecutive `(a, b, c)` rows instead of `a || b || c` blocks
//! and appends the private inputs in trailing packs. That is a pure
//! permutation of the packed witness: the same relation family (one quadratic
//! check per occupied lane, `2M` operand-binding plus `#AssertEq` output
//! equations) with permuted `A`-matrix columns, so it is a valid LPPC
//! instance of exactly the analyzed form — no paper change needed, and none
//! was made. Two deliberate deviations from the paper's minimal sketch are
//! pinned by tests: (a) inputs are committed inside `w` (the paper's
//! footnote-12 input-free optimization is optional; the size model counts our
//! `|w|`), and (b) a short final group is zero-padded, whose lanes satisfy
//! `0 = 0·0` without constraining any real gate.
//!
//! This is a relation compiler only. It does not implement the MPC protocol,
//! randomized aggregation, or a proof/verifier.

use std::collections::BTreeMap;

use ark_bn254::Fr;

use crate::v2::circuit::{CircuitV2, GateV2, Wire};
use crate::v3::matrix::{pack_witness, unpack_matrix, MatrixDims};
use crate::v3::params::V3Params;
use crate::{MpcithError, Result};

/// A sparse affine expression over the extended witness, plus a constant.
#[derive(Debug, Clone, Default)]
struct AffineExpr {
    terms: BTreeMap<usize, Fr>,
    constant: Fr,
}

impl AffineExpr {
    fn variable(index: usize) -> Self {
        Self {
            terms: BTreeMap::from([(index, Fr::from(1u64))]),
            constant: Fr::from(0u64),
        }
    }

    fn add_scaled(&self, other: &Self, scale: Fr) -> Self {
        let mut result = self.clone();
        for (index, coefficient) in &other.terms {
            let next = result.terms.get(index).copied().unwrap_or_default() + *coefficient * scale;
            if next == Fr::from(0u64) {
                result.terms.remove(index);
            } else {
                result.terms.insert(*index, next);
            }
        }
        result.constant += other.constant * scale;
        result
    }

    fn scale(&self, factor: Fr) -> Self {
        let terms = self
            .terms
            .iter()
            .filter_map(|(index, coefficient)| {
                let scaled = *coefficient * factor;
                (scaled != Fr::from(0u64)).then_some((*index, scaled))
            })
            .collect();
        Self {
            terms,
            constant: self.constant * factor,
        }
    }
}

/// One global linear equation `sum(coeff_i * witness_i) = rhs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearConstraintV3 {
    pub terms: Vec<(usize, Fr)>,
    pub rhs: Fr,
}

impl LinearConstraintV3 {
    fn from_expr(expr: &AffineExpr, rhs: Fr) -> Self {
        Self {
            terms: expr.terms.iter().map(|(i, c)| (*i, *c)).collect(),
            rhs: rhs - expr.constant,
        }
    }

    fn holds(&self, witness: &[Fr]) -> bool {
        self.terms
            .iter()
            .try_fold(Fr::from(0u64), |sum, (index, coefficient)| {
                witness.get(*index).map(|value| sum + *coefficient * value)
            })
            == Some(self.rhs)
    }
}

/// Matrix row locations for one group of up to `s` multiplication triples.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParallelMulGroupV3 {
    pub first_gate: usize,
    pub gate_count: usize,
    pub a_row: usize,
    pub b_row: usize,
    pub c_row: usize,
}

/// Compiled LPPC relation for a circuit.
#[derive(Debug, Clone)]
pub struct ConstraintProgramV3 {
    circuit: CircuitV2,
    dims: MatrixDims,
    input_offset: usize,
    num_inputs: usize,
    num_mul_gates: usize,
    num_assertions: usize,
    groups: Vec<ParallelMulGroupV3>,
    linear_constraints: Vec<LinearConstraintV3>,
}

impl ConstraintProgramV3 {
    /// Compile a canonical circuit into the witness and constraint layout.
    pub fn compile(circuit: &CircuitV2, params: &V3Params) -> Result<Self> {
        params.validate()?;
        let s = params.packing_width as usize;
        let num_mul_gates = circuit
            .gates()
            .iter()
            .filter(|gate| matches!(gate, GateV2::Mul { .. }))
            .count();
        if num_mul_gates == 0 {
            return Err(MpcithError::InvalidParams(
                "v3 LPPC compiler requires at least one multiplication gate".into(),
            ));
        }

        let num_groups = num_mul_gates.div_ceil(s);
        let input_rows = circuit.num_inputs().div_ceil(s);
        let input_offset = num_groups * 3 * s;
        let num_rows = 3 * num_groups + input_rows;
        let dims = MatrixDims {
            num_rows,
            num_cols: s,
            padded_len: num_rows * s,
        };

        let mut groups = Vec::with_capacity(num_groups);
        for group in 0..num_groups {
            let first_gate = group * s;
            groups.push(ParallelMulGroupV3 {
                first_gate,
                gate_count: (num_mul_gates - first_gate).min(s),
                a_row: group * 3,
                b_row: group * 3 + 1,
                c_row: group * 3 + 2,
            });
        }

        let mut wire_exprs: Vec<Option<AffineExpr>> = vec![None; circuit.num_wires()];
        for input in 0..circuit.num_inputs() {
            wire_exprs[input] = Some(AffineExpr::variable(input_offset + input));
        }

        let mut linear_constraints = Vec::with_capacity(2 * num_mul_gates);
        let mut mul_index = 0usize;
        let mut num_assertions = 0usize;
        let one = Fr::from(1u64);

        for gate in circuit.gates() {
            match gate {
                GateV2::Add {
                    left,
                    right,
                    output,
                } => {
                    let expr = read_expr(&wire_exprs, *left)?
                        .add_scaled(&read_expr(&wire_exprs, *right)?, one);
                    set_expr(&mut wire_exprs, *output, expr)?;
                }
                GateV2::AddConst {
                    input,
                    constant,
                    output,
                } => {
                    let mut expr = read_expr(&wire_exprs, *input)?;
                    expr.constant += *constant;
                    set_expr(&mut wire_exprs, *output, expr)?;
                }
                GateV2::MulConst {
                    input,
                    constant,
                    output,
                } => {
                    let expr = read_expr(&wire_exprs, *input)?.scale(*constant);
                    set_expr(&mut wire_exprs, *output, expr)?;
                }
                GateV2::Mul {
                    left,
                    right,
                    output,
                } => {
                    let group = mul_index / s;
                    let lane = mul_index % s;
                    let a_index = groups[group].a_row * s + lane;
                    let b_index = groups[group].b_row * s + lane;
                    let c_index = groups[group].c_row * s + lane;

                    // a_j = left-wire expression; b_j = right-wire expression.
                    let mut left_eq = read_expr(&wire_exprs, *left)?;
                    let left_coefficient =
                        left_eq.terms.get(&a_index).copied().unwrap_or_default() - one;
                    if left_coefficient == Fr::from(0u64) {
                        left_eq.terms.remove(&a_index);
                    } else {
                        left_eq.terms.insert(a_index, left_coefficient);
                    }
                    linear_constraints
                        .push(LinearConstraintV3::from_expr(&left_eq, Fr::from(0u64)));

                    let mut right_eq = read_expr(&wire_exprs, *right)?;
                    let right_coefficient =
                        right_eq.terms.get(&b_index).copied().unwrap_or_default() - one;
                    if right_coefficient == Fr::from(0u64) {
                        right_eq.terms.remove(&b_index);
                    } else {
                        right_eq.terms.insert(b_index, right_coefficient);
                    }
                    linear_constraints
                        .push(LinearConstraintV3::from_expr(&right_eq, Fr::from(0u64)));

                    set_expr(&mut wire_exprs, *output, AffineExpr::variable(c_index))?;
                    mul_index += 1;
                }
                GateV2::AssertEq { input, expected } => {
                    linear_constraints.push(LinearConstraintV3::from_expr(
                        &read_expr(&wire_exprs, *input)?,
                        *expected,
                    ));
                    num_assertions += 1;
                }
            }
        }

        debug_assert_eq!(mul_index, num_mul_gates);
        Ok(Self {
            circuit: circuit.clone(),
            dims,
            input_offset,
            num_inputs: circuit.num_inputs(),
            num_mul_gates,
            num_assertions,
            groups,
            linear_constraints,
        })
    }

    pub fn dims(&self) -> MatrixDims {
        self.dims
    }

    pub fn parallel_groups(&self) -> &[ParallelMulGroupV3] {
        &self.groups
    }

    pub fn linear_constraints(&self) -> &[LinearConstraintV3] {
        &self.linear_constraints
    }

    pub fn num_mul_gates(&self) -> usize {
        self.num_mul_gates
    }

    pub fn num_assertions(&self) -> usize {
        self.num_assertions
    }

    /// Number of parallel quadratic constraint families, `ceil(M/s)`.
    pub fn m1(&self) -> usize {
        self.groups.len()
    }

    /// Number of global linear constraints, `2M + #AssertEq`.
    pub fn m2(&self) -> usize {
        self.linear_constraints.len()
    }

    /// Build the extended witness matrix for any private input vector.
    /// Assertions are intentionally not checked here, so invalid inputs can be
    /// used in differential tests.
    pub fn witness_matrix(&self, circuit: &CircuitV2, inputs: &[Fr]) -> Result<Vec<Vec<Fr>>> {
        if circuit != &self.circuit {
            return Err(MpcithError::InvalidParams(
                "v3 witness circuit differs from the compiled LPPC relation".into(),
            ));
        }
        if inputs.len() != self.num_inputs || circuit.num_inputs() != self.num_inputs {
            return Err(MpcithError::InvalidWitness(format!(
                "v3 input length {}, expected {}",
                inputs.len(),
                self.num_inputs
            )));
        }
        let mut wire_values: Vec<Option<Fr>> = vec![None; circuit.num_wires()];
        for (i, value) in inputs.iter().enumerate() {
            wire_values[i] = Some(*value);
        }
        let mut triples = Vec::with_capacity(self.num_mul_gates);
        for gate in circuit.gates() {
            match gate {
                GateV2::Add {
                    left,
                    right,
                    output,
                } => {
                    let value =
                        read_value(&wire_values, *left)? + read_value(&wire_values, *right)?;
                    set_value(&mut wire_values, *output, value)?;
                }
                GateV2::AddConst {
                    input,
                    constant,
                    output,
                } => {
                    let value = read_value(&wire_values, *input)? + *constant;
                    set_value(&mut wire_values, *output, value)?;
                }
                GateV2::MulConst {
                    input,
                    constant,
                    output,
                } => {
                    let value = read_value(&wire_values, *input)? * *constant;
                    set_value(&mut wire_values, *output, value)?;
                }
                GateV2::Mul {
                    left,
                    right,
                    output,
                } => {
                    let a = read_value(&wire_values, *left)?;
                    let b = read_value(&wire_values, *right)?;
                    let c = a * b;
                    triples.push((a, b, c));
                    set_value(&mut wire_values, *output, c)?;
                }
                GateV2::AssertEq { .. } => {}
            }
        }

        if triples.len() != self.num_mul_gates {
            return Err(MpcithError::InvalidParams(
                "v3 circuit differs from the compiled constraint program".into(),
            ));
        }
        let s = self.dims.num_cols;
        let mut flat = vec![Fr::from(0u64); self.dims.padded_len];
        for (index, (a, b, c)) in triples.into_iter().enumerate() {
            let group = index / s;
            let lane = index % s;
            flat[self.groups[group].a_row * s + lane] = a;
            flat[self.groups[group].b_row * s + lane] = b;
            flat[self.groups[group].c_row * s + lane] = c;
        }
        flat[self.input_offset..self.input_offset + self.num_inputs].copy_from_slice(inputs);
        pack_witness(&self.dims, &flat)
    }

    /// Check the unaggregated LPPC relation on a matrix. This is a compiler
    /// differential-test helper; the proof must use randomized aggregation.
    pub fn is_satisfied(&self, matrix: &[Vec<Fr>]) -> Result<bool> {
        let flat = unpack_matrix(matrix, &self.dims)?;
        for group in &self.groups {
            for lane in 0..self.dims.num_cols {
                let a = flat[group.a_row * self.dims.num_cols + lane];
                let b = flat[group.b_row * self.dims.num_cols + lane];
                let c = flat[group.c_row * self.dims.num_cols + lane];
                if c != a * b {
                    return Ok(false);
                }
            }
        }
        Ok(self
            .linear_constraints
            .iter()
            .all(|constraint| constraint.holds(&flat)))
    }
}

fn read_expr(exprs: &[Option<AffineExpr>], wire: Wire) -> Result<AffineExpr> {
    exprs
        .get(wire.index())
        .and_then(Clone::clone)
        .ok_or_else(|| {
            MpcithError::InvalidParams(format!(
                "v3 circuit references undefined wire {}",
                wire.index()
            ))
        })
}

fn set_expr(exprs: &mut [Option<AffineExpr>], wire: Wire, expr: AffineExpr) -> Result<()> {
    let slot = exprs.get_mut(wire.index()).ok_or_else(|| {
        MpcithError::InvalidParams(format!(
            "v3 circuit output wire {} is out of range",
            wire.index()
        ))
    })?;
    *slot = Some(expr);
    Ok(())
}

fn read_value(values: &[Option<Fr>], wire: Wire) -> Result<Fr> {
    values.get(wire.index()).copied().flatten().ok_or_else(|| {
        MpcithError::InvalidWitness(format!(
            "v3 circuit references undefined wire {}",
            wire.index()
        ))
    })
}

fn set_value(values: &mut [Option<Fr>], wire: Wire, value: Fr) -> Result<()> {
    let slot = values.get_mut(wire.index()).ok_or_else(|| {
        MpcithError::InvalidParams(format!(
            "v3 circuit output wire {} is out of range",
            wire.index()
        ))
    })?;
    *slot = Some(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::merkle::MerkleTreeV2;
    use crate::v2::predicate::{compile_combined, compile_range};
    use crate::v3::params::V3Params;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    #[test]
    fn simple_circuit_compiles_to_expected_lppc_counts() {
        let mut builder = crate::v2::circuit::CircuitBuilderV2::new(2);
        let sum = builder.add(Wire(0), Wire(1));
        let product = builder.mul(sum, Wire(1));
        let shifted = builder.add_const(product, Fr::from(3u64));
        builder.assert_eq(shifted, Fr::from(11u64));
        let circuit = builder.build();
        let params = V3Params::fast_insecure_test();
        let program = ConstraintProgramV3::compile(&circuit, &params).unwrap();
        assert_eq!(program.num_mul_gates(), 1);
        assert_eq!(program.num_assertions(), 1);
        assert_eq!((program.m1(), program.m2()), (1, 3));

        let valid = program
            .witness_matrix(&circuit, &[Fr::from(2u64), Fr::from(2u64)])
            .unwrap();
        assert!(program.is_satisfied(&valid).unwrap());
        let invalid = program
            .witness_matrix(&circuit, &[Fr::from(3u64), Fr::from(2u64)])
            .unwrap();
        assert!(!program.is_satisfied(&invalid).unwrap());
    }

    #[test]
    fn combined_circuit_preserves_same_input_and_matches_v2_evaluator() {
        let members = [10u32, 20, 30, 40];
        let tree = MerkleTreeV2::build(&members).unwrap();
        let compiled =
            compile_combined(10, 40, tree.root(), tree.num_members(), tree.depth()).unwrap();
        let params = V3Params::prototype_tau2();
        let program = ConstraintProgramV3::compile(compiled.circuit(), &params).unwrap();
        assert_eq!(program.num_mul_gates(), 1038);
        assert_eq!(program.num_assertions(), 81);
        assert_eq!(program.m2(), 2 * 1038 + 81);
        assert_eq!(program.m1(), 9);

        for (index, value) in members.iter().copied().enumerate() {
            let proof = tree.prove_membership(index as u32).unwrap();
            let witness = compiled.witness_for(value, Some(&proof)).unwrap();
            let valid = program
                .witness_matrix(compiled.circuit(), &witness)
                .unwrap();
            assert!(compiled.circuit().evaluate(&witness).is_ok());
            assert!(program.is_satisfied(&valid).unwrap());
        }

        let proof = tree.prove_membership(1).unwrap();
        let witness = compiled.witness_for(20, Some(&proof)).unwrap();

        let mut out_of_range = witness.clone();
        out_of_range[0] = Fr::from(100u64);
        let range_bad = program
            .witness_matrix(compiled.circuit(), &out_of_range)
            .unwrap();
        assert!(compiled.circuit().evaluate(&out_of_range).is_err());
        assert!(!program.is_satisfied(&range_bad).unwrap());

        // In the canonical combined witness, the first sibling follows x,
        // x_bits, and the two range decompositions.
        let mut wrong_path = witness;
        wrong_path[75] += Fr::from(1u64);
        let path_bad = program
            .witness_matrix(compiled.circuit(), &wrong_path)
            .unwrap();
        assert!(compiled.circuit().evaluate(&wrong_path).is_err());
        assert!(!program.is_satisfied(&path_bad).unwrap());
    }

    #[test]
    fn phase0_32_member_dimensions_and_constraint_counts_match() {
        let members: Vec<u32> = (0..32).map(|i| 100 + 10 * i).collect();
        let tree = MerkleTreeV2::build(&members).unwrap();
        let compiled =
            compile_combined(1, 1000, tree.root(), tree.num_members(), tree.depth()).unwrap();
        let program =
            ConstraintProgramV3::compile(compiled.circuit(), &V3Params::prototype_tau2()).unwrap();
        assert_eq!(program.num_mul_gates(), 1774);
        assert_eq!(program.num_assertions(), 94);
        assert_eq!(program.m1(), 15);
        assert_eq!(program.m2(), 3642);
        assert_eq!(
            (program.dims().num_rows, program.dims().num_cols),
            (46, 120)
        );
        let reference_program =
            ConstraintProgramV3::compile(compiled.circuit(), &V3Params::published_reference_tau1())
                .unwrap();
        assert_eq!(
            (
                reference_program.dims().num_rows,
                reference_program.dims().num_cols
            ),
            (43, 133)
        );
    }

    #[test]
    fn seeded_random_combined_witnesses_match_v2_relation() {
        let mut rng = StdRng::seed_from_u64(0x4e4f_5641_4d50_4333);
        let mut member_set = std::collections::BTreeSet::new();
        while member_set.len() < 12 {
            member_set.insert(rng.gen_range(100..=900));
        }
        let members: Vec<u32> = member_set.into_iter().collect();
        let tree = MerkleTreeV2::build(&members).unwrap();
        let compiled =
            compile_combined(100, 900, tree.root(), tree.num_members(), tree.depth()).unwrap();
        let program =
            ConstraintProgramV3::compile(compiled.circuit(), &V3Params::prototype_tau2()).unwrap();

        for index in 0..members.len() {
            let proof = tree.prove_membership(index as u32).unwrap();
            let witness = compiled.witness_for(members[index], Some(&proof)).unwrap();
            let matrix = program
                .witness_matrix(compiled.circuit(), &witness)
                .unwrap();
            assert_eq!(
                compiled.circuit().evaluate(&witness).is_ok(),
                program.is_satisfied(&matrix).unwrap()
            );
            assert!(program.is_satisfied(&matrix).unwrap());

            let mut outside_range = witness.clone();
            outside_range[0] = Fr::from(901 + index as u64);
            let matrix = program
                .witness_matrix(compiled.circuit(), &outside_range)
                .unwrap();
            assert_eq!(
                compiled.circuit().evaluate(&outside_range).is_ok(),
                program.is_satisfied(&matrix).unwrap()
            );
            assert!(!program.is_satisfied(&matrix).unwrap());

            let mut wrong_path = witness;
            let sibling_start = 1 + 32 + 2 * 10 + 32;
            let sibling_index = sibling_start + rng.gen_range(0..tree.depth() as usize);
            wrong_path[sibling_index] += Fr::from(rng.gen_range(1..=10_000u64));
            let matrix = program
                .witness_matrix(compiled.circuit(), &wrong_path)
                .unwrap();
            assert_eq!(
                compiled.circuit().evaluate(&wrong_path).is_ok(),
                program.is_satisfied(&matrix).unwrap()
            );
            assert!(!program.is_satisfied(&matrix).unwrap());
        }
    }

    #[test]
    fn range_only_relation_matches_v2_evaluator() {
        let compiled = compile_range(3, 9).unwrap();
        let program =
            ConstraintProgramV3::compile(compiled.circuit(), &V3Params::fast_insecure_test())
                .unwrap();
        let valid = compiled.witness_for(7, None).unwrap();
        let matrix = program.witness_matrix(compiled.circuit(), &valid).unwrap();
        assert_eq!(
            compiled.circuit().evaluate(&valid).is_ok(),
            program.is_satisfied(&matrix).unwrap()
        );
        let mut invalid = valid;
        invalid[0] = Fr::from(20u64);
        let matrix = program
            .witness_matrix(compiled.circuit(), &invalid)
            .unwrap();
        assert_eq!(
            compiled.circuit().evaluate(&invalid).is_ok(),
            program.is_satisfied(&matrix).unwrap()
        );
    }
}
