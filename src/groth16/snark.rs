use ff::PrimeField;
use pairing::{MultiMillerLoop, Engine};
// use serde::{Deserialize, Serialize};
use ec_gpu_gen::multiexp_cpu::{DensityTracker}; 
use bellperson::groth16::{VerifyingKey};

/// A type that represents the prover's key
// #[derive(Serialize, Deserialize)]
// #[serde(bound = "")]
pub struct ProverKey<Scalar: PrimeField> {
  // Density of queries
  a_aux_density: DensityTracker,
  b_input_density: DensityTracker,
  b_aux_density: DensityTracker,

  // Evaluations of A, B, C polynomials
  a: Vec<Scalar>,
  b: Vec<Scalar>,
  c: Vec<Scalar>,

  // Assignments of variables
  input_assignment: Vec<Scalar>,
  aux_assignment: Vec<Scalar>,
}

/// A type that represents the verifier's key
// #[derive(Serialize, Deserialize)]
// #[serde(bound = "")]
pub struct VerifierKey<E: Engine + MultiMillerLoop> {
  vk: VerifyingKey<E>,
}


// impl<G: Group, EE: EvaluationEngineTrait<G, CE = G::CE>> RelaxedR1CSSNARKTrait<G>
//   for RelaxedR1CSSNARK<G, EE>
// {
//   type ProverKey = ProverKey<G, EE>;
//   type VerifierKey = VerifierKey<G, EE>;

//    fn setup(
//     ck: &CommitmentKey<G>,
//     S: &R1CSShape<G>,
//   ) -> Result<(Self::ProverKey, Self::VerifierKey), NovaError> {

//   }
// }
