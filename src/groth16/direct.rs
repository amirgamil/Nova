use ff::PrimeField;
use pairing::{MultiMillerLoop, Engine};
// use serde::{Deserialize, Serialize};
use ec_gpu_gen::multiexp_cpu::{DensityTracker}; 
use bellperson::{groth16::{VerifyingKey, prepare_verifying_key, generate_random_parameters}, ConstraintSystem, SynthesisError, gadgets::num::AllocatedNum};
use crate::{
  errors::NovaError,
  r1cs::{R1CSShape, RelaxedR1CSInstance, RelaxedR1CSWitness},
  traits::{Group, evaluation::EvaluationEngineTrait, snark::RelaxedR1CSSNARKTrait},
  CommitmentKey, 
};



#[test]
fn test_direct_groth16() {

}