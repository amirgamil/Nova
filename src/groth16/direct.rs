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


#[cfg(test)]
mod tests {
  fn test_direct_snark() {
    type G = pasta_curves::pallas::Point;
    type EE = crate::provider::ipa_pc::EvaluationEngine<G>;
    type S = crate::groth16::snark::RelaxedR1CSSNARK<G, EE>;
    test_direct_snark_with::<G, S>();

  }

  fn test_direct_snark_with<G: Group, S: RelaxedR1CSSNARKTrait<G>>() {
    let circuit = CubicCircuit::default();

    // produce keys
    let (pk, vk) =
      DirectSNARK::<G, S, CubicCircuit<<G as Group>::Scalar>>::setup(circuit.clone()).unwrap();

    let num_steps = 3;

    // setup inputs
    let z0 = vec![<G as Group>::Scalar::ZERO];
    let mut z_i = z0;

    for _i in 0..num_steps {
      // produce a SNARK
      let res = DirectSNARK::prove(&pk, circuit.clone(), &z_i);
      assert!(res.is_ok());

      let z_i_plus_one = circuit.output(&z_i);

      let snark = res.unwrap();

      // verify the SNARK
      let io = z_i
        .clone()
        .into_iter()
        .chain(z_i_plus_one.clone())
        .collect::<Vec<_>>();
      let res = snark.verify(&vk, &io);
      assert!(res.is_ok());

      // set input to the next step
      z_i = z_i_plus_one.clone();
    }

    // sanity: check the claimed output with a direct computation of the same
    assert_eq!(z_i, vec![<G as Group>::Scalar::from(2460515u64)]);
  }
}
