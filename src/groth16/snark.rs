use std::{sync::Arc, marker::PhantomData};

use ff::PrimeField;
use pairing::{MultiMillerLoop};
// use serde::{Deserialize, Serialize};
use bellperson::{groth16::{VerifyingKey, prepare_verifying_key, generate_random_parameters, create_random_proof, verify_proof, Proof}, ConstraintSystem, SynthesisError, gadgets::num::AllocatedNum};
use rand_core::{OsRng};
use serde::{Serialize, Deserialize, Serializer, Deserializer};
use crate::{
  errors::NovaError,
  r1cs::{R1CSShape, RelaxedR1CSInstance, RelaxedR1CSWitness},
  traits::{Group, evaluation::EvaluationEngineTrait, snark::RelaxedR1CSSNARKTrait},
  CommitmentKey, 
};

/// A type that represents the prover's key
// #[derive(Serialize, Deserialize)]
// #[serde(bound = "")]
pub struct ProverKey<E: MultiMillerLoop> {
  pub vk: VerifierKey<E>,
  // Elements of the form ((tau^i * t(tau)) / delta) for i between 0 and
  // m-2 inclusive. Never contains points at infinity.
  pub h: Arc<Vec<E::G1Affine>>,

  // Elements of the form (beta * u_i(tau) + alpha v_i(tau) + w_i(tau)) / delta
  // for all auxiliary inputs. Variables can never be unconstrained, so this
  // never contains points at infinity.
  pub l: Arc<Vec<E::G1Affine>>,

  // QAP "A" polynomials evaluated at tau in the Lagrange basis. Never contains
  // points at infinity: polynomials that evaluate to zero are omitted from
  // the CRS and the prover can deterministically skip their evaluation.
  pub a: Arc<Vec<E::G1Affine>>,

  // QAP "B" polynomials evaluated at tau in the Lagrange basis. Needed in
  // G1 and G2 for C/B queries, respectively. Never contains points at
  // infinity for the same reason as the "A" polynomials.
  pub b_g1: Arc<Vec<E::G1Affine>>,
  pub b_g2: Arc<Vec<E::G2Affine>>,
}

/// A type that represents the verifier's key
// #[derive(Serialize, Deserialize)]
// #[serde(bound = "")]
pub struct VerifierKey<E: MultiMillerLoop> {
  vk: VerifyingKey<E>,
}


// struct to construct a bellpearson circuit from a Nova R1CS representation
#[derive(Serialize, Deserialize, Clone)]
#[serde(bound(deserialize = ""))] //TODO: fix deserialize
pub struct R1CSBellpersonCircuit<G: Group, Fr: PrimeField> {
  //TODO: implement circuit which satisfier circuit trait in bellpearson given R1CS shape?  
  pub r1cs: R1CSShape<G>,
  _marker: PhantomData<Fr>,
}

impl<G: Group, Fr: PrimeField> R1CSBellpersonCircuit<G, Fr> {
    fn synthesize<CS: ConstraintSystem<Fr>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
      assert_eq!(self.r1cs.A.len(), self.r1cs.B.len());
      assert_eq!(self.r1cs.B.len(), self.r1cs.C.len());

      let mut z_out: Vec<AllocatedNum<Fr>> = Vec::new();

      // enforce all constrains a*b=c. Note inputs are included in here
      // Question: is this needed? since calling `r1cs_shape` in line 100 of direct.rs already adds all the constraints?
      for i in 1..self.r1cs.A.len() {
         cs.enforce(|| format!("constraint {}", i), self.r1cs.A[i].clone(), self.r1cs.B[i].clone(), self.r1cs.C[i].clone())
      }


      // Question: What is synthesize supposed to return? Is it the output of the circuit (I believe so)
      Ok(z_out)
    }
}


fn serialize_empty<S>(_value: &(), serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str("")
}

fn deserialize_empty<'de, D>(deserializer: D) -> Result<(), D::Error>
where
    D: Deserializer<'de>,
{
    let _s: String = Deserialize::deserialize(deserializer)?;
    Ok(())
}

// #[derive(Serialize, Deserialize)]
pub struct RelaxedR1CSSNARK<G: Group, EE: EvaluationEngineTrait<G, CE = G::CE> + MultiMillerLoop> {
  // #[serde(serialize_with = "serialize_empty", deserialize_with = "deserialize_empty")]
  pub circuit: R1CSBellpersonCircuit<G, G::Scalar>,
  // #[serde(serialize_with = "serialize_empty", deserialize_with = "deserialize_empty")]
  pub proof: Proof<EE>,
  inputs: Vec<G::Scalar>
}



impl<G: Group, EE: EvaluationEngineTrait<G, CE = G::CE> + MultiMillerLoop> RelaxedR1CSSNARKTrait<G>
  for RelaxedR1CSSNARK<G, EE>
{
  type ProverKey = ProverKey<EE>;
  type VerifierKey = VerifierKey<EE>;

   fn setup(
    ck: &CommitmentKey<G>,
    S: &R1CSShape<G>,
  ) -> Result<(Self::ProverKey, Self::VerifierKey), NovaError> {
    // Create parameters for our circuit
    
    let rng: &mut OsRng = &mut OsRng::new().unwrap();
    //TODO: this is expecting the R1CS representation, but we only know the R1CS shape
    let c: R1CSBellpersonCircuit<G> = R1CSBellpersonCircuit {
      r1cs: S,
      _marker: PhantomData
    };

    // TODO: need to define a struct that is the union of both EE and MultiMillerLoop
    let params: ProverKey<EE> = {
        // define c circuit
        generate_random_parameters(c, &mut *rng).unwrap()
    };


    // Prepare the verification key (for proof verification)
    let vk = prepare_verifying_key(&params.vk);


    Ok((params, vk))
  }

  fn prove(
    &self,
    ck: &CommitmentKey<G>,
    pk: &Self::ProverKey,
    U: &RelaxedR1CSInstance<G>,
    W: &RelaxedR1CSWitness<G>,
  ) -> Result<Self, NovaError> {
    let rng: &mut OsRng = &mut OsRng::new().unwrap();
    let proof = create_random_proof(self.circuit, &pk, rng);
    //TODO: get from witness instead of just passing 0s
    let mut public_inputs: Vec<G::Scalar> = vec![G::Scalar::ZERO; self.circuit.r1cs.num_io];

    // TODO: confirm inputs are prefix of the witness not suffic
    for i in 0..self.circuit.r1cs.num_inputs {
      public_inputs[i] = W.inputs[i];
    }

    Ok(RelaxedR1CSSNARK { circuit: self.circuit.clone(), proof: proof, inputs: &public_inputs })
  }

  fn verify(&self, vk: &Self::VerifierKey, U: &RelaxedR1CSInstance<G>) -> Result<(), NovaError> {
    //TODO
    verify_proof(vk, &self.proof, &self.public_inputs)
  }
}
