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

/// A type that represents the prover's key
// #[derive(Serialize, Deserialize)]
// #[serde(bound = "")]
pub struct ProverKey<E: MultiMillerLoop> {
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
pub struct VerifierKey<E: Engine + MultiMillerLoop> {
  vk: VerifyingKey<E>,
}


// struct to construct a bellpearson circuit from a Nova R1CS representation
#[derive(Clone)]
pub struct R1CSBellpersonCircuit<Fr: PrimeField> {
  //TODO: implement circuit which satisfier circuit trait in bellpearson given R1CS shape?  
  pub r1cs: R1CSShape<Fr>,
}

impl<'a, Fr: PrimeField> R1CSBellpersonCircuit<Fr> {
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




impl<G: Group, EE: EvaluationEngineTrait<G, CE = G::CE>> RelaxedR1CSSNARKTrait<G>
  for RelaxedR1CSSNARK<G, EE>
{
  type ProverKey = ProverKey<G, EE>;
  type VerifierKey = VerifierKey<G, EE>;

   fn setup(
    ck: &CommitmentKey<G>,
    S: &R1CSShape<G>,
  ) -> Result<(Self::ProverKey, Self::VerifierKey), NovaError> {
    // Create parameters for our circuit
    
    //TODO: this is expecting the R1CS representation, but we only know the R1CS shape
    let c: R1CSBellpersonCircuit<G> = R1CSBellpersonCircuit {
      r1cs: S,
    };

    // TODO: need to define a struct that is the union of both EE and MultiMillerLoop
    let params:  = {
        // define c circuit
        generate_random_parameters(c, &mut *rng).unwrap()
    };

    let pk= ProverKey {
      h: params.h,
      l: params.l,
      a: params.a,
      b_g1: params.b_g1,
      b_g2: params.b_g2
    };

    // Prepare the verification key (for proof verification)
    let vk = prepare_verifying_key(&params.vk);

    Ok((pk, vk))
  }

  fn prove(
    ck: &CommitmentKey<G>,
    pk: &Self::ProverKey,
    U: &RelaxedR1CSInstance<G>,
    W: &RelaxedR1CSWitness<G>,
  ) -> Result<Self, NovaError> {
    //TODO
  }

  fn verify(&self, vk: &Self::VerifierKey, U: &RelaxedR1CSInstance<G>) -> Result<(), NovaError> {
    //TODO
  }
}
