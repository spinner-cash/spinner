use bn::*;
use ethereum_types::U256;

mod constants;
use constants::*;

thread_local! {
    static SNARK_SCALAR_FIELD: U256 = U256::from_dec_str(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    )
    .unwrap();
    static PRIME_Q: U256 = U256::from_dec_str(
        "21888242871839275222246405745257275088696311157297823662689037894645226208583",
    )
    .unwrap();
    static VERIFYING_KEY: VerifyingKey = VerifyingKey {
        alfa1: new_g1(new_fq_from(C1), new_fq_from(C2)),
        beta2: new_g2(new_fq2(new_fq_from(C3), new_fq_from(C4)), new_fq2(new_fq_from(C5),new_fq_from(C6))),
        gamma2: new_g2(new_fq2(new_fq_from(C7), new_fq_from(C8)), new_fq2(new_fq_from(C9), new_fq_from(C10))),
        delta2: new_g2(new_fq2(new_fq_from(C11), new_fq_from(C12)), new_fq2(new_fq_from(C13), new_fq_from(C14))),
        ic: [
            new_g1(new_fq_from(C15), new_fq_from(C16)),
            new_g1(new_fq_from(C17), new_fq_from(C18)),
            new_g1( new_fq_from(C19), new_fq_from(C20)),
            new_g1( new_fq_from(C21), new_fq_from(C22)),
            new_g1( new_fq_from(C23), new_fq_from(C24)),
            new_g1( new_fq_from(C25), new_fq_from(C26)),
            new_g1( new_fq_from(C27), new_fq_from(C28)),
            new_g1( new_fq_from(C29), new_fq_from(C30))
        ],
    };
}

#[derive(Clone)]
pub struct VerifyingKey {
    alfa1: G1,
    beta2: G2,
    gamma2: G2,
    delta2: G2,
    ic: [G1; 8],
}

#[derive(Clone)]
pub struct Proof {
    a: G1,
    b: G2,
    c: G1,
}

fn id<T: Clone + 'static>(k: &'static std::thread::LocalKey<T>) -> T {
    k.with(|x| x.clone())
}

pub fn field_size() -> U256 {
    id(&SNARK_SCALAR_FIELD)
}

fn new_fq(n: &U256) -> Fq {
    let mut bytes = [0; 32];
    n.to_big_endian(&mut bytes);
    Fq::from_slice(&bytes).unwrap()
}

fn new_fq_from(decimal: &str) -> Fq {
    new_fq(&U256::from_dec_str(decimal).unwrap())
}

/// Ethereum bn128 has y before x switched.
fn new_fq2(y: Fq, x: Fq) -> Fq2 {
    Fq2::new(x, y)
}

fn new_fr(n: &U256) -> Fr {
    let mut bytes = [0; 32];
    n.to_big_endian(&mut bytes);
    Fr::from_slice(&bytes).unwrap()
}

fn new_g1(x: Fq, y: Fq) -> G1 {
    if x.is_zero() && y.is_zero() {
        G1::zero()
    } else {
        AffineG1::new(x, y).unwrap().into()
    }
}

fn new_g2(a: Fq2, b: Fq2) -> G2 {
    if a.is_zero() && b.is_zero() {
        G2::zero()
    } else {
        AffineG2::new(a, b).unwrap().into()
    }
}

pub fn verify_proof(proof: &[U256; 8], input: &[U256; 7]) -> bool {
    // Make sure that each element in the proof is less than the prime q
    for p in proof {
        assert!(*p < id(&PRIME_Q), "verifier-proof-element-gte-prime-q",);
    }
    let proof = Proof {
        a: new_g1(new_fq(&proof[0]), new_fq(&proof[1])),
        b: new_g2(
            new_fq2(new_fq(&proof[2]), new_fq(&proof[3])),
            new_fq2(new_fq(&proof[4]), new_fq(&proof[5])),
        ),
        c: new_g1(new_fq(&proof[6]), new_fq(&proof[7])),
    };
    let vk: VerifyingKey = id(&VERIFYING_KEY);
    let mut vk_x: G1 = G1::zero();

    let snark_scalar_field = id(&SNARK_SCALAR_FIELD);
    for (i, inp) in input.iter().enumerate() {
        if input[i] >= snark_scalar_field {
            panic!("Expect input[{}] less than FIELD_SIZE", i)
        };
        vk_x = vk_x + vk.ic[i + 1] * new_fr(inp);
    }
    vk_x = vk_x + vk.ic[0];

    pairing_batch(&[
        (-proof.a, proof.b),
        (vk.alfa1, vk.beta2),
        (vk_x, vk.gamma2),
        (proof.c, vk.delta2),
    ]) == Gt::one()
}

#[cfg(test)]
mod test_proof_constants;

#[cfg(test)]
mod test_input_constants;

#[test]
fn test_2() {
    use test_input_constants::*;
    use test_proof_constants::*;
    let from_dec = |s| U256::from_dec_str(s).unwrap();
    let proof = [
        from_dec(P0),
        from_dec(P1),
        from_dec(P3),
        from_dec(P2),
        from_dec(P5),
        from_dec(P4),
        from_dec(P6),
        from_dec(P7),
    ];
    let args = [
        from_dec(I0),
        from_dec(I1),
        from_dec(I2),
        from_dec(I3),
        from_dec(I4),
        from_dec(I5),
        from_dec(I6),
    ];
    assert!(verify_proof(&proof, &args))
}
