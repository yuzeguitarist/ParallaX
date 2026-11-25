//! Small byte/scalar generator shared only by protocol property tests. Failure
//! shrinking is bounded and best-effort, not an exhaustive minimality search.

use rand::{rngs::StdRng, Rng, SeedableRng};

#[derive(Clone, Debug)]
pub struct Case {
    pub a: u64,
    pub b: u64,
    pub c: u64,
    pub bytes: Vec<u8>,
}

impl Case {
    pub fn array<const N: usize>(&self, offset: usize) -> [u8; N] {
        std::array::from_fn(|i| {
            if self.bytes.is_empty() {
                0
            } else {
                self.bytes[(offset + i) % self.bytes.len()]
            }
        })
    }

    pub fn payload(&self, cap: usize) -> &[u8] {
        &self.bytes[..self.bytes.len().min(cap)]
    }
}

macro_rules! prop_assert {
    ($condition:expr) => {
        if !$condition {
            return Err(format!(
                "{}:{}: {}",
                file!(),
                line!(),
                stringify!($condition)
            ));
        }
    };
}

macro_rules! prop_assert_eq {
    ($left:expr, $right:expr) => {
        match (&$left, &$right) {
            (left, right) if left != right => {
                return Err(format!("{}:{}: {left:?} != {right:?}", file!(), line!()));
            }
            _ => {}
        }
    };
}

fn setting(name: &str, default: u64) -> u64 {
    match std::env::var(name) {
        Ok(value) => if let Some(hex) = value.strip_prefix("0x") {
            u64::from_str_radix(hex, 16)
        } else {
            value.parse()
        }
        .unwrap_or_else(|_| panic!("{name} must be an unsigned integer")),
        Err(std::env::VarError::NotPresent) => default,
        Err(error) => panic!("invalid {name}: {error}"),
    }
}

pub fn check(name: &str, property: impl Fn(&Case) -> Result<(), String>) {
    let seed = setting("PARALLAX_PROP_SEED", 0x504c_585f_5052_4f50);
    let cases = setting("PARALLAX_PROP_CASES", 256);
    assert!(
        (1..=10_000).contains(&cases),
        "PARALLAX_PROP_CASES must be in 1..=10000"
    );
    let salt = name.bytes().fold(0u64, |hash, b| {
        hash.wrapping_mul(131).wrapping_add(u64::from(b))
    });
    let mut rng = StdRng::seed_from_u64(seed ^ salt);
    let boundaries = [
        0,
        1,
        63,
        64,
        255,
        256,
        16383,
        16384,
        u32::MAX as u64,
        1 << 60,
        (1 << 62) - 1,
        u64::MAX,
    ];
    let lengths = [0, 1, 2, 15, 16, 31, 32, 255, 256, 1024, 4096];
    let run = |case: &Case| evaluate(&property, case);
    for index in 0..cases as usize {
        let scalar = |rng: &mut StdRng, shift: usize| {
            if index % 2 == 0 {
                boundaries[(index / 2 + shift) % boundaries.len()]
            } else {
                rng.gen()
            }
        };
        let len = if index % 2 == 0 {
            lengths[(index / 2) % lengths.len()]
        } else {
            rng.gen_range(0..=4096)
        };
        let case = Case {
            a: scalar(&mut rng, 0),
            b: scalar(&mut rng, 4),
            c: scalar(&mut rng, 8),
            bytes: (0..len).map(|_| rng.gen()).collect(),
        };
        if let Err(error) = run(&case) {
            let smallest = shrink(case, |case| run(case).is_err());
            panic!("{name}: {error}; replay with PARALLAX_PROP_SEED={seed:#x} PARALLAX_PROP_CASES={} (case {index}); shrunk={smallest:?}", index + 1);
        }
    }
}

fn evaluate(property: &impl Fn(&Case) -> Result<(), String>, case: &Case) -> Result<(), String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| property(case))).unwrap_or_else(
        |payload| {
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("non-string panic");
            Err(format!("property panicked: {message}"))
        },
    )
}

fn shrink(mut smallest: Case, fails: impl Fn(&Case) -> bool) -> Case {
    // Every accepted reduction still fails the property. This does not claim a
    // unique or globally minimal counterexample; at most 128 candidates run.
    let mut attempts = 0;
    while !smallest.bytes.is_empty() && attempts < 128 {
        attempts += 1;
        let mut candidate = smallest.clone();
        candidate.bytes.truncate(candidate.bytes.len() / 2);
        if !fails(&candidate) {
            break;
        }
        smallest = candidate;
    }
    for field in 0..3 {
        let value = match field {
            0 => smallest.a,
            1 => smallest.b,
            _ => smallest.c,
        };
        for value in std::iter::once(0).chain(std::iter::successors(Some(value / 2), |value| {
            (*value > 0).then_some(*value / 2)
        })) {
            if attempts >= 128 {
                break;
            }
            attempts += 1;
            let mut candidate = smallest.clone();
            match field {
                0 => candidate.a = value,
                1 => candidate.b = value,
                _ => candidate.c = value,
            }
            if fails(&candidate) {
                smallest = candidate;
                if value == 0 {
                    break;
                }
            }
        }
    }
    for at in 0..smallest.bytes.len() {
        if attempts >= 128 {
            break;
        }
        attempts += 1;
        let mut candidate = smallest.clone();
        candidate.bytes[at] = 0;
        if fails(&candidate) {
            smallest = candidate;
        }
    }
    smallest
}

#[test]
fn false_property_is_detected_and_shrinking_preserves_failure() {
    let case = Case {
        a: 1024,
        b: 9,
        c: 7,
        bytes: vec![1; 32],
    };
    let false_property = |case: &Case| {
        prop_assert!(case.a == 0 || case.bytes.first() != Some(&1));
        Ok(())
    };
    assert!(evaluate(&false_property, &case).is_err());
    let shrunk = shrink(case, |case| evaluate(&false_property, case).is_err());
    assert!(evaluate(&false_property, &shrunk).is_err());
    assert_eq!(shrunk.a, 1);
    assert_eq!(shrunk.bytes, vec![1]);
    assert!(evaluate(&|_| panic!("panic control"), &shrunk)
        .unwrap_err()
        .contains("panic control"));
}
