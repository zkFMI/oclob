//! Deterministic single-host regression, not a WAN or operator acceptance run.

use oclob_core::{PrivateMatchInput, Side};
use oclob_mpc::{MpcRunner, MPC_PARTIES};

#[test]
#[ignore = "requires the authorized remote hybrid MP-SPDZ engine"]
fn seven_native_parties_match_after_fresh_hybrid_connections() {
    let root = std::env::var_os("MP_SPDZ_ROOT").expect("MP_SPDZ_ROOT is required");
    let mut runner = MpcRunner::compile(root).expect("compile the canonical matching circuit");
    let input = PrivateMatchInput {
        resting_side: Side::Sell,
        resting_price: 100,
        resting_quantity: 5,
        arriving_side: Side::Buy,
        arriving_price: 101,
        arriving_quantity: 3,
    };
    for _ in 0..2 {
        let receipt = runner
            .execute(&input)
            .expect("execute seven real native parties");
        assert_eq!(receipt.parties, MPC_PARTIES);
        assert!(receipt.all_parties_agreed);
        assert!(receipt.result.matched);
        assert_eq!(receipt.result.trade_price, 100);
        assert_eq!(receipt.result.trade_quantity, 3);
        assert_eq!(receipt.result.resting_remaining, 2);
        assert_eq!(receipt.result.arriving_remaining, 0);
    }
}
