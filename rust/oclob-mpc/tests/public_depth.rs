use oclob_core::{MpcPriceLevel, Side, MAX_MATCH_SLOTS};
use oclob_mpc::{parse_result, public_output_digest};
fn wire() -> String {
    let mut s = String::new();
    for i in 0..MAX_MATCH_SLOTS {
        s.push_str(&format!(
            "OCLOB_SLOT_{i}_MATCHED=0\nOCLOB_SLOT_{i}_PRICE=0\nOCLOB_SLOT_{i}_QUANTITY=0\n"
        ));
    }
    s.push_str("OCLOB_ARRIVING_REMAINING=0\n");
    for i in 0..=MAX_MATCH_SLOTS {
        s.push_str(&format!(
            "OCLOB_LEVEL_{i}_SIDE=0\nOCLOB_LEVEL_{i}_PRICE=0\nOCLOB_LEVEL_{i}_QUANTITY=0\n"
        ));
    }
    s
}
#[test]
fn depth_parser_requires_complete_unique_canonical_fixed_shape() {
    let wire = wire();
    assert_eq!(parse_result(&wire).unwrap().public_levels, Some(Vec::new()));
    assert!(parse_result(&wire.replace("OCLOB_LEVEL_0_SIDE=0\n", "")).is_err());
    assert!(parse_result(&(wire.clone() + "OCLOB_LEVEL_0_SIDE=0\n")).is_err());
    assert!(
        parse_result(&wire.replace("OCLOB_LEVEL_0_PRICE=0", "OCLOB_LEVEL_0_PRICE=100")).is_err()
    );
    let row = wire
        .replace("OCLOB_LEVEL_0_SIDE=0", "OCLOB_LEVEL_0_SIDE=1")
        .replace("OCLOB_LEVEL_0_PRICE=0", "OCLOB_LEVEL_0_PRICE=100")
        .replace("OCLOB_LEVEL_0_QUANTITY=0", "OCLOB_LEVEL_0_QUANTITY=90");
    let result = parse_result(&row).unwrap();
    assert_eq!(
        result.public_levels,
        Some(vec![MpcPriceLevel {
            side: Side::Sell,
            price: 100,
            quantity: 90
        }])
    );
    assert!(parse_result(&row.replace("OCLOB_LEVEL_0_SIDE=1", "OCLOB_LEVEL_0_SIDE=2")).is_err());
    assert!(parse_result(&row.replace(
        "OCLOB_LEVEL_0_QUANTITY=90",
        "OCLOB_LEVEL_0_QUANTITY=999999999999"
    ))
    .is_err());
    assert!(parse_result(
        &row.replace("LEVEL_0_", "LEVEL_TMP_")
            .replace("LEVEL_1_", "LEVEL_0_")
            .replace("LEVEL_TMP_", "LEVEL_1_")
    )
    .is_err());
    let duplicate = row
        .replace("OCLOB_LEVEL_1_SIDE=0", "OCLOB_LEVEL_1_SIDE=1")
        .replace("OCLOB_LEVEL_1_PRICE=0", "OCLOB_LEVEL_1_PRICE=100")
        .replace("OCLOB_LEVEL_1_QUANTITY=0", "OCLOB_LEVEL_1_QUANTITY=1");
    assert!(parse_result(&duplicate).is_err());
}
#[test]
fn output_digest_binds_depth_and_distinguishes_missing_from_empty() {
    let mut b = parse_result(&wire()).unwrap();
    let empty = public_output_digest(&b);
    b.public_levels = None;
    assert_ne!(empty, public_output_digest(&b));
    b.public_levels = Some(vec![MpcPriceLevel {
        side: Side::Sell,
        price: 100,
        quantity: 90,
    }]);
    let before = public_output_digest(&b);
    b.public_levels.as_mut().unwrap()[0].quantity = 15;
    assert_ne!(before, public_output_digest(&b));
}
