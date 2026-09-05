use oclob_settlement::native::native_batch_binding;
use qomm_defmi::application_reservation::ApplicationReserveScope;

fn scope() -> ApplicationReserveScope {
    ApplicationReserveScope {
        application_binding: [1; 32],
        venue_id: [2; 32],
        defmi_id: [3; 32],
        committee_key_digest: [4; 32],
        committee_epoch: 1,
        amount_bits: 32,
    }
}

#[test]
fn sparse_matched_slots_bind_the_full_ordered_execution_and_parent() {
    let scope = scope();
    let binding = |slots: &[usize], slot| {
        native_batch_binding(&scope, [5; 32], [6; 32], [7; 32], slots, slot)
    };
    let first = binding(&[0, 2, 7], 0).unwrap().unwrap();
    let last = binding(&[0, 2, 7], 7).unwrap().unwrap();
    assert_eq!(first.group, last.group);
    assert_eq!((first.index, last.index, first.count), (0, 2, 3));
    assert_ne!(first.group, binding(&[0, 7], 0).unwrap().unwrap().group);
    for (parent, round, output) in [
        ([8; 32], [6; 32], [7; 32]),
        ([5; 32], [8; 32], [7; 32]),
        ([5; 32], [6; 32], [8; 32]),
    ] {
        assert_ne!(
            first.group,
            native_batch_binding(&scope, parent, round, output, &[0, 2, 7], 0)
                .unwrap()
                .unwrap()
                .group
        );
    }
    assert_eq!(binding(&[0], 0).unwrap(), None);
}

#[test]
fn membership_refuses_unmatched_duplicate_reordered_or_out_of_range_slots() {
    for slots in [&[][..], &[0, 0], &[2, 0], &[0, 8]] {
        assert!(native_batch_binding(&scope(), [5; 32], [6; 32], [7; 32], slots, 0).is_err());
    }
    assert!(native_batch_binding(&scope(), [5; 32], [6; 32], [7; 32], &[0, 2], 1).is_err());
    let all = (0..8).collect::<Vec<_>>();
    assert_eq!(
        native_batch_binding(&scope(), [5; 32], [6; 32], [7; 32], &all, 7)
            .unwrap()
            .unwrap()
            .count,
        8
    );
}
