#![cfg(test)]
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env};
use crate::{CrowdfundContract, CrowdfundContractClient};

#[test]
fn test_admin_upgrade_validation() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let token = Address::generate(&env);

    let contract_id = env.register(CrowdfundContract, ());
    let client = CrowdfundContractClient::new(&env, &contract_id);

    client.initialize(
        &admin,
        &creator,
        &token,
        &1000i128,
        &10000u64,
        &10i128,
        &None,
        &None,
        &None,
        &None, // metadata_uri
    );

    let new_wasm_hash = BytesN::from_array(&env, &[1u8; 32]);

    // SUCCESS: Upgrade by the correct admin
    client.upgrade(&new_wasm_hash);

    // Verify event exists
    let events = env.events().all();
    assert!(events.len() > 0);
    let last_event = events.last().unwrap();
    assert_eq!(last_event.0, contract_id);
}

#[test]
#[should_panic]
fn test_unauthorized_upgrade_fail() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let token = Address::generate(&env);

    let contract_id = env.register(CrowdfundContract, ());
    let client = CrowdfundContractClient::new(&env, &contract_id);

    // Initialize with mock_all_auths so initialize() succeeds
    env.mock_all_auths();
    client.initialize(
        &admin,
        &creator,
        &token,
        &1000i128,
        &10000u64,
        &10i128,
        &None,
        &None,
        &None,
        &None, // metadata_uri
    );

    // Clear auths — upgrade() must fail without admin auth
    env.set_auths(&[]);
    let new_wasm_hash = BytesN::from_array(&env, &[1u8; 32]);
    client.upgrade(&new_wasm_hash);
}
