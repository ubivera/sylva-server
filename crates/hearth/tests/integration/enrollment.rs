//! Identity enrollment repos (Hub Phase 2a) — `user_keys`, `machines`,
//! `devices`. Exercises the repos directly against the bundled-postgres test
//! pool (the `Account` gRPC service that drives them lands next).

use identity::{
    DeviceRepository, InstanceRole, MachineRepository, NewDevice, UserKeyMaterial,
    UserKeyRepository, UserLifecycle, UserRepository,
};

use super::common::TestApp;

#[tokio::test]
async fn enrollment_repos_round_trip() {
    let app = TestApp::new().await;

    // Bootstrap-style: create the owner + key bundle + machine + device in one tx.
    let mut tx = app.pool.begin().await.unwrap();
    let user = UserRepository::create(
        &mut tx,
        "owner@test.local",
        "Olivia",
        InstanceRole::Owner,
        UserLifecycle::Active,
    )
    .await
    .unwrap();

    let km = UserKeyMaterial {
        x25519_public: vec![1u8; 32],
        ed25519_public: vec![2u8; 32],
        x25519_private_wrapped: vec![3u8; 48],
        ed25519_private_wrapped: vec![4u8; 48],
        master_key_wrapped: vec![5u8; 48],
        kdf_salt: vec![6u8; 16],
        kdf_params: r#"{"m":65536,"t":3,"p":4}"#.to_string(),
    };
    UserKeyRepository::create(&mut tx, user.id, &km).await.unwrap();

    let machine = MachineRepository::create(&mut tx, "Family-PC", "windows", Some(user.id))
        .await
        .unwrap();
    let device = DeviceRepository::register(
        &mut tx,
        &NewDevice {
            user_id: user.id,
            machine_id: Some(machine.id),
            device_label: "Olivia's PC".to_string(),
            platform: "windows".to_string(),
            device_public_key: vec![7u8; 32],
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    // Key material round-trips (the server stored exactly the ciphertext given).
    let keys = UserKeyRepository::new(app.pool.clone())
        .get(user.id)
        .await
        .unwrap()
        .expect("key bundle persisted");
    assert_eq!(keys.master_key_wrapped, vec![5u8; 48]);
    assert_eq!(keys.kdf_params, r#"{"m":65536,"t":3,"p":4}"#);

    let devices = DeviceRepository::new(app.pool.clone());

    // The device lists, linked to its machine.
    let list = devices.list_for_user(user.id).await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, device.id);
    assert_eq!(list[0].machine_id, Some(machine.id));
    assert_eq!(list[0].device_public_key, vec![7u8; 32]);

    // Owner-scoped fetch + revoke.
    assert!(devices.get_owned(device.id, user.id).await.unwrap().is_some());
    assert!(devices.revoke_owned(device.id, user.id).await.unwrap());
    // A revoked device drops out of the active list.
    assert!(devices.list_for_user(user.id).await.unwrap().is_empty());
    // Revoking again is a no-op.
    assert!(!devices.revoke_owned(device.id, user.id).await.unwrap());
}
