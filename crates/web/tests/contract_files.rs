//! The API contract the frontend is built from is the one the service serves.
//!
//! `cargo xtask api` writes both files and `npm run api` turns them into the
//! TypeScript types. A changed route, response type or module without a new
//! export fails here.

#[test]
fn the_committed_contract_is_current() {
    let hint = "run `cargo xtask api` and `npm run api` in frontend/";
    assert_eq!(
        garrison_web::openapi::text(),
        include_str!("../../../frontend/api/openapi.json"),
        "{hint}"
    );
    assert_eq!(
        garrison_core::modules::document(),
        include_str!("../../../frontend/api/modules.json"),
        "{hint}"
    );
}
