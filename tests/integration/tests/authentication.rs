use dress_up::error::Error;
use dress_up::SuitManifest;
use std::cell::Cell;

fn signed_manifest() -> Vec<u8> {
    hex::decode(
        "d86ba2025873825824822f58206658ea560262696dd1f13b782239a064da\
         7c6c5cbaf52fded428a6fc83c7e5af584ad28443a10126a0f65840408d08\
         16f9b510749bf6a51b066951e08a4438f849eb092a1ac768eed9de696c1b\
         1dd35d82ef149e6a73a61976ad2cfe78444b8064293350a122f332cb49f0\
         da035871a50101020003585fa202818141000458568614a40150fa6b4a53\
         d5ad5fdfbe9de663e4d41ffe02501492af1425695e48bf429b2d51f2ab45\
         035824822f582000112233445566778899aabbccddeeff0123456789abcd\
         effedcba98765432100e1987d0010f020f074382030f0943821702",
    )
    .expect("fixture must be valid hexadecimal")
}

#[test]
fn authenticates_a_manifest_after_the_digest_and_signature_callback() {
    let input = signed_manifest();
    let callback_calls = Cell::new(0);

    let authenticated = SuitManifest::from_bytes(&input)
        .authenticate(|signature, digest| {
            callback_calls.set(callback_calls.get() + 1);
            assert!(!signature.is_empty());
            assert!(!digest.is_empty());
            Ok(true)
        })
        .expect("valid digest and accepted signature should authenticate");

    authenticated
        .envelope()
        .expect("authenticated manifests expose their envelope");
    assert_eq!(callback_calls.get(), 1);
}

#[test]
fn rejects_a_signature_when_the_callback_rejects_it() {
    let input = signed_manifest();

    let result = SuitManifest::from_bytes(&input).authenticate(|_, _| Ok(false));

    assert!(matches!(result, Err(Error::AuthenticationFailure)));
}
