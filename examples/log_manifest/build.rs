use std::fmt::Write;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=keys/demo-public-key-p256.pem");

    let pem = fs::read("keys/demo-public-key-p256.pem")
        .expect("failed to read demo P-256 public key");
    let public_key = openssl::ec::EcKey::public_key_from_pem(&pem)
        .expect("failed to parse demo P-256 public key");
    let group = public_key.group();
    let mut x = openssl::bn::BigNum::new().expect("failed to allocate P-256 x coordinate");
    let mut y = openssl::bn::BigNum::new().expect("failed to allocate P-256 y coordinate");
    let mut context = openssl::bn::BigNumContext::new()
        .expect("failed to allocate P-256 coordinate context");
    public_key
        .public_key()
        .affine_coordinates_gfp(group, &mut x, &mut y, &mut context)
        .expect("failed to read P-256 public key coordinates");

    let x = fixed_coordinate(x.to_vec());
    let y = fixed_coordinate(y.to_vec());
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);

    let mut generated = String::from("const PUBKEY_P256: &[u8] = &[\n");
    for (index, byte) in sec1.iter().enumerate() {
        if index % 8 == 0 {
            generated.push_str("    ");
        }
        write!(&mut generated, "0x{byte:02x}, ").expect("writing generated public key");
        if index % 8 == 7 {
            generated.push('\n');
        }
    }
    generated.push_str("];\n");

    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR is not set"));
    fs::write(out_dir.join("demo_public_key.rs"), generated)
        .expect("failed to write generated public key");
}

fn fixed_coordinate(coordinate: Vec<u8>) -> [u8; 32] {
    assert!(coordinate.len() <= 32, "P-256 coordinate is longer than 32 bytes");

    let mut fixed = [0u8; 32];
    fixed[32 - coordinate.len()..].copy_from_slice(&coordinate);
    fixed
}