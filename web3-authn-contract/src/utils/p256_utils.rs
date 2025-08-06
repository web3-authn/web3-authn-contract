use serde_cbor::Value as CborValue;
use p256::ecdsa::VerifyingKey;
use p256::PublicKey as P256PublicKey;

pub fn extract_p256_coordinates_from_cose(cose_key: &CborValue) -> Result<(Vec<u8>, Vec<u8>), String> {
    if let CborValue::Map(map) = cose_key {
        let x = map
            .get(&CborValue::Integer(-2))
            .and_then(|v| {
                if let CborValue::Bytes(b) = v {
                    Some(b.clone())
                } else {
                    None
                }
            })
            .ok_or("Missing x coordinate")?;

        let y = map
            .get(&CborValue::Integer(-3))
            .and_then(|v| {
                if let CborValue::Bytes(b) = v {
                    Some(b.clone())
                } else {
                    None
                }
            })
            .ok_or("Missing y coordinate")?;

        if x.len() != 32 || y.len() != 32 {
            return Err("Invalid coordinate length (expected 32 bytes each)".to_string());
        }

        Ok((x, y))
    } else {
        Err("COSE key must be a map".to_string())
    }
}

pub fn create_p256_public_key(x_bytes: &[u8], y_bytes: &[u8]) -> Result<VerifyingKey, String> {
    // Create uncompressed point: 0x04 || x || y
    let mut uncompressed = vec![0x04];
    uncompressed.extend_from_slice(x_bytes);
    uncompressed.extend_from_slice(y_bytes);

    // Create P-256 public key
    let public_key = P256PublicKey::from_sec1_bytes(&uncompressed)
        .map_err(|_| "Invalid P-256 public key")?;

    Ok(VerifyingKey::from(public_key))
}

// Helper function to extract uncompressed P-256 public key from COSE format
pub fn get_uncompressed_p256_pubkey(cose_public_key_bytes: &[u8]) -> Result<Vec<u8>, String> {

    let cose_public_key: CborValue = serde_cbor::from_slice(cose_public_key_bytes)
        .map_err(|_| "Failed to parse COSE public key")?;

    let (
        x_bytes,
        y_bytes
    ) = extract_p256_coordinates_from_cose(&cose_public_key)?;

    // Create uncompressed point format: 0x04 || x || y
    let mut uncompressed = Vec::with_capacity(65);
    uncompressed.push(0x04); // Uncompressed point indicator
    uncompressed.extend_from_slice(&x_bytes);
    uncompressed.extend_from_slice(&y_bytes);

    Ok(uncompressed)
}

/////////////////////////////////////
/// TESTS
/////////////////////////////////////

mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn _build_p256_cose_key(x_coord: &[u8; 32], y_coord: &[u8; 32]) -> Vec<u8> {
        let mut map = BTreeMap::new();
        map.insert(CborValue::Integer(1), CborValue::Integer(2)); // kty: EC2
        map.insert(CborValue::Integer(3), CborValue::Integer(-7)); // alg: ES256
        map.insert(CborValue::Integer(-1), CborValue::Integer(1)); // crv: P-256
        map.insert(CborValue::Integer(-2), CborValue::Bytes(x_coord.to_vec())); // x
        map.insert(CborValue::Integer(-3), CborValue::Bytes(y_coord.to_vec())); // y
        serde_cbor::to_vec(&CborValue::Map(map)).unwrap()
    }

    #[test]
    fn test_get_uncompressed_p256_pubkey() {
        // Use valid P-256 coordinates
        let x_coord = [
            0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74, 0xc6, 0x35,
            0x6d, 0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e,
            0x60, 0xf2, 0x9f, 0xb6,
        ];
        let y_coord = [
            0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28,
            0xbc, 0x64, 0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3, 0xc2, 0x94,
            0xd4, 0x46, 0x22, 0x99,
        ];
        let cose_public_key = _build_p256_cose_key(&x_coord, &y_coord);

        let result = get_uncompressed_p256_pubkey(&cose_public_key);

        assert!(result.is_ok());
        let uncompressed = result.unwrap();

        // Should be 65 bytes: 0x04 || x || y
        assert_eq!(uncompressed.len(), 65);
        assert_eq!(uncompressed[0], 0x04); // Uncompressed indicator
        assert_eq!(&uncompressed[1..33], &x_coord); // X coordinate
        assert_eq!(&uncompressed[33..65], &y_coord); // Y coordinate
    }
}