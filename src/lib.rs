use webpki::EndEntityCert;
use untrusted::Input;
use serde::Deserialize;
use base64;

#[derive(Debug, PartialEq)]
pub enum Error {
    ParseError,
    Signature,
    ChallengeDoesNotMatch,
    OriginDoesNotMatch,
    KeyHandleDoesNotMatch,
}

pub struct RegistrationResponse {
    pub user_public_key: Vec<u8>,
    pub key_handle: Vec<u8>,
    pub attestation_certificate: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Deserialize)]
struct ClientData {
    pub typ: String,
    pub challenge: String,
    pub origin: String,
}

impl RegistrationResponse {
    pub fn verify(&self, allowed_origins: Vec<String>, challenge: &str, client_data: &[u8]) -> Result<(), Error> {
        let client_data_json = serde_json::from_slice::<ClientData>(client_data).map_err(|_| Error::ParseError)?;

        if challenge != client_data_json.challenge {
            return Err(Error::ChallengeDoesNotMatch);
        }
        if !allowed_origins.contains(&client_data_json.origin) {
            return Err(Error::OriginDoesNotMatch);
        }

        let cert = EndEntityCert::from(Input::from(&self.attestation_certificate))
            .map_err(|_| Error::Signature)?;

        let msg_len = 1 + 32 + 32 + self.key_handle.len() + 65;
        let appid_hash = ring::digest::digest(&ring::digest::SHA256, client_data_json.origin.as_bytes());
        let client_data_hash = ring::digest::digest(&ring::digest::SHA256, client_data);

        let mut msg: Vec<u8> = Vec::with_capacity(msg_len);
        msg.push(0x00);
        msg.extend_from_slice(appid_hash.as_ref());
        msg.extend_from_slice(client_data_hash.as_ref());
        msg.extend_from_slice(&self.key_handle);
        msg.extend_from_slice(&self.user_public_key);

        cert.verify_signature(&webpki::ECDSA_P256_SHA256, Input::from(&msg), Input::from(&self.signature))
            .map_err(|_| Error::Signature)?;
        Ok(())
    }
}

#[test]
fn test_reg_resp_verify() {
    let resp = base64::decode_config("BQTq2F9Hc8LbdhiJTczl-yTabd1ZhbOvOvCPd5-mpn05p_Ir1Q6KEbJ_HMbZFr-S4b85k87hMXCI6B0XAONfHk0bQFT93wm0sLD8vF_fVItyB-WJGOETm_I5szGVAPsgtX_sQsRZSdJoGV3D-5ALYBHZwL1G1yVOK4N7i6il8ZlDxJswggJDMIIBLaADAgECAgQX8O1GMAsGCSqGSIb3DQEBCzAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowKTEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgNDAxNjY1MzUwMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQ-o66R9AJgeKoH6g3FI_WXmvdxUFy__TAreJbnl45E32rKCLQMy2nnKllZs1VfZX136Ff_pQLhUr2BB0C69RpaM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjIwEwYLKwYBBAGC5RwCAQEEBAMCBDAwCwYJKoZIhvcNAQELA4IBAQAvwnBqkckkOuQ35S9TJNDHSuAqdwQwRJbeF4KBDEG3ZNHdb1AcS5GL1FfzCGIiCAYVpMvaQZShExivRC204PlK7yj4zLCFds0eF7U6GH9h6JNxZnLXGcXBACk653kzkHBn7LvLIps4U--50K2w0gBQu5HM-B1ev_XXc0MDD4WWwlsY1SdL_w_OFQ-jo5uWCD_surmS-Iqcu5VlZntWzPdIpSeFznGGj7dpGzB676fQsQOizggEB0ikWmur8SqijlrNcMFAlvq0eNAzWNRDCu78b6ad1anwrAEKcanqQDrh4BbEPel9P_Gs6Ft94HYPxkfLFPFeaMJdwASMeXdV8SYVMEUCIQCLyfVmOeJEdK36OYW8JvpdEu7ae9SiaUf5EXnuzWUOBAIgG8M8Rt4B3onL6vdFGwYzzWKgeJGbriyLGxUbVH5KMnc", base64::URL_SAFE_NO_PAD).ok().unwrap();
    let client_data = base64::decode_config("eyJjaGFsbGVuZ2UiOiJkZmdiaG5qa2xtLGZjZ2hqbm0iLCJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdDoyMDIwIiwidHlwIjoibmF2aWdhdG9yLmlkLmZpbmlzaEVucm9sbG1lbnQifQ", base64::URL_SAFE_NO_PAD).ok().unwrap();
    let reg_resp = parse_registration_response(&resp).ok().unwrap();
    let res = reg_resp.verify(vec!["https://localhost:2020".to_string()], "vfegbegi", &client_data);
    assert!(res.is_err());
    assert_eq!(res, Err(Error::ChallengeDoesNotMatch));

    let res = reg_resp.verify(vec!["https://localghost:2020".to_string()], "dfgbhnjklm,fcghjnm", &client_data);
    assert!(res.is_err());
    assert_eq!(res, Err(Error::OriginDoesNotMatch));

    let res = reg_resp.verify(vec!["https://localhost:2020".to_string()], "dfgbhnjklm,fcghjnm", &client_data);
    assert!(res.is_ok());
}

pub fn parse_registration_response(data: &[u8]) -> Result<RegistrationResponse, Error> {
    if data[0] != 0x05 || data.len() < 67 {
        return Err(Error::ParseError);
    }

    let user_public_key = Vec::from(&data[1..66]);
    let handle_len = data[66] as usize;

    if data.len() < 67 + handle_len + 2 {
        return Err(Error::ParseError);
    }

    let key_handle = Vec::from(&data[67..(67 + handle_len)]);

    let mut pos = 67 + handle_len;
    // parse start of X.509 cert
    if data[pos] != 0x30 {
        return Err(Error::ParseError);
    }

    let (x509_len, x509_len_len) = parse_der_len(&data[pos + 1..])?;
    let attestation_len = 1 + x509_len_len + x509_len;

    if data.len() < pos + attestation_len {
        return Err(Error::ParseError);
    }

    let attestation_certificate = Vec::from(&data[pos..(pos + attestation_len)]);

    pos += attestation_len;

    let signature = Vec::from(&data[pos..]);

    Ok(RegistrationResponse {
        user_public_key,
        key_handle,
        attestation_certificate,
        signature,
    })
}

#[test]
fn test_parse_registration_response() {
    let reg_resp = "BQR0Dx3Zy4fY74xfS0wZI9FkzFttiNA_FOODMfYCCh2Xpx3126fko3zBGwytGzrDmQn3VzgEG-izO0kmd8kNps1qQIIaAarqUF4CARQYqaTFBII2eqciJpQvqs2hrpEnthHIS_ew-ufy25X4SUQaPRPrgRDmGoSYKHICgVJiOqp1ztMwggE0MIHboAMCAQICCmLqA072q-X-8BMwCgYIKoZIzj0EAwIwFTETMBEGA1UEAxMKVTJGIElzc3VlcjAaFwswMDAxMDEwMDAwWhcLMDAwMTAxMDAwMFowFTETMBEGA1UEAxMKVTJGIERldmljZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMwMTq_COwMSIZUJeXsEydPmpFSVMbYaRwcJ3sOM4UMTpg321lv_2SlORsTzFsofAocqp9e0QmMOwBA7xVO4pgWjFzAVMBMGCysGAQQBguUcAgEBBAQDAgQwMAoGCCqGSM49BAMCA0gAMEUCIQDBo6aOLxanIUYnBX9iu3KMngPnobpi0EZSTkVtLC8_cwIgC1945RGqGBKfbyNtkhMifZK05n7fU-gW37Bdnci5D94wRgIhALZYojvL3pUHuCsPggtHU7qXtVPYo0SaE4lSsJ-Zi3VOAiEAvwdx-wjfiqL-ugl5N5LeCxwGtvqrSjmRD1YDt9fe5Gw";
    let bin = base64::decode_config(reg_resp, base64::URL_SAFE_NO_PAD).unwrap();
    let res = parse_registration_response(&bin);

    assert!(res.is_ok());
    let res = res.ok().unwrap();

    assert_eq!(res.user_public_key, vec![0x04, 0x74, 0x0f, 0x1d, 0xd9, 0xcb, 0x87, 0xd8, 0xef, 0x8c, 0x5f, 0x4b, 0x4c, 0x19, 0x23, 0xd1, 0x64, 0xcc, 0x5b, 0x6d, 0x88, 0xd0, 0x3f, 0x14, 0xe3, 0x83, 0x31, 0xf6, 0x02, 0x0a, 0x1d, 0x97, 0xa7, 0x1d, 0xf5, 0xdb, 0xa7, 0xe4, 0xa3, 0x7c, 0xc1, 0x1b, 0x0c, 0xad, 0x1b, 0x3a, 0xc3, 0x99, 0x09, 0xf7, 0x57, 0x38, 0x04, 0x1b, 0xe8, 0xb3, 0x3b, 0x49, 0x26, 0x77, 0xc9, 0x0d, 0xa6, 0xcd, 0x6a]);
    assert_eq!(res.key_handle, vec![0x82, 0x1a, 0x01, 0xaa, 0xea, 0x50, 0x5e, 0x02, 0x01, 0x14, 0x18, 0xa9, 0xa4, 0xc5, 0x04, 0x82, 0x36, 0x7a, 0xa7, 0x22, 0x26, 0x94, 0x2f, 0xaa, 0xcd, 0xa1, 0xae, 0x91, 0x27, 0xb6, 0x11, 0xc8, 0x4b, 0xf7, 0xb0, 0xfa, 0xe7, 0xf2, 0xdb, 0x95, 0xf8, 0x49, 0x44, 0x1a, 0x3d, 0x13, 0xeb, 0x81, 0x10, 0xe6, 0x1a, 0x84, 0x98, 0x28, 0x72, 0x02, 0x81, 0x52, 0x62, 0x3a, 0xaa, 0x75, 0xce, 0xd3]);
    assert_eq!(res.attestation_certificate, vec![0x30, 0x82, 0x01, 0x34, 0x30, 0x81, 0xdb, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x0a, 0x62, 0xea, 0x03, 0x4e, 0xf6, 0xab, 0xe5, 0xfe, 0xf0, 0x13, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0a, 0x55, 0x32, 0x46, 0x20, 0x49, 0x73, 0x73, 0x75, 0x65, 0x72, 0x30, 0x1a, 0x17, 0x0b, 0x30, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, 0x0b, 0x30, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0a, 0x55, 0x32, 0x46, 0x20, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xcc, 0x0c, 0x4e, 0xaf, 0xc2, 0x3b, 0x03, 0x12, 0x21, 0x95, 0x09, 0x79, 0x7b, 0x04, 0xc9, 0xd3, 0xe6, 0xa4, 0x54, 0x95, 0x31, 0xb6, 0x1a, 0x47, 0x07, 0x09, 0xde, 0xc3, 0x8c, 0xe1, 0x43, 0x13, 0xa6, 0x0d, 0xf6, 0xd6, 0x5b, 0xff, 0xd9, 0x29, 0x4e, 0x46, 0xc4, 0xf3, 0x16, 0xca, 0x1f, 0x02, 0x87, 0x2a, 0xa7, 0xd7, 0xb4, 0x42, 0x63, 0x0e, 0xc0, 0x10, 0x3b, 0xc5, 0x53, 0xb8, 0xa6, 0x05, 0xa3, 0x17, 0x30, 0x15, 0x30, 0x13, 0x06, 0x0b, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xe5, 0x1c, 0x02, 0x01, 0x01, 0x04, 0x04, 0x03, 0x02, 0x04, 0x30, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 0xc1, 0xa3, 0xa6, 0x8e, 0x2f, 0x16, 0xa7, 0x21, 0x46, 0x27, 0x05, 0x7f, 0x62, 0xbb, 0x72, 0x8c, 0x9e, 0x03, 0xe7, 0xa1, 0xba, 0x62, 0xd0, 0x46, 0x52, 0x4e, 0x45, 0x6d, 0x2c, 0x2f, 0x3f, 0x73, 0x02, 0x20, 0x0b, 0x5f, 0x78, 0xe5, 0x11, 0xaa, 0x18, 0x12, 0x9f, 0x6f, 0x23, 0x6d, 0x92, 0x13, 0x22, 0x7d, 0x92, 0xb4, 0xe6, 0x7e, 0xdf, 0x53, 0xe8, 0x16, 0xdf, 0xb0, 0x5d, 0x9d, 0xc8, 0xb9, 0x0f, 0xde]);
    assert_eq!(res.signature, vec![0x30, 0x46, 0x02, 0x21, 0x00, 0xb6, 0x58, 0xa2, 0x3b, 0xcb, 0xde, 0x95, 0x07, 0xb8, 0x2b, 0x0f, 0x82, 0x0b, 0x47, 0x53, 0xba, 0x97, 0xb5, 0x53, 0xd8, 0xa3, 0x44, 0x9a, 0x13, 0x89, 0x52, 0xb0, 0x9f, 0x99, 0x8b, 0x75, 0x4e, 0x02, 0x21, 0x00, 0xbf, 0x07, 0x71, 0xfb, 0x08, 0xdf, 0x8a, 0xa2, 0xfe, 0xba, 0x09, 0x79, 0x37, 0x92, 0xde, 0x0b, 0x1c, 0x06, 0xb6, 0xfa, 0xab, 0x4a, 0x39, 0x91, 0x0f, 0x56, 0x03, 0xb7, 0xd7, 0xde, 0xe4, 0x6c]);
}

/// parse length field of DER and return (length, size of length field)
fn parse_der_len(data: &[u8]) -> Result<(usize, usize), Error> {
    let long_form = data[0] & 0x80 == 0x80;

    if long_form {
        let len_octets = (data[0] & 0x7f) as usize;
        // forbid more than 4 length octets, payloads should by much smaller and this way usizes on 32bit systems won't overflow
        if len_octets > 4 || data.len() < len_octets + 1 {
            return Err(Error::ParseError);
        }
        let mut len: usize = 0;
        for (i, octet) in data[1..(len_octets + 1)].iter().enumerate() {
            len += ((*octet as usize) << ((len_octets - (i + 1)) * 8)) as usize;
        }
        return Ok((len, len_octets + 1));
    }

    let len = data[0] as usize;
    Ok((len, 1))
}


#[test]
fn test_parse_der_len() {
    let res = parse_der_len(&[16]);
    assert!(res.is_ok());
    assert_eq!((16, 1), res.ok().unwrap());

    let res = parse_der_len(&[0x81, 0xff]);
    assert!(res.is_ok());
    assert_eq!((255, 2), res.ok().unwrap());

    let res = parse_der_len(&[0x82, 0x01, 0x34]);
    assert!(res.is_ok());
    assert_eq!((308, 3), res.ok().unwrap());

    let res = parse_der_len(&[0x85, 0x01, 0x34]);
    assert!(res.is_err());
}

pub struct SignatureData {
    user_presence: u8,
    counter: u32,
    signature: Vec<u8>,
}

impl SignatureData {
    pub fn verify(&self, app_id: &str, challenge: &str, client_data: &[u8], public_key: &[u8]) -> Result<(), Error> {
        let client_data_json = serde_json::from_slice::<ClientData>(client_data).map_err(|_| Error::ParseError)?;
        if client_data_json.challenge != challenge {
            return Err(Error::ChallengeDoesNotMatch);
        }

        let appid_hash = ring::digest::digest(&ring::digest::SHA256, app_id.as_bytes());
        let client_data_hash = ring::digest::digest(&ring::digest::SHA256, client_data);

        let counter = self.counter.to_be_bytes();
        let mut msg: Vec<u8> = Vec::with_capacity(69);
        msg.extend_from_slice(appid_hash.as_ref());
        msg.push(self.user_presence);
        msg.extend_from_slice(&counter);
        msg.extend_from_slice(client_data_hash.as_ref());

        ring::signature::verify(&ring::signature::ECDSA_P256_SHA256_ASN1,
                                Input::from(public_key),
                                Input::from(&msg),
                                Input::from(&self.signature))
            .map_err(|_| Error::Signature)?;

        Ok(())
    }
}

#[test]
fn test_signature_data_verify() {
    let pub_key = base64::decode_config("BHQPHdnLh9jvjF9LTBkj0WTMW22I0D8U44Mx9gIKHZenHfXbp-SjfMEbDK0bOsOZCfdXOAQb6LM7SSZ3yQ2mzWo", base64::URL_SAFE_NO_PAD).unwrap();
    let sig_data = base64::decode_config("AQAAAAcwRgIhAMIZkfT3V843TjB_0Lpe69qSD--mdRVFZTVNa01u01QBAiEAw9sKwHe7lf_hlN63UH7g8k0BUgzsloSkFPOk_34ujEk", base64::URL_SAFE_NO_PAD).unwrap();
    let sig = parse_signature_data(&sig_data).unwrap();
    let client_data = base64::decode_config("eyJjaGFsbGVuZ2UiOiJ2Y2V1enZiMzc4Yml1bml1Iiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6MjAyMCIsInR5cCI6Im5hdmlnYXRvci5pZC5nZXRBc3NlcnRpb24ifQ", base64::URL_SAFE_NO_PAD).unwrap();
    let res = sig.verify("https://localhost:2020", "vceuzvb378biuniu", &client_data, &pub_key);
    assert!(res.is_ok());
}

pub fn parse_signature_data(data: &[u8]) -> Result<SignatureData, Error> {
    if data.len() < 6 {
        return Err(Error::ParseError);
    }

    let user_presence = data[0];

    let counter = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);

    let signature = Vec::from(&data[5..]);

    Ok(SignatureData {
        user_presence,
        counter,
        signature,
    })
}

#[test]
fn test_parse_signature_data() {
    let sig_data = base64::decode_config("AQAAAAcwRgIhAMIZkfT3V843TjB_0Lpe69qSD--mdRVFZTVNa01u01QBAiEAw9sKwHe7lf_hlN63UH7g8k0BUgzsloSkFPOk_34ujEk", base64::URL_SAFE_NO_PAD).unwrap();
    let sig = parse_signature_data(&sig_data);
    assert!(sig.is_ok());
    let sig = sig.unwrap();
    assert_eq!(1, sig.user_presence);
    assert_eq!(7, sig.counter);
    assert_eq!(vec![0x30, 0x46, 0x02, 0x21, 0x00, 0xc2, 0x19, 0x91, 0xf4, 0xf7, 0x57, 0xce, 0x37, 0x4e, 0x30, 0x7f, 0xd0, 0xba, 0x5e, 0xeb, 0xda, 0x92, 0x0f, 0xef, 0xa6, 0x75, 0x15, 0x45, 0x65, 0x35, 0x4d, 0x6b, 0x4d, 0x6e, 0xd3, 0x54, 0x01, 0x02, 0x21, 0x00, 0xc3, 0xdb, 0x0a, 0xc0, 0x77, 0xbb, 0x95, 0xff, 0xe1, 0x94, 0xde, 0xb7, 0x50, 0x7e, 0xe0, 0xf2, 0x4d, 0x01, 0x52, 0x0c, 0xec, 0x96, 0x84, 0xa4, 0x14, 0xf3, 0xa4, 0xff, 0x7e, 0x2e, 0x8c, 0x49], sig.signature);
}
