use std::{
    fmt::Write as _,
    net::{Shutdown, SocketAddr, TcpListener},
    sync::{mpsc, Arc},
    thread,
    time::Duration,
};

use parallax::{
    crypto::session::X25519KeyPair,
    tls::{client_hello_builder::BrowserProfile, stateful::StatefulRustlsCamouflageBackend},
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};

const TLS12: u16 = 0x0303;
const TLS13: u16 = 0x0304;
const EXT_SNI: u16 = 0x0000;
const EXT_EC_POINT_FORMATS: u16 = 0x000b;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_KEY_SHARE: u16 = 0x0033;
const GROUP_X25519: u16 = 0x001d;
const GROUP_X25519_MLKEM768: u16 = 0x11ec;

const EXPECTED_CHROME_GUI_JA3: &str = "f15fe5d1f9edead72e873c77bfe9c606";
const EXPECTED_CHROME_HEADLESS_JA3: &str = "f5b2bb9f2cc8fce256f5443aca5dd654";
const EXPECTED_CHROME_JA4: &str = "t13d1516h2_8daaf6152771_d8a2da3f94cd";
const EXPECTED_PARALLAX_JA4: &str = "t13d1010h2_61a7ad8aa9b6_648ed004696a";

const WHITELISTED_FIELD_DIFFS: &[&str] = &["cipher_suites", "extensions", "grease"];

const CHROME_GUI_HEX: &str = "16030106d2010006ce0303191b75ac9e43d69c4deb59abf279397cf71f561d3fad472a6f4fa73dba4f511a206d0e6c7c2d7122146b6676359b2ecd39743ffe9b0337702ccb54d818123e0cb50020aaaa130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010006651a1a0000002d00020101000d00120010040308040401050308050501080606010000000e000c0000096c6f63616c686f7374000b0002010044cd00050003026832fe0d00da0000010001cf002095873fe655d62cd4db3014a43a40ab981b969c1eb6fc2ad7399cd39473a9775a00b07204f721ecf7729cfb161fbd05014b1e9dd5eed5841dd57717d06c735d7ee35c65afb8047ce64863729d94e51263c918b48575012f2e87a9ba981a25a664ea9045aac3bc49d394fb4952750c40d47462764b48cdab5281ae8043f5a552602edf5b3807051fe7e12ce8562cea7a9d9982b97b3d798636087f4aaef5e9e3329ebcf049df6fb4b658577fb9f01cf16004d72a3f9b776eda2cea59cdd09184e1c92c4b1478155a5b2d29a21b9c10468af6a3001b00030200020005000501000000000010000e000c02683208687474702f312e31003304ef04ed3a3a00010011ec04c00d443258d14739738de9c13df0eab555b5c62f51b46d47187af547fbe981af669bf0464f7b895da7c7ca8c74533228b7b3c83f40e9b92c92bea0989691a5389dccaa09845eeb96c4354924d14286ed56c94748aac546520e594ccc13a7ae8c1823cb130858b63568265e8b68fc326614c1191019b90d13507f46856d926e24e70274453bd8364a9906a16618bd09a17d73d4443695b6c7f4478aa656d6d81be7ca922a66a15f63647bd0b7bbc1a2924103b25c0421c0cda4d6aad8173201b865a33a40edb036618ccfcb4a2bc1a949a9b8399f5b0c321b85e30cb0471c1d89cc08f3412f80c491f7590423698c2673782e7b2ff917b1d194a7e935a9481b82e5dca8630ba341c65e93fa19ec692a07c01b5741a1d659b8da22472d82661b093d4507ca37631e85f4998787b14f6236aa59ad1f76210454ac4cc35f2f58cc23073f79e57950741cea1c21c5f39db9353b0d50c5aa9177f76968e89c9c5ad3796ae7ba69b545b3e222bef7bce2c28d1f1a73d3bb9ab528582fd628c58c31c4c84bee8a0d2ef493c92c4d772b02e39025e387663cc1b7035a2b0112c8cb6c90af0c2d1a5a9f6bc35b16c36d1fc3a1cc6c7f1e204edf1bb1c419042a0c2a14f0b8e3c8563eac8e965913fd89ae179b1f0ed62cc22082e010cc784149c6629029371bc8130bb056347fc819ff035eb6c21e26b526d9072c73ab62459bbb1ef81f98b55fabea23fbdaaabaa22c5eb3b6518412c80c7c895c612dd8c9469245039b23f67b2520480d36f1c0cc115a8f721afe13be41ba09b573c89a64ba2c60825bb86bf50b4d6b601074b3c3c4ab020f6bc5c7012c86b1786032a8deda9a8eca225bf4548baa7a6dfa1dd73203eb4570a527641fe056dab0663565856bf6cafd76ab057454914b0fac7751f5b5c6f2f9be43128f21da13ab6c4b53a24ba25900558b471fc73ed9d286b70cafd2e66063b2bc1f892080045bcd4385f4fb24eb7359e3847433dc7d686433a4954a3757b80fe96ad4bc445ac709df71406c132302099c81d61ebb429267a4910fd96a53b9556d8087f32b1a963a8c8f6957d1f39362974fd33101a3ca0c7f076dd9ecccad4b8412e364c9297667c219dae208a870c75253929325301c500d022b88adda945a25983e31921e587652369578062fb72bc430323a9751b6da968934db1f64419d70d1b704666fe5fb2820b0946c667feacaa247d5ac5490430182774b30c96e6a5f46a132fa337c8631afac829eb2970ce7044dc6d2bfc5233ff831aa0d9345ff20ae99dc32e370c0a7b566d9f6c49517317cc877b6d496c3c6701d11658867456b36512286a13415a8f72125988230e2a939d2436a2f94783462327907286c0973196c6dfbc4c82d3507c507a5f73ab0d9378a34b8bdac459a09b0cb052020e0589d9b902af492791ce66188b06a89bb4e7f3b61fe8b307df260272992dd608391316fb6f27016162be7fb575be27a98f256a72471dc5836c884a5d32324ac92217b63775d5684e9453a0087765ce74268a4108bb0c7b2c782a9f963fd353b97a153f4608adc49233cd7b0e6e34d66e87cae8aaa2c813dedbc9f26172a147211f2982cd711cf27068f05804a02d8512e685a36e83f80e973dcce846cbac780da1ed05d6d9eff9db7b1a709588511862e7c69ffc9b948a1fc2902fa227b0d86ad42904d8b0b6c3ffed160ca489ffde5eea214001d00206fbfab789c39f8ba2eef965aa40fce5fa6055f1dde4373cc82e53a20eb4a1728000a000c000a3a3a11ec001d00170018002300000017000000120000002b000706aaaa03040303ff010001005a5a000100";

const CHROME_HEADLESS_HEX: &str = "16030107120100070e0303575a545edf1e2e7a7ca086980b8bdcd9926655e8c826a3e167555483d25aa02d2002a6a7b2c080b19e1f4bea9722d44baf355df1b7393d50651faf82bf7e5d3c050020eaea130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010006a50a0a000000230000000d0012001004030804040105030805050108060601002d00020101000b00020100003304ef04ed9a9a00010011ec04c00a32ae1c83201c8999afa50e9ec37c471493ef253b6d0974f95a736b98054a847c67a625f0f9cb7d52ca4b607b79183b6fd91ac444745f6bb3825263b6049eecd09154919857fbcb0b7736a6d02a6ad337036391d1f06d90b85db0c81d26e12efe8737de52860b76c771093b4ffb5893449d52b0ce5b747e754a1f6afaa593364e80442018db3f6d754eb9381209c6bf9c189738995061f51ac65b140eb501d49828f70b4c3ac54dbf26aed0300f2e9abbe82397c623b0d7f530b9f080ec87576105b4e714a63b7bbf380336c4178bef1014af0aa8497ac97f1c93b069a259284e369c8cf0a13978b0521f83632bb239f0a0730143888bc4ac4ee9a3783432a0391ced099d9049cf50783660163c94f93ba7769db9701555956905e24bca04baa0ec60cf99a00fa5b4b3d26d3319768daa1adda570aba974608607777837c5683384a94476a21ead82031940063ae4a54d7171cd959eb3d5128f05511d897bbb9c4b9f49294013bfa76625c623b77375503e4b59114aba65f98d28929b18312f5b60aa5adb6eb1768992a4cacc7607a1b6aebe30be97e3a4bcfc2c674488656520cfaca06a6730fb97a3d295235010292b298ff3e875f04abb58371087260b044c532f5a58b07466a41331d7d66ad683caae66129f83712cfc0fc9366cd8e62e540303996b8b35a02eb97bcd7d649a9a49a0ba8b2745e70ed3085b6f3a21d6d9c86191bc355cb0eaf240cdbc9f221231c5ab4a54935a48a747a6149c071b05e2912713232eb73bae9bf49c484b6e05c722b6846700095e722354096402ca322e6989c8709a07b2dbc345154808334ac52c2eecac127cbc53919c6655ea8d7b022a85d6be84b7aff47117d60c3829f8403190881a6a59fff1c08dfa36f423c508e3785c3b8b8a465f2abccc00953a0207a1cc24c14e2557d4405263f96b877b127b930f37ab2b54527d4568b999759a79406011b16e5bfb35ab563d1d984b51d9a8dc5ca500913b61358ab4da3dad5616f30ca550d52084344d331bc2491210fc2977b89c22dbe3a43e83157d17a454e774ebe54354b84658d8c1e309996a9b93df0451910ac63b838eabe974901a63f6498300d2801fd2b17950abd84a2d4b19a317354f8ae7cafca982eef31b67451795322895373306d532e5e1328cc85e6d3627cf6a846bac0e8d2118856407f35793bf4b3084888598ba32d0717897a4c6b9c7a221516e2d036f157057916a6978f04f5aaa6fc2357865d1cf2fd71836750ea496c4896c9841b107328b79a9fc49298caa3ab20eeea509578781bca918f58b7748f35dfaf0a22132b57af0396e534dcb28305b74c5193a7f23f0224f2bab1dba087cc456003163f4e69dffc22fdbd78fa7444208dbc40d7b0485e0a344960206c774efdbc2b6730abe23cafc3b110d421138d001a9573591d58615e513ea663b55a433afe9b063737e697822bb85ab2e28cef84723bf56bcbb0c922a9c03913bbac8e426e7278fd5a6335a93a98a88b93da1bc6263537f94028579833916619c43bd66174578d287fdb83536331c76da105a938390a5599bd9bbba478550e2c6505ab9504a85635b6a5cab1b1e3127ddf98b4ad88312f084aed60013416ad3a2396c7f23e8f493f21516b1089b8035d1d9de1733dccc57d17fc7bd8528e33c77eedcf67808beee81206c139172b7e08bd98e318261b2f5c6ebcf97904010001d0020b04e8e78446d386f472ed9d8a10ca062d845b75e6406ddc5e8f26e401c013d50002b0007060a0a03040303001700000010000e000c02683208687474702f312e3144cd00050003026832000500050100000000001b0003020002fe0d011a0000010001340020d5e16fb36370e6c6c5ca0f297fbaf16eeb11499993d9a72813525e28ff07761d00f09e93ed78c09e755aeba1c60a1a9cdac56d2afbfa7f18ee0999f65e0debd38b7e50053126f3c2497ec4427aedbe2e1acd8a0e373aacabe231537fae8da61577fc8557759f263b7b7d55202b8d286efcce8c55de6cba45eeebd6679bef1513dcd421d835286de0563f17199b2bc5fb18e81839b4cf902c3f7f043af66a197bc1e15bf91b51f9ce09127d28a821168bf5cb0e55692c5b2e3986205201f13c21c56c48734da285c467c8b7f484e722bcacf45b86b2bd114787bdddd207714b7e90f41e0674471762a97481066d04cbf80824292dc8b3ec63af7d4f19a6dac20a5dbdc9106d6304440678af74ac3c598f03c50000000e000c0000096c6f63616c686f7374000a000c000a9a9a11ec001d00170018ff0100010000120000dada000100";

#[test]
#[ignore = "chrome_parity: helper vector test; run when refreshing local Chrome ClientHello samples"]
fn chrome_parity_ja3_known_vectors() {
    let input = b"769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0";
    assert_eq!(md5_hex(input), "ada70206e40642a3e4461f35503241d5");

    let input = b"769,4-5-10-9-100-98-3-6-19-18-99,,,";
    assert_eq!(md5_hex(input), "de350869b8c85de67a350c8d186f11e6");
}

#[test]
#[ignore = "chrome_parity: helper vector test; run when refreshing local Chrome ClientHello samples"]
fn chrome_parity_ja4_known_vector() {
    let fields = ClientHelloFields {
        legacy_version: TLS12,
        cipher_suites: vec![
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ],
        extensions: vec![
            0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012,
            0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
        ],
        supported_versions: vec![TLS13],
        signature_algorithms: vec![
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ],
        alpn: vec!["h2".to_owned()],
        ..ClientHelloFields::default()
    };

    assert_eq!(
        fingerprints(&fields).ja4,
        "t13d1516h2_8daaf6152771_e5627efa2ab1"
    );
}

#[tokio::test]
#[ignore = "chrome_parity: needs local Chrome samples to be refreshed intentionally"]
async fn chrome_parity_field_diff_baseline() {
    let gui = parse_client_hello(&hex_to_bytes(CHROME_GUI_HEX)).unwrap();
    let headless = parse_client_hello(&hex_to_bytes(CHROME_HEADLESS_HEX)).unwrap();
    let parallax = parse_client_hello(&generate_parallax_client_hello().await).unwrap();

    assert_required_chrome_parity("GUI", &gui, &parallax);
    assert_required_chrome_parity("headless", &headless, &parallax);
    assert_eq!(
        actual_field_diffs(&gui, &parallax),
        WHITELISTED_FIELD_DIFFS,
        "GUI Chrome vs ParallaX field differences must stay explicitly whitelisted"
    );
    assert_eq!(
        actual_field_diffs(&headless, &parallax),
        WHITELISTED_FIELD_DIFFS,
        "headless Chrome vs ParallaX field differences must stay explicitly whitelisted"
    );
}

#[tokio::test]
#[ignore = "chrome_parity: needs local Chrome samples to be refreshed intentionally"]
async fn chrome_parity_fingerprint_snapshots() {
    let gui = parse_client_hello(&hex_to_bytes(CHROME_GUI_HEX)).unwrap();
    let headless = parse_client_hello(&hex_to_bytes(CHROME_HEADLESS_HEX)).unwrap();
    let parallax = parse_client_hello(&generate_parallax_client_hello().await).unwrap();
    let gui_fp = fingerprints(&gui);
    let headless_fp = fingerprints(&headless);
    let parallax_fp = fingerprints(&parallax);

    assert_eq!(gui_fp.ja3, EXPECTED_CHROME_GUI_JA3);
    assert_eq!(headless_fp.ja3, EXPECTED_CHROME_HEADLESS_JA3);
    assert_eq!(gui_fp.ja4, EXPECTED_CHROME_JA4);
    assert_eq!(headless_fp.ja4, EXPECTED_CHROME_JA4);
    assert_eq!(parallax_fp.ja4, EXPECTED_PARALLAX_JA4);

    println!(
        "{}",
        markdown_report(
            (&gui, &gui_fp),
            (&headless, &headless_fp),
            (&parallax, &parallax_fp)
        )
    );
}

fn assert_required_chrome_parity(
    sample: &str,
    chrome: &ClientHelloFields,
    parallax: &ClientHelloFields,
) {
    let expected_alpn = vec!["h2".to_owned(), "http/1.1".to_owned()];
    assert_eq!(chrome.alpn, expected_alpn, "{sample} Chrome ALPN changed");
    assert_eq!(parallax.alpn, expected_alpn, "ParallaX ALPN changed");
    assert_eq!(
        non_grease(&chrome.supported_versions),
        vec![TLS13, TLS12],
        "{sample} Chrome supported_versions changed"
    );
    assert_eq!(
        non_grease(&parallax.supported_versions),
        vec![TLS13, TLS12],
        "ParallaX supported_versions changed"
    );
    assert_eq!(
        non_grease(&chrome.supported_groups),
        vec![GROUP_X25519_MLKEM768, GROUP_X25519, 0x0017, 0x0018],
        "{sample} Chrome supported_groups changed"
    );
    assert_eq!(
        non_grease(&parallax.supported_groups),
        vec![GROUP_X25519_MLKEM768, GROUP_X25519, 0x0017, 0x0018],
        "ParallaX supported_groups changed"
    );
    assert_eq!(
        non_grease_key_share_groups(chrome),
        vec![GROUP_X25519_MLKEM768, GROUP_X25519],
        "{sample} Chrome key_share groups changed"
    );
    assert_eq!(
        non_grease_key_share_groups(parallax),
        vec![GROUP_X25519_MLKEM768, GROUP_X25519],
        "ParallaX key_share groups changed"
    );
    assert_eq!(
        chrome.ec_point_formats,
        vec![0],
        "{sample} Chrome ec_point_formats changed"
    );
    assert_eq!(
        parallax.ec_point_formats,
        vec![0],
        "ParallaX ec_point_formats changed"
    );

    let chrome_signature_algorithms = vec![
        0x0403_u16, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ];
    assert_eq!(
        chrome.signature_algorithms, chrome_signature_algorithms,
        "{sample} Chrome signature_algorithms changed"
    );
    assert_eq!(
        parallax.signature_algorithms, chrome_signature_algorithms,
        "ParallaX signature_algorithms must stay Chrome/BoringSSL-shaped"
    );
}

async fn generate_parallax_client_hello() -> Vec<u8> {
    let (addr_tx, addr_rx) = mpsc::channel();
    let server_thread = thread::spawn(move || run_loopback_rustls_server(addr_tx));
    let addr = addr_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("loopback rustls server did not publish its address");
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect loopback rustls server");
    let server = X25519KeyPair::generate();
    let psk = b"0123456789abcdef0123456789abcdef";
    let completed = StatefulRustlsCamouflageBackend
        .start(
            "localhost".to_owned(),
            psk,
            &server.public,
            BrowserProfile::Chrome124,
        )
        .expect("start stateful ParallaX TLS camouflage")
        .complete(&mut stream)
        .await
        .expect("complete loopback TLS handshake");
    drop(stream);
    server_thread
        .join()
        .expect("loopback rustls server panicked")
        .expect("loopback rustls server failed");
    completed.client_hello
}

fn run_loopback_rustls_server(addr_tx: mpsc::Sender<SocketAddr>) -> Result<(), String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|err| err.to_string())?;
    addr_tx
        .send(listener.local_addr().map_err(|err| err.to_string())?)
        .map_err(|err| err.to_string())?;
    let (mut tcp, _) = listener.accept().map_err(|err| err.to_string())?;
    tcp.set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|err| err.to_string())?;
    tcp.set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|err| err.to_string())?;

    let mut connection =
        rustls::ServerConnection::new(rustls_server_config()).map_err(|err| err.to_string())?;
    while connection.is_handshaking() {
        while connection.wants_write() {
            connection
                .write_tls(&mut tcp)
                .map_err(|err| err.to_string())?;
        }
        let read = connection
            .read_tls(&mut tcp)
            .map_err(|err| err.to_string())?;
        if read == 0 {
            break;
        }
        connection
            .process_new_packets()
            .map_err(|err| err.to_string())?;
    }
    while connection.wants_write() {
        connection
            .write_tls(&mut tcp)
            .map_err(|err| err.to_string())?;
    }
    let _ = tcp.shutdown(Shutdown::Both);
    Ok(())
}

fn rustls_server_config() -> Arc<rustls::ServerConfig> {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("generate local self-signed certificate");
    let cert_der = certified.cert.der().clone();
    let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("aws_lc_rs provider supports rustls default protocol versions")
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key_der)
    .expect("self-signed certificate is valid for rustls");
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ClientHelloFields {
    record_len: usize,
    handshake_len: usize,
    legacy_version: u16,
    session_id_len: usize,
    cipher_suites: Vec<u16>,
    extensions: Vec<u16>,
    supported_versions: Vec<u16>,
    supported_groups: Vec<u16>,
    signature_algorithms: Vec<u16>,
    alpn: Vec<String>,
    key_shares: Vec<KeyShare>,
    ec_point_formats: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KeyShare {
    group: u16,
    len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Fingerprints {
    ja3_raw: String,
    ja3: String,
    ja4: String,
}

fn parse_client_hello(record: &[u8]) -> Result<ClientHelloFields, String> {
    let mut cursor = Cursor::new(record);
    let content_type = cursor.u8()?;
    if content_type != 0x16 {
        return Err(format!("not a TLS handshake record: {content_type:#04x}"));
    }
    let _record_version = cursor.u16()?;
    let record_len = cursor.u16()? as usize;
    if cursor.remaining() != record_len {
        return Err(format!(
            "record length mismatch: header={record_len}, actual={}",
            cursor.remaining()
        ));
    }
    let handshake_type = cursor.u8()?;
    if handshake_type != 0x01 {
        return Err(format!("not a ClientHello: {handshake_type:#04x}"));
    }
    let handshake_len = cursor.u24()? as usize;
    let handshake_end = cursor
        .pos
        .checked_add(handshake_len)
        .ok_or_else(|| "handshake length overflow".to_owned())?;
    if handshake_end != record.len() {
        return Err(format!(
            "handshake length mismatch: end={handshake_end}, record={}",
            record.len()
        ));
    }

    let legacy_version = cursor.u16()?;
    cursor.skip(32)?;
    let session_id_len = cursor.u8()? as usize;
    cursor.skip(session_id_len)?;
    let cipher_len = cursor.u16()? as usize;
    if cipher_len % 2 != 0 {
        return Err("odd cipher_suites vector length".to_owned());
    }
    let cipher_suites = cursor.u16_vec(cipher_len / 2)?;
    let compression_len = cursor.u8()? as usize;
    cursor.skip(compression_len)?;

    let mut fields = ClientHelloFields {
        record_len: record.len(),
        handshake_len,
        legacy_version,
        session_id_len,
        cipher_suites,
        ..ClientHelloFields::default()
    };

    if cursor.remaining() == 0 {
        return Ok(fields);
    }
    let extensions_len = cursor.u16()? as usize;
    let extensions_end = cursor
        .pos
        .checked_add(extensions_len)
        .ok_or_else(|| "extensions length overflow".to_owned())?;
    if extensions_end != record.len() {
        return Err(format!(
            "extensions length mismatch: end={extensions_end}, record={}",
            record.len()
        ));
    }

    while cursor.pos < extensions_end {
        let extension_type = cursor.u16()?;
        let extension_len = cursor.u16()? as usize;
        let data = cursor.bytes(extension_len)?;
        fields.extensions.push(extension_type);
        match extension_type {
            EXT_SUPPORTED_GROUPS => fields.supported_groups = parse_u16_vector(data)?,
            EXT_SIGNATURE_ALGORITHMS => fields.signature_algorithms = parse_u16_vector(data)?,
            EXT_ALPN => fields.alpn = parse_alpn(data)?,
            EXT_SUPPORTED_VERSIONS => fields.supported_versions = parse_u16_vector_u8_len(data)?,
            EXT_KEY_SHARE => fields.key_shares = parse_key_shares(data)?,
            EXT_EC_POINT_FORMATS => fields.ec_point_formats = parse_u8_vector(data)?,
            _ => {}
        }
    }
    Ok(fields)
}

fn parse_u16_vector(data: &[u8]) -> Result<Vec<u16>, String> {
    let mut cursor = Cursor::new(data);
    let len = cursor.u16()? as usize;
    if len % 2 != 0 || len != cursor.remaining() {
        return Err("invalid u16 vector length".to_owned());
    }
    cursor.u16_vec(len / 2)
}

fn parse_u16_vector_u8_len(data: &[u8]) -> Result<Vec<u16>, String> {
    let mut cursor = Cursor::new(data);
    let len = cursor.u8()? as usize;
    if len % 2 != 0 || len != cursor.remaining() {
        return Err("invalid u8-length u16 vector length".to_owned());
    }
    cursor.u16_vec(len / 2)
}

fn parse_u8_vector(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut cursor = Cursor::new(data);
    let len = cursor.u8()? as usize;
    if len != cursor.remaining() {
        return Err("invalid u8 vector length".to_owned());
    }
    Ok(cursor.bytes(len)?.to_vec())
}

fn parse_alpn(data: &[u8]) -> Result<Vec<String>, String> {
    let mut cursor = Cursor::new(data);
    let len = cursor.u16()? as usize;
    if len != cursor.remaining() {
        return Err("invalid ALPN vector length".to_owned());
    }
    let end = cursor.pos + len;
    let mut out = Vec::new();
    while cursor.pos < end {
        let name_len = cursor.u8()? as usize;
        let name = cursor.bytes(name_len)?;
        out.push(String::from_utf8_lossy(name).into_owned());
    }
    Ok(out)
}

fn parse_key_shares(data: &[u8]) -> Result<Vec<KeyShare>, String> {
    let mut cursor = Cursor::new(data);
    let len = cursor.u16()? as usize;
    if len != cursor.remaining() {
        return Err("invalid key_share vector length".to_owned());
    }
    let end = cursor.pos + len;
    let mut out = Vec::new();
    while cursor.pos < end {
        let group = cursor.u16()?;
        let key_len = cursor.u16()? as usize;
        cursor.skip(key_len)?;
        out.push(KeyShare {
            group,
            len: key_len,
        });
    }
    Ok(out)
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn u8(&mut self) -> Result<u8, String> {
        if self.remaining() < 1 {
            return Err("truncated u8".to_owned());
        }
        let value = self.data[self.pos];
        self.pos += 1;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, String> {
        let bytes = self.bytes(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u24(&mut self) -> Result<u32, String> {
        let bytes = self.bytes(3)?;
        Ok(((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | bytes[2] as u32)
    }

    fn u16_vec(&mut self, count: usize) -> Result<Vec<u16>, String> {
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(self.u16()?);
        }
        Ok(out)
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8], String> {
        if self.remaining() < len {
            return Err("truncated bytes".to_owned());
        }
        let start = self.pos;
        self.pos += len;
        Ok(&self.data[start..start + len])
    }

    fn skip(&mut self, len: usize) -> Result<(), String> {
        self.bytes(len).map(|_| ())
    }
}

fn fingerprints(fields: &ClientHelloFields) -> Fingerprints {
    let ja3_raw = ja3_raw(fields);
    let ja3 = md5_hex(ja3_raw.as_bytes());
    let ja4 = ja4(fields);
    Fingerprints { ja3_raw, ja3, ja4 }
}

fn ja3_raw(fields: &ClientHelloFields) -> String {
    [
        fields.legacy_version.to_string(),
        join_dec(&non_grease(&fields.cipher_suites), "-"),
        join_dec(&non_grease(&fields.extensions), "-"),
        join_dec(&non_grease(&fields.supported_groups), "-"),
        join_u8_dec(&fields.ec_point_formats, "-"),
    ]
    .join(",")
}

fn ja4(fields: &ClientHelloFields) -> String {
    let tls_version = ja4_tls_version(fields);
    let sni = if fields.extensions.contains(&EXT_SNI) {
        "d"
    } else {
        "i"
    };
    let cipher_count = non_grease(&fields.cipher_suites).len().min(99);
    let extension_count = non_grease(&fields.extensions).len().min(99);
    let alpn = ja4_alpn(&fields.alpn);
    let cipher_hash = ja4_cipher_hash(fields);
    let extension_hash = ja4_extension_hash(fields);
    format!(
        "t{tls_version}{sni}{cipher_count:02}{extension_count:02}{alpn}_{cipher_hash}_{extension_hash}"
    )
}

fn ja4_tls_version(fields: &ClientHelloFields) -> &'static str {
    let version = non_grease(&fields.supported_versions)
        .into_iter()
        .max()
        .unwrap_or(fields.legacy_version);
    match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        0xfeff => "d1",
        0xfefd => "d2",
        0xfefc => "d3",
        _ => "00",
    }
}

fn ja4_alpn(alpn: &[String]) -> String {
    let Some(first) = alpn.first() else {
        return "00".to_owned();
    };
    let bytes = first.as_bytes();
    let Some(first_byte) = bytes.first() else {
        return "00".to_owned();
    };
    let last_byte = *bytes.last().expect("non-empty bytes has a last byte");
    if first_byte.is_ascii_alphanumeric() && last_byte.is_ascii_alphanumeric() {
        format!("{}{}", *first_byte as char, last_byte as char)
    } else {
        let hex = hex_lower(bytes);
        format!(
            "{}{}",
            hex.as_bytes()[0] as char,
            *hex.as_bytes()
                .last()
                .expect("hex for non-empty bytes is non-empty") as char
        )
    }
}

fn ja4_cipher_hash(fields: &ClientHelloFields) -> String {
    let mut values = non_grease(&fields.cipher_suites)
        .into_iter()
        .map(|value| format!("{value:04x}"))
        .collect::<Vec<_>>();
    values.sort();
    if values.is_empty() {
        "000000000000".to_owned()
    } else {
        sha256_12(&values.join(","))
    }
}

fn ja4_extension_hash(fields: &ClientHelloFields) -> String {
    let mut extensions = non_grease(&fields.extensions)
        .into_iter()
        .filter(|value| !matches!(*value, EXT_SNI | EXT_ALPN))
        .map(|value| format!("{value:04x}"))
        .collect::<Vec<_>>();
    extensions.sort();
    if extensions.is_empty() {
        return "000000000000".to_owned();
    }

    let mut input = extensions.join(",");
    let signature_algorithms = non_grease(&fields.signature_algorithms)
        .into_iter()
        .map(|value| format!("{value:04x}"))
        .collect::<Vec<_>>();
    if !signature_algorithms.is_empty() {
        input.push('_');
        input.push_str(&signature_algorithms.join(","));
    }
    sha256_12(&input)
}

fn actual_field_diffs(
    chrome: &ClientHelloFields,
    parallax: &ClientHelloFields,
) -> Vec<&'static str> {
    let mut out = Vec::new();
    if non_grease(&chrome.cipher_suites) != non_grease(&parallax.cipher_suites) {
        out.push("cipher_suites");
    }
    if non_grease(&chrome.extensions) != non_grease(&parallax.extensions) {
        out.push("extensions");
    }
    if non_grease(&chrome.signature_algorithms) != non_grease(&parallax.signature_algorithms) {
        out.push("signature_algorithms");
    }
    if grease_positions(chrome) != grease_positions(parallax) {
        out.push("grease");
    }
    out
}

fn markdown_report(
    gui: (&ClientHelloFields, &Fingerprints),
    headless: (&ClientHelloFields, &Fingerprints),
    parallax: (&ClientHelloFields, &Fingerprints),
) -> String {
    let mut out = String::new();
    writeln!(out, "# ParallaX / Chrome ClientHello parity baseline").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "## JA3 / JA4").unwrap();
    writeln!(out, "| Sample | Record bytes | JA3 | JA4 |").unwrap();
    writeln!(out, "|---|---:|---|---|").unwrap();
    writeln!(
        out,
        "| Chrome GUI | {} | `{}` | `{}` |",
        gui.0.record_len, gui.1.ja3, gui.1.ja4
    )
    .unwrap();
    writeln!(
        out,
        "| Chrome headless | {} | `{}` | `{}` |",
        headless.0.record_len, headless.1.ja3, headless.1.ja4
    )
    .unwrap();
    writeln!(
        out,
        "| ParallaX stateful Chrome124 | {} | `{}` | `{}` |",
        parallax.0.record_len, parallax.1.ja3, parallax.1.ja4
    )
    .unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "Note: JA3 is order-sensitive, so both Chrome/BoringSSL and rustls extension permutation make it sample/run-local. JA4 is the stable snapshot asserted for ParallaX."
    )
    .unwrap();
    writeln!(out).unwrap();
    writeln!(out, "## Field differences").unwrap();
    writeln!(
        out,
        "| Field | Chrome real GUI / headless | ParallaX current | Status |"
    )
    .unwrap();
    writeln!(out, "|---|---|---|---|").unwrap();
    write_field_row(
        &mut out,
        "ALPN",
        &format!("GUI/headless `{}`", gui.0.alpn.join(", ")),
        &format!("`{}`", parallax.0.alpn.join(", ")),
        "assert_eq required",
    );
    write_field_row(
        &mut out,
        "supported_versions",
        &format!(
            "GUI `{}` / headless `{}`",
            fmt_hex(&non_grease(&gui.0.supported_versions)),
            fmt_hex(&non_grease(&headless.0.supported_versions))
        ),
        &fmt_hex(&non_grease(&parallax.0.supported_versions)),
        "assert_eq after GREASE removal",
    );
    write_field_row(
        &mut out,
        "supported_groups",
        &format!(
            "GUI `{}` / headless `{}`",
            fmt_hex(&non_grease(&gui.0.supported_groups)),
            fmt_hex(&non_grease(&headless.0.supported_groups))
        ),
        &fmt_hex(&non_grease(&parallax.0.supported_groups)),
        "assert_eq after GREASE removal",
    );
    write_field_row(
        &mut out,
        "key_share groups",
        &format!(
            "GUI `{}` / headless `{}`",
            fmt_key_shares(gui.0),
            fmt_key_shares(headless.0)
        ),
        &fmt_key_shares(parallax.0),
        "assert_eq after GREASE removal",
    );
    write_field_row(
        &mut out,
        "cipher_suites",
        &format!(
            "Chrome non-GREASE count {}",
            non_grease(&gui.0.cipher_suites).len()
        ),
        &format!(
            "ParallaX non-GREASE count {}",
            non_grease(&parallax.0.cipher_suites).len()
        ),
        "whitelisted: rustls/aws-lc emits a shorter suite list and includes SCSV 0x00ff",
    );
    write_field_row(
        &mut out,
        "extensions",
        &format!(
            "GUI `{}` / headless `{}`",
            fmt_hex(&non_grease(&gui.0.extensions)),
            fmt_hex(&non_grease(&headless.0.extensions))
        ),
        &fmt_hex(&non_grease(&parallax.0.extensions)),
        "whitelisted: Chrome has ALPS/ECH/cert-compression/ticket/SCT/renegotiation extras",
    );
    write_field_row(
        &mut out,
        "signature_algorithms",
        &format!("Chrome `{}`", fmt_hex(&gui.0.signature_algorithms)),
        &format!("ParallaX `{}`", fmt_hex(&parallax.0.signature_algorithms)),
        "assert_eq: shaped to Chrome/BoringSSL order without Ed25519",
    );
    write_field_row(
        &mut out,
        "GREASE positions",
        &format!(
            "GUI `{}` / headless `{}`",
            grease_positions(gui.0),
            grease_positions(headless.0)
        ),
        &grease_positions(parallax.0),
        "whitelisted: current rustls path does not emit Chrome-style GREASE",
    );
    writeln!(out).unwrap();
    writeln!(out, "## code_refs/chrome-fp-src cross-check").unwrap();
    writeln!(
        out,
        "- `boringssl-tls-min/ssl/extensions.cc` has `ssl_setup_extension_permutation`, then iterates `kExtensions`; this matches the GUI/headless samples having the same extension set but different order/JA3."
    )
    .unwrap();
    writeln!(
        out,
        "- The same file adds a first GREASE extension before the permuted list and a second GREASE extension after it; both captured Chrome samples show GREASE at extension-list edges."
    )
    .unwrap();
    writeln!(
        out,
        "- `ssl_setup_key_shares` prepends a GREASE key share and then picks one post-quantum plus one classical share. The captured non-GREASE groups are X25519MLKEM768 + X25519, matching ParallaX."
    )
    .unwrap();
    writeln!(out).unwrap();
    writeln!(out, "## Still missing, by priority").unwrap();
    writeln!(
        out,
        "1. Match Chrome cipher catalog/order, including the extra ECDHE and legacy suites: 3-5h."
    )
    .unwrap();
    writeln!(
        out,
        "2. Add Chrome-style GREASE in cipher/group/key_share/extensions without breaking ParallaX auth patching: 4-6h."
    )
    .unwrap();
    writeln!(
        out,
        "3. Add/shape Chrome-only extensions (ALPS 0x44cd, ECH GREASE 0xfe0d, cert compression, session ticket, SCT, renegotiation_info): 6-10h."
    )
    .unwrap();
    writeln!(
        out,
        "4. If exact JA3 parity is a goal, expose deterministic extension permutation/GREASE seeding for test snapshots only: 4-8h."
    )
    .unwrap();
    out
}

fn write_field_row(out: &mut String, field: &str, chrome: &str, parallax: &str, status: &str) {
    writeln!(out, "| {field} | {chrome} | {parallax} | {status} |").unwrap();
}

fn non_grease(values: &[u16]) -> Vec<u16> {
    values
        .iter()
        .copied()
        .filter(|value| !is_grease(*value))
        .collect()
}

fn non_grease_key_share_groups(fields: &ClientHelloFields) -> Vec<u16> {
    fields
        .key_shares
        .iter()
        .map(|share| share.group)
        .filter(|group| !is_grease(*group))
        .collect()
}

fn grease_positions(fields: &ClientHelloFields) -> String {
    let cipher = positions(&fields.cipher_suites);
    let extensions = positions(&fields.extensions);
    let groups = positions(&fields.supported_groups);
    let key_share = fields
        .key_shares
        .iter()
        .enumerate()
        .filter_map(|(idx, share)| is_grease(share.group).then_some(idx))
        .collect::<Vec<_>>();
    format!("cipher={cipher:?}; ext={extensions:?}; groups={groups:?}; key_share={key_share:?}")
}

fn positions(values: &[u16]) -> Vec<usize> {
    values
        .iter()
        .enumerate()
        .filter_map(|(idx, value)| is_grease(*value).then_some(idx))
        .collect()
}

fn is_grease(value: u16) -> bool {
    let high = (value >> 8) as u8;
    let low = value as u8;
    high == low && (low & 0x0f) == 0x0a
}

fn join_dec(values: &[u16], sep: &str) -> String {
    values
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(sep)
}

fn join_u8_dec(values: &[u8], sep: &str) -> String {
    values
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(sep)
}

fn fmt_hex(values: &[u16]) -> String {
    values
        .iter()
        .map(|value| format!("0x{value:04x}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn fmt_key_shares(fields: &ClientHelloFields) -> String {
    fields
        .key_shares
        .iter()
        .filter(|share| !is_grease(share.group))
        .map(|share| format!("0x{:04x}/{}B", share.group, share.len))
        .collect::<Vec<_>>()
        .join(", ")
}

fn sha256_12(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    hex_lower(&digest[..6])
}

fn md5_hex(input: &[u8]) -> String {
    hex_lower(&md5_digest(input))
}

fn md5_digest(input: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    let mut message = input.to_vec();
    let bit_len = (input.len() as u64) * 8;
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_le_bytes());

    let mut a0 = 0x67452301_u32;
    let mut b0 = 0xefcdab89_u32;
    let mut c0 = 0x98badcfe_u32;
    let mut d0 = 0x10325476_u32;

    for chunk in message.chunks_exact(64) {
        let mut words = [0_u32; 16];
        for (idx, word) in words.iter_mut().enumerate() {
            let start = idx * 4;
            *word = u32::from_le_bytes([
                chunk[start],
                chunk[start + 1],
                chunk[start + 2],
                chunk[start + 3],
            ]);
        }

        let mut a = a0;
        let mut b = b0;
        let mut c = c0;
        let mut d = d0;

        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | ((!b) & d), i),
                16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * i) % 16),
            };
            let next = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                a.wrapping_add(f)
                    .wrapping_add(K[i])
                    .wrapping_add(words[g])
                    .rotate_left(S[i]),
            );
            a = next;
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = [0_u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut chunks = hex.as_bytes().chunks_exact(2);
    let bytes = chunks
        .by_ref()
        .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
        .collect::<Vec<_>>();
    assert!(
        chunks.remainder().is_empty(),
        "hex string must have an even length"
    );
    bytes
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("invalid hex nibble: {value:#04x}"),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
