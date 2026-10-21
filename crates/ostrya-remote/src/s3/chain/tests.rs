use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;

const ID: &str = "AKIAIOSFODNN7EXAMPLE";
const SECRET: &str = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY";
const TOKEN: &str = "FwoGZXIvYXdzEXAMPLETOKEN";

/// A scratch directory under the temporary directory. A drop removes it.
struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new(tag: &str) -> Scratch {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("ostrya-remote-s3-{}-{tag}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Scratch { path }
    }

    /// Writes `text` to the file `name` under the directory, and returns its
    /// path.
    fn write(&self, name: &str, text: impl AsRef<[u8]>) -> PathBuf {
        let path = self.path.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, text).unwrap();
        path
    }

    /// Returns the path of `name` under the directory as text.
    fn at(&self, name: &str) -> String {
        self.path.join(name).to_str().unwrap().to_owned()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn environment(pairs: &[(&str, &str)]) -> Environment {
    Environment::Variables(
        pairs
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect(),
    )
}

fn vars(pairs: &[(&str, &str)], windows: bool) -> Vars {
    Vars::of(&environment(pairs), windows)
}

fn resolved(settings: &Settings, pairs: &[(&str, &str)]) -> Resolved {
    resolve_with(settings, &vars(pairs, false), false).unwrap()
}

fn refused(settings: &Settings, pairs: &[(&str, &str)]) -> String {
    match resolve_with(settings, &vars(pairs, false), false) {
        Err(Error::InvalidInput(msg)) => msg,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// The environment variables of the key pair of the environment.
const ENV_PAIR: [(&str, &str); 2] = [("AWS_ACCESS_KEY_ID", ID), ("AWS_SECRET_ACCESS_KEY", SECRET)];

fn file_origin(path: &Path, section: &str, key: &'static str) -> Origin {
    Origin::SharedFile {
        path: path.to_owned(),
        section: section.into(),
        key,
    }
}

fn named(profile: &str) -> Settings {
    Settings {
        profile: Some(profile.into()),
        ..Settings::default()
    }
}

#[test]
fn the_region_comes_from_the_first_source_that_gives_one() {
    let scratch = Scratch::new("region");
    let config = scratch.write("config", "[default]\nregion = eu-west-3\n");
    let config_var = ("AWS_CONFIG_FILE", config.to_str().unwrap());
    let caller = Settings {
        region: Some("eu-west-1".into()),
        ..Settings::default()
    };
    let all = [
        ENV_PAIR[0],
        ENV_PAIR[1],
        ("AWS_REGION", "eu-north-1"),
        ("AWS_DEFAULT_REGION", "eu-south-1"),
        config_var,
    ];
    let r = resolved(&caller, &all);
    assert_eq!(
        r.region,
        Setting {
            value: "eu-west-1".into(),
            origin: Origin::Caller
        }
    );
    let r = resolved(&Settings::default(), &all);
    assert_eq!(r.region.value, "eu-north-1");
    assert_eq!(r.region.origin, Origin::Environment("AWS_REGION"));
    let r = resolved(&Settings::default(), &[all[0], all[1], all[3], all[4]]);
    assert_eq!(r.region.value, "eu-south-1");
    assert_eq!(r.region.origin, Origin::Environment("AWS_DEFAULT_REGION"));
    let r = resolved(&Settings::default(), &[all[0], all[1], all[4]]);
    assert_eq!(r.region.value, "eu-west-3");
    assert_eq!(r.region.origin, file_origin(&config, "default", "region"));
    let r = resolved(&Settings::default(), &[all[0], all[1], ("AWS_REGION", "")]);
    assert_eq!(r.region.value, DEFAULT_REGION);
    assert_eq!(r.region.origin, Origin::Default);
}

#[test]
fn the_endpoint_comes_from_the_first_source_that_gives_one() {
    let scratch = Scratch::new("endpoint");
    let config = scratch.write(
        "config",
        "[default]\n\
         services = local\n\
         endpoint_url = http://profile:9000\n\
         [services local]\n\
         s3 =\n  endpoint_url = http://services:9000\n\
         [profile plain]\n\
         endpoint_url = http://plain:9000\n\
         [profile other]\n\
         services = elsewhere\n\
         endpoint_url = http://other:9000\n\
         [services elsewhere]\n\
         dynamodb =\n  endpoint_url = http://dynamo:9000\n",
    );
    let config_var = ("AWS_CONFIG_FILE", config.to_str().unwrap());
    let caller = Settings {
        endpoint: Some("http://caller:9000".into()),
        ..Settings::default()
    };
    let all = [
        ENV_PAIR[0],
        ENV_PAIR[1],
        ("AWS_ENDPOINT_URL_S3", "http://env-s3:9000"),
        ("AWS_ENDPOINT_URL", "http://env:9000"),
        config_var,
    ];
    let endpoint = |settings: &Settings, pairs: &[(&str, &str)]| {
        resolved(settings, pairs)
            .endpoint
            .map(|e| (e.value, e.origin))
    };
    assert_eq!(
        endpoint(&caller, &all),
        Some(("http://caller:9000".into(), Origin::Caller))
    );
    assert_eq!(
        endpoint(&Settings::default(), &all),
        Some((
            "http://env-s3:9000".into(),
            Origin::Environment("AWS_ENDPOINT_URL_S3")
        ))
    );
    assert_eq!(
        endpoint(&Settings::default(), &[all[0], all[1], all[3], all[4]]),
        Some((
            "http://env:9000".into(),
            Origin::Environment("AWS_ENDPOINT_URL")
        ))
    );
    assert_eq!(
        endpoint(&Settings::default(), &[all[0], all[1], all[4]]),
        Some((
            "http://services:9000".into(),
            file_origin(&config, "services local", "s3.endpoint_url")
        ))
    );
    let profile = |name: &'static str| [all[0], all[1], all[4], ("AWS_PROFILE", name)];
    assert_eq!(
        endpoint(&Settings::default(), &profile("plain")),
        Some((
            "http://plain:9000".into(),
            file_origin(&config, "profile plain", "endpoint_url")
        ))
    );
    assert_eq!(
        endpoint(&Settings::default(), &profile("other")),
        Some((
            "http://other:9000".into(),
            file_origin(&config, "profile other", "endpoint_url")
        ))
    );
    assert_eq!(endpoint(&Settings::default(), &profile("absent")), None);
}

#[test]
fn the_addressing_style_comes_from_the_caller_then_the_config_file() {
    let scratch = Scratch::new("addressing");
    let config = scratch.write(
        "config",
        "[default]\n\
         s3 =\n  addressing_style = virtual\n\
         [profile auto]\n\
         s3 =\n  addressing_style = auto\n\
         [profile bad]\n\
         s3 =\n  addressing_style = Path\n\
         [profile scalar]\n\
         s3 = path\n",
    );
    let config_var = ("AWS_CONFIG_FILE", config.to_str().unwrap());
    let caller = Settings {
        addressing: Some(Addressing::Path),
        ..Settings::default()
    };
    let pairs = [ENV_PAIR[0], ENV_PAIR[1], config_var];
    let r = resolved(&caller, &pairs);
    assert_eq!(
        r.addressing,
        Some(Setting {
            value: Addressing::Path,
            origin: Origin::Caller
        })
    );
    let r = resolved(&Settings::default(), &pairs);
    assert_eq!(
        r.addressing,
        Some(Setting {
            value: Addressing::Virtual,
            origin: file_origin(&config, "default", "s3.addressing_style"),
        })
    );
    let profile =
        |name: &'static str| [ENV_PAIR[0], ENV_PAIR[1], config_var, ("AWS_PROFILE", name)];
    assert_eq!(
        resolved(&Settings::default(), &profile("auto")).addressing,
        None
    );
    let msg = refused(&Settings::default(), &profile("bad"));
    assert!(
        msg.contains(&format!("{}:9:", config.display())) && msg.contains("s3.addressing_style"),
        "{msg}"
    );
    let msg = refused(&Settings::default(), &profile("scalar"));
    assert!(
        msg.contains(&format!("{}:11:", config.display())) && msg.contains("the key s3"),
        "{msg}"
    );
    assert_eq!(Addressing::Virtual.as_str(), "virtual");
    assert_eq!(Addressing::from_name("virtual"), Some(Addressing::Virtual));
    assert_eq!(Addressing::from_name("Path"), None);
}

#[test]
fn a_profile_of_the_caller_turns_off_the_environment() {
    let scratch = Scratch::new("named");
    let config = scratch.write(
        "config",
        "[profile dev]\n\
         region = ap-south-1\n\
         endpoint_url = http://dev:9000\n",
    );
    let creds = scratch.write(
        "credentials",
        "[dev]\naws_access_key_id = AKIADEV\naws_secret_access_key = devsecret\n",
    );
    let pairs = [
        ENV_PAIR[0],
        ENV_PAIR[1],
        ("AWS_SESSION_TOKEN", TOKEN),
        ("AWS_REGION", "eu-north-1"),
        ("AWS_ENDPOINT_URL", "http://env:9000"),
        ("AWS_PROFILE", "other"),
        ("AWS_CONFIG_FILE", config.to_str().unwrap()),
        ("AWS_SHARED_CREDENTIALS_FILE", creds.to_str().unwrap()),
    ];
    let r = resolved(&named("dev"), &pairs);
    assert_eq!(r.profile, "dev");
    assert_eq!(r.credentials.access_key_id(), "AKIADEV");
    assert!(!r.credentials.has_session_token());
    assert_eq!(
        r.credentials_origin,
        file_origin(&creds, "dev", "aws_access_key_id")
    );
    assert_eq!(
        r.region.origin,
        file_origin(&config, "profile dev", "region")
    );
    assert_eq!(r.region.value, "ap-south-1");
    assert_eq!(
        r.endpoint.unwrap().origin,
        file_origin(&config, "profile dev", "endpoint_url")
    );

    // A half pair of the environment is not read for a named profile.
    let half = [
        ENV_PAIR[0],
        ("AWS_CONFIG_FILE", config.to_str().unwrap()),
        ("AWS_SHARED_CREDENTIALS_FILE", creds.to_str().unwrap()),
    ];
    assert_eq!(
        resolved(&named("dev"), &half).credentials.access_key_id(),
        "AKIADEV"
    );
}

#[test]
fn a_profile_of_aws_profile_keeps_the_environment_first() {
    let scratch = Scratch::new("aws-profile");
    let config = scratch.write("config", "[profile dev]\nregion = ap-south-1\n");
    let pairs = [
        ENV_PAIR[0],
        ENV_PAIR[1],
        ("AWS_REGION", "eu-north-1"),
        ("AWS_PROFILE", "dev"),
        ("AWS_CONFIG_FILE", config.to_str().unwrap()),
    ];
    let r = resolved(&Settings::default(), &pairs);
    assert_eq!(r.profile, "dev");
    assert_eq!(r.credentials.access_key_id(), ID);
    assert_eq!(
        r.credentials_origin,
        Origin::Environment("AWS_ACCESS_KEY_ID")
    );
    assert_eq!(r.region.origin, Origin::Environment("AWS_REGION"));
    let r = resolved(
        &Settings::default(),
        &[pairs[0], pairs[1], pairs[3], pairs[4]],
    );
    assert_eq!(r.region.value, "ap-south-1");
}

#[test]
fn an_empty_aws_profile_is_the_default_profile() {
    let r = resolved(
        &Settings::default(),
        &[
            ENV_PAIR[0],
            ENV_PAIR[1],
            ("AWS_PROFILE", ""),
            ("AWS_PROFILE", "later"),
        ],
    );
    assert_eq!(r.profile, "later");
    let r = resolved(
        &Settings::default(),
        &[ENV_PAIR[0], ENV_PAIR[1], ("AWS_PROFILE", "")],
    );
    assert_eq!(r.profile, "default");
}

#[test]
fn a_session_token_of_the_environment_goes_with_its_pair() {
    let r = resolved(
        &Settings::default(),
        &[ENV_PAIR[0], ENV_PAIR[1], ("AWS_SESSION_TOKEN", TOKEN)],
    );
    assert!(r.credentials.has_session_token());
    assert_eq!(r.credentials.session_token(), Some(TOKEN));
}

#[test]
fn a_half_pair_of_the_environment_is_refused() {
    let msg = refused(&Settings::default(), &[ENV_PAIR[0]]);
    assert!(
        msg.contains("AWS_ACCESS_KEY_ID is set") && msg.contains("AWS_SECRET_ACCESS_KEY"),
        "{msg}"
    );
    let msg = refused(&Settings::default(), &[ENV_PAIR[1]]);
    assert!(
        msg.contains("AWS_SECRET_ACCESS_KEY is set") && msg.contains("AWS_ACCESS_KEY_ID"),
        "{msg}"
    );
    assert!(!msg.contains(SECRET), "{msg}");
    let msg = refused(&Settings::default(), &[("AWS_SESSION_TOKEN", TOKEN)]);
    assert!(msg.contains("AWS_SESSION_TOKEN is set"), "{msg}");
    assert!(!msg.contains(TOKEN), "{msg}");
    let msg = refused(
        &Settings::default(),
        &[("AWS_ACCESS_KEY_ID", "AKIA/BAD"), ENV_PAIR[1]],
    );
    assert!(
        msg.contains("environment variables") && msg.contains("access key id"),
        "{msg}"
    );
}

#[test]
fn the_credentials_file_comes_before_the_config_file() {
    let scratch = Scratch::new("pairs");
    let config = scratch.write(
        "config",
        "[default]\naws_access_key_id = AKIACONFIG\naws_secret_access_key = c\n",
    );
    let creds = scratch.write(
        "credentials",
        "[default]\naws_access_key_id = AKIACREDS\naws_secret_access_key = s\n\
         aws_session_token = tok\n",
    );
    let both = [
        ("AWS_CONFIG_FILE", config.to_str().unwrap()),
        ("AWS_SHARED_CREDENTIALS_FILE", creds.to_str().unwrap()),
    ];
    let r = resolved(&Settings::default(), &both);
    assert_eq!(r.credentials.access_key_id(), "AKIACREDS");
    assert!(r.credentials.has_session_token());
    assert_eq!(
        r.credentials_origin,
        file_origin(&creds, "default", "aws_access_key_id")
    );
    let absent = scratch.at("absent");
    let r = resolved(
        &Settings::default(),
        &[both[0], ("AWS_SHARED_CREDENTIALS_FILE", &absent)],
    );
    assert_eq!(r.credentials.access_key_id(), "AKIACONFIG");
    assert!(!r.credentials.has_session_token());
    assert_eq!(
        r.credentials_origin,
        file_origin(&config, "default", "aws_access_key_id")
    );
}

#[test]
fn the_config_file_names_its_profile_sections() {
    let scratch = Scratch::new("sections");
    let plain = scratch.write("plain", "[default]\nregion = eu-west-1\n");
    let prefixed = scratch.write(
        "prefixed",
        "[profile default]\nregion = eu-west-2\n[dev]\nregion = eu-west-3\n\
         [profile dev]\nregion = eu-west-4\n",
    );
    let both = scratch.write(
        "both",
        "[default]\nregion = eu-west-1\n[profile default]\nregion = eu-west-2\n",
    );
    let region = |path: &Path, profile: &str| {
        resolved(
            &Settings::default(),
            &[
                ENV_PAIR[0],
                ENV_PAIR[1],
                ("AWS_PROFILE", profile),
                ("AWS_CONFIG_FILE", path.to_str().unwrap()),
            ],
        )
        .region
    };
    assert_eq!(region(&plain, "default").value, "eu-west-1");
    let r = region(&prefixed, "default");
    assert_eq!(r.value, "eu-west-2");
    assert_eq!(
        r.origin,
        file_origin(&prefixed, "profile default", "region")
    );
    assert_eq!(region(&prefixed, "dev").value, "eu-west-4");
    let msg = refused(
        &Settings::default(),
        &[
            ENV_PAIR[0],
            ENV_PAIR[1],
            ("AWS_CONFIG_FILE", both.to_str().unwrap()),
        ],
    );
    assert!(
        msg.contains(&both.display().to_string())
            && msg.contains("[default]")
            && msg.contains("[profile default]"),
        "{msg}"
    );
}

#[test]
fn a_half_pair_in_a_file_is_refused() {
    let scratch = Scratch::new("half");
    let absent = scratch.at("absent");
    let cases = [
        (
            "[default]\naws_access_key_id = AKIA\n",
            "aws_access_key_id is set",
        ),
        (
            "[default]\naws_secret_access_key = QQQ\n",
            "aws_secret_access_key is set",
        ),
        (
            "[default]\naws_session_token = ZZZ\n",
            "aws_session_token is set",
        ),
        (
            "[default]\naws_access_key_id = AKIA,\naws_secret_access_key = QQQ\n",
            "access key id holds",
        ),
    ];
    for (text, want) in cases {
        let creds = scratch.write("credentials", text);
        let msg = refused(
            &Settings::default(),
            &[
                ("AWS_SHARED_CREDENTIALS_FILE", creds.to_str().unwrap()),
                ("AWS_CONFIG_FILE", &absent),
            ],
        );
        assert!(
            msg.contains(&format!("{}:", creds.display()))
                && msg.contains("[default]")
                && msg.contains(want),
            "{msg}"
        );
        assert!(!msg.contains("QQQ") && !msg.contains("ZZZ"), "{msg}");
    }
}

#[test]
fn a_key_of_another_credential_source_is_refused() {
    let scratch = Scratch::new("other-source");
    let creds = scratch.write(
        "credentials",
        "[default]\naws_access_key_id = AKIA\naws_secret_access_key = s\n",
    );
    for key in [
        "role_arn",
        "source_profile",
        "credential_process",
        "web_identity_token_file",
        "sso_session",
        "sso_start_url",
    ] {
        let config = scratch.write("config", format!("[default]\n{key} = x\n"));
        let pairs = [
            ("AWS_CONFIG_FILE", config.to_str().unwrap()),
            ("AWS_SHARED_CREDENTIALS_FILE", creds.to_str().unwrap()),
        ];
        let msg = refused(&Settings::default(), &pairs);
        assert!(
            msg.contains(&format!("{}:2:", config.display()))
                && msg.contains("[default]")
                && msg.contains(key),
            "{key}: {msg}"
        );
        // The key pair of the environment turns the check off.
        let with_env = [pairs[0], pairs[1], ENV_PAIR[0], ENV_PAIR[1]];
        assert_eq!(
            resolved(&Settings::default(), &with_env)
                .credentials
                .access_key_id(),
            ID
        );
    }
    let creds = scratch.write(
        "credentials",
        "[default]\naws_access_key_id = AKIA\naws_secret_access_key = s\n\
         credential_process = /bin/true\n",
    );
    let msg = refused(
        &Settings::default(),
        &[
            ("AWS_CONFIG_FILE", &scratch.at("absent")),
            ("AWS_SHARED_CREDENTIALS_FILE", creds.to_str().unwrap()),
        ],
    );
    assert!(
        msg.contains(&format!("{}:4:", creds.display())) && msg.contains("credential_process"),
        "{msg}"
    );
}

#[test]
fn a_services_key_that_names_no_section_is_refused() {
    let scratch = Scratch::new("services");
    let config = scratch.write("config", "[default]\nservices = gone\n");
    let msg = refused(
        &Settings::default(),
        &[
            ENV_PAIR[0],
            ENV_PAIR[1],
            ("AWS_CONFIG_FILE", config.to_str().unwrap()),
        ],
    );
    assert!(
        msg.contains(&format!("{}:2:", config.display())) && msg.contains("[services gone]"),
        "{msg}"
    );
}

#[test]
fn an_absent_file_is_not_an_error() {
    let scratch = Scratch::new("absent");
    let r = resolved(
        &Settings::default(),
        &[
            ENV_PAIR[0],
            ENV_PAIR[1],
            ("AWS_CONFIG_FILE", &scratch.at("no/config")),
        ],
    );
    assert_eq!(r.region.origin, Origin::Default);
    assert_eq!(r.endpoint, None);
    assert_eq!(r.addressing, None);
}

#[test]
fn a_file_that_cannot_be_read_is_an_io_error() {
    let scratch = Scratch::new("directory");
    fs::create_dir_all(scratch.path.join("config")).unwrap();
    let path = scratch.at("config");
    let err = resolve_with(
        &Settings::default(),
        &vars(
            &[ENV_PAIR[0], ENV_PAIR[1], ("AWS_CONFIG_FILE", &path)],
            false,
        ),
        false,
    )
    .unwrap_err();
    let Error::Io(e) = &err else {
        panic!("expected an I/O error, got {err:?}");
    };
    assert!(
        e.to_string()
            .contains(&format!("shared config file '{path}'")),
        "{e}"
    );
}

#[test]
fn a_file_over_1_mib_is_refused() {
    let scratch = Scratch::new("cap");
    let head = "[default]\nregion = eu-west-1\n#";
    let mut text = head.to_owned();
    text.push_str(&"x".repeat((1 << 20) - head.len()));
    assert_eq!(text.len(), 1 << 20);
    let config = scratch.write("config", &text);
    let pairs = [
        ENV_PAIR[0],
        ENV_PAIR[1],
        ("AWS_CONFIG_FILE", config.to_str().unwrap()),
    ];
    assert_eq!(
        resolved(&Settings::default(), &pairs).region.value,
        "eu-west-1"
    );
    text.push('x');
    scratch.write("config", &text);
    let msg = refused(&Settings::default(), &pairs);
    assert!(
        msg.contains(&config.display().to_string()) && msg.contains("over 1 MiB"),
        "{msg}"
    );
}

#[test]
fn the_files_are_found_from_the_variables_and_the_home() {
    let scratch = Scratch::new("home");
    let home = scratch.at("home");
    scratch.write("home/.aws/config", "[default]\nregion = eu-west-1\n");
    scratch.write(
        "home/.aws/credentials",
        "[default]\naws_access_key_id = AKIAHOME\naws_secret_access_key = s\n",
    );
    scratch.write("home/alt/config", "[default]\nregion = eu-west-2\n");
    let alt_creds = scratch.write(
        "alt-credentials",
        "[default]\naws_access_key_id = AKIAALT\naws_secret_access_key = s\n",
    );
    let r = resolved(&Settings::default(), &[("HOME", &home)]);
    assert_eq!(r.region.value, "eu-west-1");
    assert_eq!(r.credentials.access_key_id(), "AKIAHOME");
    let r = resolved(
        &Settings::default(),
        &[
            ("HOME", &home),
            ("AWS_CONFIG_FILE", "~/alt/config"),
            ("AWS_SHARED_CREDENTIALS_FILE", alt_creds.to_str().unwrap()),
        ],
    );
    assert_eq!(r.region.value, "eu-west-2");
    assert_eq!(
        r.region.origin,
        file_origin(&Path::new(&home).join("alt/config"), "default", "region")
    );
    assert_eq!(r.credentials.access_key_id(), "AKIAALT");
    // The variables apply to a profile of the caller as well.
    let r = resolve_with(
        &named("default"),
        &vars(
            &[
                ("HOME", &home),
                ("AWS_SHARED_CREDENTIALS_FILE", alt_creds.to_str().unwrap()),
            ],
            false,
        ),
        false,
    )
    .unwrap();
    assert_eq!(r.credentials.access_key_id(), "AKIAALT");
}

#[test]
fn windows_takes_userprofile_when_home_is_unset() {
    let scratch = Scratch::new("userprofile");
    let home = scratch.at("home");
    scratch.write(
        "home/.aws/credentials",
        "[default]\naws_access_key_id = AKIAWIN\naws_secret_access_key = s\n",
    );
    let pairs = [("USERPROFILE", home.as_str())];
    let r = resolve_with(&Settings::default(), &vars(&pairs, true), true).unwrap();
    assert_eq!(r.credentials.access_key_id(), "AKIAWIN");
    // Off Windows, the variable is not read.
    let msg = refused(&Settings::default(), &pairs);
    assert!(msg.contains("not located"), "{msg}");
}

#[test]
fn no_home_leaves_the_files_not_located() {
    let msg = refused(&Settings::default(), &[]);
    assert_eq!(
        msg,
        "no S3 credentials for the profile 'default': the environment: \
         AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are not set; the shared \
         credentials file: not located, because AWS_SHARED_CREDENTIALS_FILE gives \
         no path and HOME is not set; the shared config file: not located, \
         because AWS_CONFIG_FILE gives no path and HOME is not set"
    );
    let msg = refused(
        &Settings::default(),
        &[
            ("AWS_CONFIG_FILE", "~/config"),
            ("AWS_SHARED_CREDENTIALS_FILE", "~/credentials"),
        ],
    );
    assert_eq!(
        msg,
        "no S3 credentials for the profile 'default': the environment: \
         AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are not set; the shared \
         credentials file: not located, because AWS_SHARED_CREDENTIALS_FILE \
         starts with '~/' and HOME is not set; the shared config file: not \
         located, because AWS_CONFIG_FILE starts with '~/' and HOME is not set"
    );
    let msg = refused(&Settings::default(), &[("AWS_CONFIG_FILE", "~/config")]);
    assert!(
        msg.ends_with(
            "the shared credentials file: not located, because \
             AWS_SHARED_CREDENTIALS_FILE gives no path and HOME is not set; the \
             shared config file: not located, because AWS_CONFIG_FILE starts \
             with '~/' and HOME is not set"
        ),
        "{msg}"
    );
    let err = resolve_with(&Settings::default(), &vars(&[], true), true).unwrap_err();
    assert!(
        err.to_string().ends_with(
            "the shared config file: not located, because AWS_CONFIG_FILE gives \
             no path and HOME and USERPROFILE are not set"
        ),
        "{err}"
    );
    let err = resolve_with(
        &Settings::default(),
        &vars(&[("AWS_CONFIG_FILE", "~/config")], true),
        true,
    )
    .unwrap_err();
    assert!(
        err.to_string().ends_with(
            "the shared config file: not located, because AWS_CONFIG_FILE starts \
             with '~/' and HOME and USERPROFILE are not set"
        ),
        "{err}"
    );
}

#[test]
fn the_refusal_of_no_credentials_states_each_source() {
    let scratch = Scratch::new("no-source");
    let config = scratch.write("config", "[profile dev]\nregion = eu-west-1\n");
    let creds = scratch.write("credentials", "[other]\nx = y\n");
    let pairs = [
        ("AWS_CONFIG_FILE", config.to_str().unwrap()),
        ("AWS_SHARED_CREDENTIALS_FILE", creds.to_str().unwrap()),
    ];
    let msg = refused(&named("dev"), &pairs);
    assert_eq!(
        msg,
        format!(
            "no S3 credentials for the profile 'dev': the environment: not read, \
             because the caller names the profile; the shared credentials file \
             '{}': no section [dev]; the shared config file '{}': the section \
             [profile dev] has no key pair",
            creds.display(),
            config.display()
        )
    );
    let absent = scratch.at("absent");
    let msg = refused(
        &Settings::default(),
        &[pairs[0], ("AWS_SHARED_CREDENTIALS_FILE", &absent)],
    );
    assert_eq!(
        msg,
        format!(
            "no S3 credentials for the profile 'default': the environment: \
             AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are not set; the shared \
             credentials file '{absent}': absent; the shared config file '{}': no \
             section [default]",
            config.display()
        )
    );
}

#[test]
fn the_files_are_read_only_when_a_value_is_missing() {
    let scratch = Scratch::new("lazy");
    fs::create_dir_all(scratch.path.join("config")).unwrap();
    fs::create_dir_all(scratch.path.join("credentials")).unwrap();
    let config = scratch.at("config");
    let creds = scratch.at("credentials");
    let settings = Settings {
        region: Some("eu-west-1".into()),
        endpoint: Some("http://localhost:9000".into()),
        addressing: Some(Addressing::Path),
        profile: None,
    };
    let pairs = [
        ENV_PAIR[0],
        ENV_PAIR[1],
        ("AWS_CONFIG_FILE", config.as_str()),
        ("AWS_SHARED_CREDENTIALS_FILE", creds.as_str()),
    ];
    let r = resolved(&settings, &pairs);
    assert_eq!(r.credentials.access_key_id(), ID);
    // With a setting missing, the config file is read.
    let missing = Settings {
        addressing: None,
        ..settings.clone()
    };
    let err = resolve_with(&missing, &vars(&pairs, false), false).unwrap_err();
    assert!(
        err.to_string().contains(&format!("config file '{config}'")),
        "{err}"
    );
}

#[test]
fn the_credentials_file_is_not_read_when_the_environment_gives_the_key_pair() {
    let scratch = Scratch::new("env-pair");
    let config = scratch.write("config", "[default]\ns3 =\n  addressing_style = virtual\n");
    fs::create_dir_all(scratch.path.join("credentials")).unwrap();
    let creds = scratch.at("credentials");
    let settings = Settings {
        region: Some("eu-west-1".into()),
        endpoint: Some("http://localhost:9000".into()),
        addressing: None,
        profile: None,
    };
    let files = [
        ("AWS_CONFIG_FILE", config.to_str().unwrap()),
        ("AWS_SHARED_CREDENTIALS_FILE", creds.as_str()),
    ];
    let r = resolved(&settings, &[ENV_PAIR[0], ENV_PAIR[1], files[0], files[1]]);
    assert_eq!(
        r.addressing,
        Some(Setting {
            value: Addressing::Virtual,
            origin: file_origin(&config, "default", "s3.addressing_style"),
        })
    );
    assert_eq!(
        r.credentials_origin,
        Origin::Environment("AWS_ACCESS_KEY_ID")
    );
    // Without the key pair of the environment, the credentials file is read,
    // and the read fails.
    let err = resolve_with(&settings, &vars(&files, false), false).unwrap_err();
    let Error::Io(e) = &err else {
        panic!("expected an I/O error, got {err:?}");
    };
    assert!(
        e.to_string()
            .contains(&format!("shared credentials file '{creds}'")),
        "{e}"
    );
}

#[test]
fn debug_shows_the_endpoint_with_no_userinfo() {
    let endpoint = "https://user:PASSWORD@minio:9000";
    let settings = Settings {
        endpoint: Some(endpoint.into()),
        ..Settings::default()
    };
    let debug = format!("{settings:?}");
    assert!(debug.contains("\"https://minio:9000\""), "{debug}");
    assert!(
        !debug.contains("PASSWORD") && !debug.contains("user:"),
        "{debug}"
    );
    let r = resolved(&settings, &ENV_PAIR);
    let debug = format!("{r:?}");
    assert!(debug.contains("\"https://minio:9000\""), "{debug}");
    assert!(
        !debug.contains("PASSWORD") && !debug.contains("user:"),
        "{debug}"
    );
    let r = resolved(
        &Settings::default(),
        &[ENV_PAIR[0], ENV_PAIR[1], ("AWS_ENDPOINT_URL", endpoint)],
    );
    let debug = format!("{r:?}");
    assert!(
        debug.contains("\"https://minio:9000\"") && debug.contains("AWS_ENDPOINT_URL"),
        "{debug}"
    );
    assert!(
        !debug.contains("PASSWORD") && !debug.contains("user:"),
        "{debug}"
    );
}

#[test]
fn an_invalid_region_is_refused_with_its_source() {
    let scratch = Scratch::new("bad-region");
    let config = scratch.write("config", "[default]\nregion = eu west 1\n");
    let config_var = ("AWS_CONFIG_FILE", config.to_str().unwrap());
    let caller = Settings {
        region: Some("eu/west".into()),
        ..Settings::default()
    };
    let msg = refused(&caller, &[ENV_PAIR[0], ENV_PAIR[1]]);
    assert!(
        msg.starts_with("the caller: the region \"eu/west\""),
        "{msg}"
    );
    let msg = refused(&Settings::default(), &[("AWS_REGION", "a b")]);
    assert!(
        msg.starts_with("the environment variable AWS_REGION: the region"),
        "{msg}"
    );
    let msg = refused(&Settings::default(), &[("AWS_DEFAULT_REGION", "a:b")]);
    assert!(
        msg.starts_with("the environment variable AWS_DEFAULT_REGION: the region"),
        "{msg}"
    );
    let msg = refused(
        &Settings::default(),
        &[ENV_PAIR[0], ENV_PAIR[1], config_var],
    );
    assert!(
        msg.starts_with(&format!(
            "the key region of the section [default] of '{}': the region \"eu west 1\"",
            config.display()
        )),
        "{msg}"
    );
}

#[test]
fn an_invalid_profile_name_is_refused() {
    for profile in ["", "a]b", "[a", "a\nb"] {
        let msg = refused(&named(profile), &[]);
        assert!(msg.starts_with("the profile of the caller:"), "{msg}");
        let msg = refused(&Settings::default(), &[("AWS_PROFILE", profile)]);
        if !profile.is_empty() {
            assert!(
                msg.starts_with("the environment variable AWS_PROFILE:"),
                "{msg}"
            );
        }
    }
}

#[test]
fn debug_holds_no_secret() {
    let env = environment(&[ENV_PAIR[0], ENV_PAIR[1], ("AWS_SESSION_TOKEN", TOKEN)]);
    let debug = format!("{env:?}");
    assert!(debug.contains("AWS_SECRET_ACCESS_KEY"), "{debug}");
    assert!(!debug.contains(SECRET) && !debug.contains(TOKEN), "{debug}");
    assert_eq!(format!("{:?}", Environment::Process), "Process");
    let r = resolve_with(&Settings::default(), &Vars::of(&env, false), false).unwrap();
    let debug = format!("{r:?}");
    assert!(debug.contains(ID), "{debug}");
    assert!(!debug.contains(SECRET) && !debug.contains(TOKEN), "{debug}");
}

#[test]
fn each_origin_names_its_source() {
    assert_eq!(Origin::Caller.to_string(), "the caller");
    assert_eq!(
        Origin::Environment("AWS_REGION").to_string(),
        "the environment variable AWS_REGION"
    );
    assert_eq!(
        file_origin(Path::new("/h/.aws/config"), "profile dev", "region").to_string(),
        "the key region of the section [profile dev] of '/h/.aws/config'"
    );
    assert_eq!(Origin::Default.to_string(), "the default");
}

#[test]
fn resolve_reads_the_given_variables() {
    let env = environment(&[
        ENV_PAIR[0],
        ENV_PAIR[1],
        ("AWS_REGION", "eu-central-1"),
        ("NOT_READ", "x"),
    ]);
    let r = ostrya_rt::block_on(resolve(&Settings::default(), &env)).unwrap();
    assert_eq!(r.profile, "default");
    assert_eq!(r.region.value, "eu-central-1");
    assert_eq!(r.credentials.access_key_id(), ID);
}
