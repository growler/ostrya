//! The settings and the credentials of an S3 endpoint, from the caller, the
//! environment, and the shared AWS files.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};

use super::ini::{self, Entry, IniFile, Section};
use super::sigv4::{region_refusal, valid_region};
use super::{Credentials, DEFAULT_REGION};
use crate::transport::without_userinfo;
use crate::{Error, Result};

/// The largest shared file that [`resolve`] reads: 1 MiB.
const FILE_CAP: u64 = 1 << 20;

/// The environment variables that [`resolve`] reads, other than
/// `USERPROFILE`.
const NAMES: [&str; 11] = [
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "AWS_ENDPOINT_URL_S3",
    "AWS_ENDPOINT_URL",
    "AWS_PROFILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_CONFIG_FILE",
    "HOME",
];

/// The keys of a credential source other than a static key pair. A key that
/// starts with `sso_` is also such a key.
const OTHER_SOURCES: [&str; 4] = [
    "role_arn",
    "source_profile",
    "credential_process",
    "web_identity_token_file",
];

/// The settings of an S3 endpoint that the caller gives.
///
/// A field that is `None` comes from the environment or from the shared AWS
/// files. [`resolve`] states the order of the sources.
///
/// The [`Debug`] output shows the endpoint with no userinfo.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Settings {
    /// The region of the signature scope.
    pub region: Option<String>,
    /// The endpoint URL.
    pub endpoint: Option<String>,
    /// The addressing style of a bucket.
    pub addressing: Option<Addressing>,
    /// The profile of the shared AWS files.
    ///
    /// A profile that the caller names turns off the key pair, the region,
    /// and the endpoint of the environment. [`resolve`] states the rule.
    pub profile: Option<String>,
}

impl fmt::Debug for Settings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Settings")
            .field("region", &self.region)
            .field("endpoint", &self.endpoint.as_deref().map(without_userinfo))
            .field("addressing", &self.addressing)
            .field("profile", &self.profile)
            .finish()
    }
}

/// The environment that [`resolve`] reads.
///
/// The [`Debug`] output shows the names of the variables, and shows each
/// value as `<redacted>`.
#[derive(Clone, Default)]
pub enum Environment {
    /// The variables of the process environment.
    ///
    /// [`resolve`] reads them once, before it reads a file. This is the
    /// default.
    #[default]
    Process,
    /// The variables, given as name and value pairs.
    ///
    /// [`resolve`] does not read the process environment. It ignores a name
    /// that it does not read. Of two entries of one name, the first entry with
    /// a value counts.
    Variables(Vec<(String, String)>),
}

impl fmt::Debug for Environment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Environment::Process => f.write_str("Process"),
            Environment::Variables(variables) => f
                .debug_tuple("Variables")
                .field(&RedactedVariables { variables })
                .finish(),
        }
    }
}

/// The variables of [`Environment::Variables`] in a [`Debug`] output: a list
/// of names and redacted values.
struct RedactedVariables<'a> {
    variables: &'a [(String, String)],
}

impl fmt::Debug for RedactedVariables<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.variables.iter().map(|(name, _)| (name, "<redacted>")))
            .finish()
    }
}

/// The addressing style of a bucket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Addressing {
    /// The bucket is the first segment of the path:
    /// `https://s3.example.com/bucket/key`.
    Path,
    /// The bucket is the first label of the host name:
    /// `https://bucket.s3.example.com/key`.
    Virtual,
}

impl Addressing {
    /// Returns the style of the name `name`: `path` or `virtual`.
    ///
    /// # Examples
    ///
    /// ```
    /// use ostrya_remote::s3::Addressing;
    /// assert_eq!(Addressing::from_name("path"), Some(Addressing::Path));
    /// assert_eq!(Addressing::from_name("auto"), None);
    /// ```
    pub fn from_name(name: &str) -> Option<Addressing> {
        match name {
            "path" => Some(Addressing::Path),
            "virtual" => Some(Addressing::Virtual),
            _ => None,
        }
    }

    /// Returns the name of the style: `path` or `virtual`.
    pub fn as_str(self) -> &'static str {
        match self {
            Addressing::Path => "path",
            Addressing::Virtual => "virtual",
        }
    }
}

/// A value of a setting, and the source that gives it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Setting<T> {
    /// The value.
    pub value: T,
    /// The source of the value.
    pub origin: Origin,
}

/// The source of a setting or of the credentials.
///
/// The [`Display`](fmt::Display) output names the source for a message.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Origin {
    /// A field of [`Settings`].
    Caller,
    /// The environment variable of this name.
    Environment(&'static str),
    /// A key of a shared AWS file.
    SharedFile {
        /// The path of the file.
        path: PathBuf,
        /// The name of the section, without the brackets.
        section: String,
        /// The key. A key of the `s3` sub-section has the prefix `s3.`.
        key: &'static str,
    },
    /// The default of the setting.
    Default,
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Origin::Caller => f.write_str("the caller"),
            Origin::Environment(name) => write!(f, "the environment variable {name}"),
            Origin::SharedFile { path, section, key } => write!(
                f,
                "the key {key} of the section [{section}] of '{}'",
                path.display()
            ),
            Origin::Default => f.write_str("the default"),
        }
    }
}

/// The settings and the credentials of an S3 endpoint that [`resolve`]
/// gives.
///
/// The [`Debug`] output shows the endpoint with no userinfo, and shows the
/// credentials as the [`Debug`] output of [`Credentials`] shows them.
#[derive(Clone)]
#[non_exhaustive]
pub struct Resolved {
    /// The profile of the shared AWS files.
    pub profile: String,
    /// The region of the signature scope.
    pub region: Setting<String>,
    /// The endpoint URL, or `None` if no source gives one.
    pub endpoint: Option<Setting<String>>,
    /// The addressing style, or `None` if no source gives one.
    pub addressing: Option<Setting<Addressing>>,
    /// The key pair.
    pub credentials: Credentials,
    /// The source of the key pair. For the environment, it names
    /// `AWS_ACCESS_KEY_ID`. For a file, it names the key
    /// `aws_access_key_id`.
    pub credentials_origin: Origin,
}

impl fmt::Debug for Resolved {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let endpoint = self.endpoint.as_ref().map(|endpoint| Setting {
            value: without_userinfo(&endpoint.value),
            origin: endpoint.origin.clone(),
        });
        f.debug_struct("Resolved")
            .field("profile", &self.profile)
            .field("region", &self.region)
            .field("endpoint", &endpoint)
            .field("addressing", &self.addressing)
            .field("credentials", &self.credentials)
            .field("credentials_origin", &self.credentials_origin)
            .finish()
    }
}

/// Returns the settings and the credentials of an S3 endpoint, from
/// `settings`, from `environment`, and from the shared AWS files.
///
/// The call reads each file on the blocking pool of `ostrya-rt`.
///
/// # Profile
///
/// The profile is [`Settings::profile`], else `AWS_PROFILE`, else
/// `default`. A profile that the caller names turns off `AWS_ACCESS_KEY_ID`,
/// `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_REGION`,
/// `AWS_DEFAULT_REGION`, `AWS_ENDPOINT_URL_S3`, and `AWS_ENDPOINT_URL`. A
/// profile from `AWS_PROFILE` does not.
///
/// # Order of the sources
///
/// The first source that gives a value counts:
///
/// - The key pair: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and
///   `AWS_SESSION_TOKEN`; then the keys `aws_access_key_id`,
///   `aws_secret_access_key`, and `aws_session_token` of the section
///   `[PROFILE]` of the credentials file; then the same keys of the profile
///   section of the config file.
/// - The region: [`Settings::region`], `AWS_REGION`, `AWS_DEFAULT_REGION`,
///   the key `region` of the profile section of the config file, then
///   [`DEFAULT_REGION`].
/// - The endpoint: [`Settings::endpoint`], `AWS_ENDPOINT_URL_S3`,
///   `AWS_ENDPOINT_URL`, the key `endpoint_url` of the `s3` sub-section of the
///   section `[services NAME]` that the key `services` of the profile names,
///   then the key `endpoint_url` of the profile section.
/// - The addressing style: [`Settings::addressing`], then the key
///   `addressing_style` of the `s3` sub-section of the profile section. The
///   value `auto` gives no style.
///
/// A key pair comes from one source alone. The token goes with the pair of its
/// source.
///
/// An empty variable and an empty value in a file count as unset.
///
/// # Files
///
/// The config file is `AWS_CONFIG_FILE`, else `HOME/.aws/config`. The
/// credentials file is `AWS_SHARED_CREDENTIALS_FILE`, else
/// `HOME/.aws/credentials`. On Windows, `USERPROFILE` takes the place of
/// `HOME` when `HOME` is unset. A leading `~/` of `AWS_CONFIG_FILE` or of
/// `AWS_SHARED_CREDENTIALS_FILE` is the home directory. These two variables
/// apply also to a profile that the caller names.
///
/// The profile section of the config file is `[default]` or
/// `[profile default]` for the profile `default`, and `[profile NAME]` for
/// another profile. The section of the credentials file is `[NAME]`.
///
/// The call reads the credentials file if the environment gives no key pair.
/// It reads the config file if the environment gives no key pair, or if a
/// setting has no value from the caller or from the environment. An absent
/// file is not an error. The call reads at most 1 MiB of each file.
///
/// The call reads static key pairs alone. A profile section that holds
/// `role_arn`, `source_profile`, `credential_process`,
/// `web_identity_token_file`, or a key that starts with `sso_` is refused,
/// unless the environment gives the key pair.
///
/// The call does not read other variables, for example
/// `AWS_IGNORE_CONFIGURED_ENDPOINT_URLS` and `AWS_USE_FIPS_ENDPOINT`.
///
/// # File syntax
///
/// - A file is UTF-8. A line ends with LF or CRLF.
/// - A blank line is skipped. A line whose first non-blank character is `#`
///   or `;` is a comment. A comment cannot follow a value on its line.
/// - A line with no indent that starts with `[` opens a section. The name is
///   the text between `[` and `]`, without the white space around it.
/// - A line with no indent in a section is a key and a value. It splits at
///   the first `=` or `:`. The key is lowercased. White space around the key
///   and around the value is removed.
/// - An indented line after a key with an empty value is a key and a value of
///   a sub-section of that key, for example `addressing_style` under `s3`.
/// - The call checks the syntax of each section, also of a section that it
///   does not read.
///
/// These are refused: a key before the first section, an indented line that
/// continues a value, an indented line with no key before it, a malformed
/// section header, a line with no `=` and no `:`, a section twice in a file,
/// and a key twice in a section or in a sub-section.
///
/// # Errors
///
/// - [`Error::InvalidInput`] if no source gives a key pair. The message names
///   the profile, and states for each source why it gives none.
/// - [`Error::InvalidInput`] if a value is refused. The message names the
///   source, and holds no secret and no session token. These are refused:
///   - a region that [`SigV4::new`](super::SigV4::new) refuses
///   - an empty profile name, or a profile name with `[`, `]`, or a control
///     character
///   - one of `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` without the
///     other, or `AWS_SESSION_TOKEN` without the two, and the same in a file
///     section
///   - a value of a key pair that [`Credentials::new`] refuses
///   - a key of a credential source other than a static key pair
///   - an `addressing_style` other than `path`, `virtual`, and `auto`
///   - a key `services` that names no section, or an `s3` key with a value
///     in place of a sub-section
///   - a section of a profile in the config file as `[default]` and as
///     `[profile default]`
///   - a variable that is not UTF-8, other than a path
///   - a file that is larger than 1 MiB. The message names the file.
///   - a line that [File syntax](resolve#file-syntax) refuses. The message
///     names the file and the line.
/// - [`Error::Io`] if a file exists and cannot be read. The message names the
///   file and its path.
///
/// # Examples
///
/// ```no_run
/// use ostrya_remote::s3::{Environment, Settings, SigV4, resolve};
/// # async fn run() -> ostrya_remote::Result<()> {
/// let settings = Settings {
///     profile: Some("backup".into()),
///     ..Settings::default()
/// };
/// let resolved = resolve(&settings, &Environment::Process).await?;
/// println!("region {} from {}", resolved.region.value, resolved.region.origin);
/// let signer = SigV4::new(resolved.credentials, &resolved.region.value)?;
/// # let _ = signer;
/// # Ok(()) }
/// ```
pub async fn resolve(settings: &Settings, environment: &Environment) -> Result<Resolved> {
    let windows = cfg!(windows);
    let vars = Vars::of(environment, windows);
    let settings = settings.clone();
    ostrya_rt::unblock(move || resolve_with(&settings, &vars, windows)).await
}

/// The values of the variables that [`resolve`] reads.
struct Vars {
    values: Vec<(&'static str, OsString)>,
}

impl Vars {
    /// Returns the variables of `environment`. `USERPROFILE` is read if
    /// `windows` is `true`.
    fn of(environment: &Environment, windows: bool) -> Vars {
        let names = NAMES.into_iter().chain(windows.then_some("USERPROFILE"));
        let values = match environment {
            Environment::Process => names
                .filter_map(|name| Some((name, std::env::var_os(name)?)))
                .collect(),
            Environment::Variables(variables) => names
                .filter_map(|name| {
                    variables
                        .iter()
                        .find(|(n, v)| n == name && !v.is_empty())
                        .map(|(_, v)| (name, OsString::from(v)))
                })
                .collect(),
        };
        Vars { values }
    }

    /// Returns the value of `name`, or `None` if it is unset or empty.
    fn os(&self, name: &str) -> Option<&OsStr> {
        self.values
            .iter()
            .find(|(n, v)| *n == name && !v.is_empty())
            .map(|(_, v)| v.as_os_str())
    }

    /// Returns the value of `name` as text, or `None` if it is unset or empty.
    fn text(&self, name: &str) -> Result<Option<&str>> {
        self.os(name)
            .map(|value| {
                value.to_str().ok_or_else(|| {
                    Error::InvalidInput(format!("the environment variable {name} is not UTF-8"))
                })
            })
            .transpose()
    }
}

/// The state of one shared file.
enum Shared {
    /// Neither a variable nor the home directory gives the path of the file,
    /// or the call does not need the file.
    NotLocated,
    /// The variable gives a path that starts with `~/`, and no variable gives
    /// the home directory.
    NoHome,
    /// No file is at the path.
    Absent(PathBuf),
    /// The file is read.
    Read(IniFile),
}

impl Shared {
    fn file(&self) -> Option<&IniFile> {
        match self {
            Shared::Read(file) => Some(file),
            _ => None,
        }
    }
}

/// Resolves the settings as [`resolve`] does, with the values of the
/// variables in `vars`, and with the Windows rule of the home directory if
/// `windows` is `true`.
fn resolve_with(settings: &Settings, vars: &Vars, windows: bool) -> Result<Resolved> {
    let named = settings.profile.is_some();
    if let Some(region) = &settings.region {
        check_region(region, &Origin::Caller)?;
    }
    let profile = match &settings.profile {
        Some(profile) => {
            check_profile(profile, "the profile of the caller")?;
            profile.clone()
        }
        None => match vars.text("AWS_PROFILE")? {
            Some(profile) => {
                check_profile(profile, "the environment variable AWS_PROFILE")?;
                profile.to_owned()
            }
            None => "default".to_owned(),
        },
    };

    let env_pair = if named { None } else { env_pair(vars)? };

    let mut region = settings.region.clone().map(|value| Setting {
        value,
        origin: Origin::Caller,
    });
    let mut endpoint = settings.endpoint.clone().map(|value| Setting {
        value,
        origin: Origin::Caller,
    });
    let mut addressing = settings.addressing.map(|value| Setting {
        value,
        origin: Origin::Caller,
    });
    if !named {
        if region.is_none() {
            region = env_setting(vars, &["AWS_REGION", "AWS_DEFAULT_REGION"])?;
            if let Some(region) = &region {
                check_region(&region.value, &region.origin)?;
            }
        }
        if endpoint.is_none() {
            endpoint = env_setting(vars, &["AWS_ENDPOINT_URL_S3", "AWS_ENDPOINT_URL"])?;
        }
    }

    let home = vars
        .os("HOME")
        .or_else(|| {
            if windows {
                vars.os("USERPROFILE")
            } else {
                None
            }
        })
        .map(PathBuf::from);
    let need_config =
        env_pair.is_none() || region.is_none() || endpoint.is_none() || addressing.is_none();
    let config = if need_config {
        let place = place(vars, "AWS_CONFIG_FILE", home.as_deref(), "config");
        read_place(place, "shared config file")?
    } else {
        Shared::NotLocated
    };
    let config_section = match config.file() {
        Some(file) => profile_section(file, &profile)?,
        None => None,
    };

    if let (Some(file), Some(section)) = (config.file(), config_section) {
        if region.is_none()
            && let Some(entry) = section.value("region")
        {
            let origin = shared(file, section, "region");
            check_region(&entry.value, &origin)?;
            region = Some(Setting {
                value: entry.value.clone(),
                origin,
            });
        }
        if endpoint.is_none() {
            endpoint = file_endpoint(file, section)?;
        }
        if addressing.is_none() {
            addressing = file_addressing(file, section)?;
        }
    }
    let region = region.unwrap_or_else(|| Setting {
        value: DEFAULT_REGION.to_owned(),
        origin: Origin::Default,
    });

    let (credentials, credentials_origin) = match env_pair {
        Some(pair) => pair,
        None => {
            let place = place(
                vars,
                "AWS_SHARED_CREDENTIALS_FILE",
                home.as_deref(),
                "credentials",
            );
            let creds = read_place(place, "shared credentials file")?;
            let creds_section = creds.file().and_then(|file| file.section(&profile));
            if let (Some(file), Some(section)) = (creds.file(), creds_section) {
                check_static(file, section)?;
            }
            if let (Some(file), Some(section)) = (config.file(), config_section) {
                check_static(file, section)?;
            }
            let from_creds = match (creds.file(), creds_section) {
                (Some(file), Some(section)) => file_pair(file, section)?,
                _ => None,
            };
            let from_config = match (from_creds.is_none(), config.file(), config_section) {
                (true, Some(file), Some(section)) => file_pair(file, section)?,
                _ => None,
            };
            match from_creds.or(from_config) {
                Some(pair) => pair,
                None => {
                    return Err(no_credentials(
                        &profile,
                        named,
                        windows,
                        (&creds, creds_section),
                        (&config, config_section),
                    ));
                }
            }
        }
    };

    Ok(Resolved {
        profile,
        region,
        endpoint,
        addressing,
        credentials,
        credentials_origin,
    })
}

/// Refuses `region` if [`SigV4::new`](super::SigV4::new) refuses it. The
/// message names `origin`.
fn check_region(region: &str, origin: &Origin) -> Result<()> {
    if valid_region(region) {
        Ok(())
    } else {
        Err(Error::InvalidInput(region_refusal(
            region,
            &origin.to_string(),
        )))
    }
}

/// Refuses the profile name `profile` if it is empty, or if it holds `[`,
/// `]`, or a control character. The message names `source`.
fn check_profile(profile: &str, source: &str) -> Result<()> {
    if profile.is_empty()
        || profile
            .chars()
            .any(|c| c == '[' || c == ']' || c.is_control())
    {
        return Err(Error::InvalidInput(format!(
            "{source}: the profile name {profile:?} is empty, or holds '[', ']', or a control character"
        )));
    }
    Ok(())
}

/// Returns the key pair of the environment, or `None` if the environment
/// sets none of its variables.
fn env_pair(vars: &Vars) -> Result<Option<(Credentials, Origin)>> {
    let id = vars.text("AWS_ACCESS_KEY_ID")?;
    let secret = vars.text("AWS_SECRET_ACCESS_KEY")?;
    let token = vars.text("AWS_SESSION_TOKEN")?;
    match (id, secret) {
        (Some(id), Some(secret)) => {
            let credentials = Credentials::checked(id.into(), secret.into(), token.map(Into::into))
                .map_err(|why| {
                    Error::InvalidInput(format!(
                        "the environment variables AWS_ACCESS_KEY_ID, \
                             AWS_SECRET_ACCESS_KEY, and AWS_SESSION_TOKEN: {why}"
                    ))
                })?;
            Ok(Some((
                credentials,
                Origin::Environment("AWS_ACCESS_KEY_ID"),
            )))
        }
        (Some(_), None) => Err(Error::InvalidInput(
            "the environment variable AWS_ACCESS_KEY_ID is set, and \
             AWS_SECRET_ACCESS_KEY is not"
                .into(),
        )),
        (None, Some(_)) => Err(Error::InvalidInput(
            "the environment variable AWS_SECRET_ACCESS_KEY is set, and \
             AWS_ACCESS_KEY_ID is not"
                .into(),
        )),
        (None, None) if token.is_some() => Err(Error::InvalidInput(
            "the environment variable AWS_SESSION_TOKEN is set, and \
             AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are not"
                .into(),
        )),
        (None, None) => Ok(None),
    }
}

/// Returns the value of the first variable of `names` that is set, as a
/// setting.
fn env_setting(vars: &Vars, names: &[&'static str]) -> Result<Option<Setting<String>>> {
    for &name in names {
        if let Some(value) = vars.text(name)? {
            return Ok(Some(Setting {
                value: value.to_owned(),
                origin: Origin::Environment(name),
            }));
        }
    }
    Ok(None)
}

/// Returns the path of the shared file that the variable `variable` names,
/// else of the file `name` in the directory `.aws` of `home`.
///
/// A leading `~/` of the variable is `home`. An error is
/// [`Shared::NoHome`] if the variable needs `home`, and [`Shared::NotLocated`]
/// if the variable is not set. Each is for a `home` that is `None`.
fn place(
    vars: &Vars,
    variable: &str,
    home: Option<&Path>,
    name: &str,
) -> std::result::Result<PathBuf, Shared> {
    match vars.os(variable) {
        Some(value) => match value.to_str().and_then(|text| text.strip_prefix("~/")) {
            Some(rest) => home.map(|home| home.join(rest)).ok_or(Shared::NoHome),
            None => Ok(PathBuf::from(value)),
        },
        None => home
            .map(|home| home.join(".aws").join(name))
            .ok_or(Shared::NotLocated),
    }
}

/// Reads and parses the shared file at `place`, which `what` names.
fn read_place(place: std::result::Result<PathBuf, Shared>, what: &str) -> Result<Shared> {
    let path = match place {
        Ok(path) => path,
        Err(state) => return Ok(state),
    };
    match read_shared(&path, what)? {
        Some(bytes) => Ok(Shared::Read(ini::parse(&path, &bytes)?)),
        None => Ok(Shared::Absent(path)),
    }
}

/// Returns the bytes of the shared file at `path`, which `what` names, or
/// `None` if no file is at the path.
///
/// The function reads at most 1 MiB and one byte of the file. A failure is an
/// [`Error::Io`] with the kind of the failure. Its message names `what` and
/// the path, and holds no byte of the file.
fn read_shared(path: &Path, what: &str) -> Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    let read =
        std::fs::File::open(path).and_then(|file| file.take(FILE_CAP + 1).read_to_end(&mut bytes));
    match read {
        Ok(_) if bytes.len() as u64 > FILE_CAP => Err(Error::InvalidInput(format!(
            "the {what} '{}' is over 1 MiB",
            path.display()
        ))),
        Ok(_) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::Io(std::io::Error::new(
            e.kind(),
            format!("the {what} '{}': {e}", path.display()),
        ))),
    }
}

/// Returns the section of the profile `profile` in the config file `file`.
fn profile_section<'a>(file: &'a IniFile, profile: &str) -> Result<Option<&'a Section>> {
    let named = file.section(&format!("profile {profile}"));
    if profile != "default" {
        return Ok(named);
    }
    match (file.section("default"), named) {
        (Some(plain), Some(named)) => Err(Error::InvalidInput(format!(
            "{}:{}: the profile default has the section [default] and the section \
             [profile default]",
            file.path.display(),
            plain.line.max(named.line)
        ))),
        (plain, named) => Ok(plain.or(named)),
    }
}

/// Returns the origin of `key` in `section` of `file`.
fn shared(file: &IniFile, section: &Section, key: &'static str) -> Origin {
    Origin::SharedFile {
        path: file.path.clone(),
        section: section.name.clone(),
        key,
    }
}

/// Returns the refusal of the line `line` of `section` of `file`, for the
/// reason `why`.
fn refusal(file: &IniFile, section: &Section, line: usize, why: &str) -> Error {
    Error::InvalidInput(format!(
        "{}:{line}: the section [{}]: {why}",
        file.path.display(),
        section.name
    ))
}

/// Returns the `s3` sub-section of `section`, or `None` if the section has no
/// key `s3`. A key `s3` with a value is refused.
fn s3_entry<'a>(file: &IniFile, section: &'a Section) -> Result<Option<&'a Entry>> {
    match section.entry("s3") {
        Some(entry) if !entry.value.is_empty() => Err(refusal(
            file,
            section,
            entry.line,
            "the key s3 has a value, and it must open a sub-section",
        )),
        entry => Ok(entry),
    }
}

/// Returns the endpoint of the profile section `section` of the config file
/// `file`.
fn file_endpoint(file: &IniFile, section: &Section) -> Result<Option<Setting<String>>> {
    if let Some(services) = section.value("services") {
        let name = format!("services {}", services.value);
        let Some(target) = file.section(&name) else {
            return Err(refusal(
                file,
                section,
                services.line,
                &format!("the key services names the section [{name}], which is absent"),
            ));
        };
        if let Some((value, _)) =
            s3_entry(file, target)?.and_then(|s3| s3.sub_value("endpoint_url"))
        {
            return Ok(Some(Setting {
                value: value.to_owned(),
                origin: shared(file, target, "s3.endpoint_url"),
            }));
        }
    }
    Ok(section.value("endpoint_url").map(|entry| Setting {
        value: entry.value.clone(),
        origin: shared(file, section, "endpoint_url"),
    }))
}

/// Returns the addressing style of the profile section `section` of the
/// config file `file`.
fn file_addressing(file: &IniFile, section: &Section) -> Result<Option<Setting<Addressing>>> {
    let Some((value, line)) =
        s3_entry(file, section)?.and_then(|s3| s3.sub_value("addressing_style"))
    else {
        return Ok(None);
    };
    if value == "auto" {
        return Ok(None);
    }
    match Addressing::from_name(value) {
        Some(style) => Ok(Some(Setting {
            value: style,
            origin: shared(file, section, "s3.addressing_style"),
        })),
        None => Err(refusal(
            file,
            section,
            line,
            &format!("s3.addressing_style {value:?} is not path, virtual, or auto"),
        )),
    }
}

/// Refuses `section` of `file` if it holds a key of a credential source other
/// than a static key pair.
fn check_static(file: &IniFile, section: &Section) -> Result<()> {
    let other = section
        .entries
        .iter()
        .find(|entry| OTHER_SOURCES.contains(&entry.key.as_str()) || entry.key.starts_with("sso_"));
    match other {
        Some(entry) => Err(refusal(
            file,
            section,
            entry.line,
            &format!(
                "the key {} names a credential source other than a static key pair, \
                 which is not read",
                entry.key
            ),
        )),
        None => Ok(()),
    }
}

/// Returns the key pair of `section` of `file`, or `None` if the section
/// holds none of its keys.
fn file_pair(file: &IniFile, section: &Section) -> Result<Option<(Credentials, Origin)>> {
    let id = section.value("aws_access_key_id");
    let secret = section.value("aws_secret_access_key");
    let token = section.value("aws_session_token");
    match (id, secret) {
        (Some(id), Some(secret)) => {
            let credentials = Credentials::checked(
                id.value.clone(),
                secret.value.clone(),
                token.map(|token| token.value.clone()),
            )
            .map_err(|why| refusal(file, section, id.line, why))?;
            Ok(Some((
                credentials,
                shared(file, section, "aws_access_key_id"),
            )))
        }
        (Some(entry), None) => Err(refusal(
            file,
            section,
            entry.line,
            "the key aws_access_key_id is set, and aws_secret_access_key is not",
        )),
        (None, Some(entry)) => Err(refusal(
            file,
            section,
            entry.line,
            "the key aws_secret_access_key is set, and aws_access_key_id is not",
        )),
        (None, None) => match token {
            Some(entry) => Err(refusal(
                file,
                section,
                entry.line,
                "the key aws_session_token is set, and aws_access_key_id and \
                 aws_secret_access_key are not",
            )),
            None => Ok(None),
        },
    }
}

/// Returns the refusal of a profile with no key pair. The message states for
/// each source why it gives none.
fn no_credentials(
    profile: &str,
    named: bool,
    windows: bool,
    creds: (&Shared, Option<&Section>),
    config: (&Shared, Option<&Section>),
) -> Error {
    let environment = if named {
        "the environment: not read, because the caller names the profile"
    } else {
        "the environment: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are not set"
    };
    let config_name = if profile == "default" {
        "default".to_owned()
    } else {
        format!("profile {profile}")
    };
    Error::InvalidInput(format!(
        "no S3 credentials for the profile '{profile}': {environment}; {}; {}",
        file_state(
            "shared credentials file",
            "AWS_SHARED_CREDENTIALS_FILE",
            windows,
            creds,
            profile
        ),
        file_state(
            "shared config file",
            "AWS_CONFIG_FILE",
            windows,
            config,
            &config_name
        ),
    ))
}

/// Returns why the shared file `what`, whose path the variable `variable`
/// gives, gives no key pair. `name` is the section of the profile.
fn file_state(
    what: &str,
    variable: &str,
    windows: bool,
    (shared, section): (&Shared, Option<&Section>),
    name: &str,
) -> String {
    let home = if windows {
        "HOME and USERPROFILE are"
    } else {
        "HOME is"
    };
    match (shared, section) {
        (Shared::NotLocated, _) => {
            format!("the {what}: not located, because {variable} gives no path and {home} not set")
        }
        (Shared::NoHome, _) => format!(
            "the {what}: not located, because {variable} starts with '~/' and {home} not set"
        ),
        (Shared::Absent(path), _) => format!("the {what} '{}': absent", path.display()),
        (Shared::Read(file), None) => {
            format!("the {what} '{}': no section [{name}]", file.path.display())
        }
        (Shared::Read(file), Some(section)) => format!(
            "the {what} '{}': the section [{}] has no key pair",
            file.path.display(),
            section.name
        ),
    }
}

#[cfg(test)]
mod tests;
