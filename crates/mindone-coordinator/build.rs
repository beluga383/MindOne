use std::{env, ffi::OsStr, fs, path::PathBuf};

fn main() -> Result<(), String> {
    generate_embedded_migrations()
}

fn generate_embedded_migrations() -> Result<(), String> {
    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR")
            .ok_or_else(|| "CARGO_MANIFEST_DIR is unavailable".to_owned())?,
    );
    let migrations_dir = manifest_dir.join("../../migrations");
    let migrations_dir = migrations_dir
        .canonicalize()
        .map_err(|error| format!("cannot resolve {}: {error}", migrations_dir.display()))?;
    println!("cargo:rerun-if-changed={}", migrations_dir.display());

    let mut entries = fs::read_dir(&migrations_dir)
        .map_err(|error| format!("cannot read {}: {error}", migrations_dir.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot enumerate {}: {error}", migrations_dir.display()))?;
    entries.sort_by_key(|entry| entry.file_name());

    let mut generated = String::from(
        "use std::{borrow::Cow, sync::LazyLock};\n\
         use sqlx::migrate::{Migration, MigrationType, Migrator};\n\n\
         pub static MIGRATOR: LazyLock<Migrator> = LazyLock::new(|| Migrator {\n\
         migrations: Cow::Owned(vec![\n",
    );
    let mut versions = Vec::new();

    for entry in entries {
        let metadata = entry
            .metadata()
            .map_err(|error| format!("cannot stat {}: {error}", entry.path().display()))?;
        if !metadata.is_file() || entry.path().extension() != Some(OsStr::new("sql")) {
            continue;
        }
        let file_name = entry
            .file_name()
            .into_string()
            .map_err(|_| "migration filenames must be valid UTF-8".to_owned())?;
        let (version, description, migration_type) = parse_filename(&file_name)?;
        versions.push(version);
        let sql = fs::read_to_string(entry.path())
            .map_err(|error| format!("cannot read {}: {error}", entry.path().display()))?;
        let no_tx = sql.starts_with("-- no-transaction");
        let canonical_path = entry
            .path()
            .canonicalize()
            .map_err(|error| format!("cannot resolve {}: {error}", entry.path().display()))?;
        generated.push_str(&format!(
            "Migration::new({version}, Cow::Borrowed({description:?}), \
             MigrationType::{migration_type}, Cow::Borrowed(include_str!({path:?})), {no_tx}),\n",
            path = canonical_path.to_string_lossy(),
        ));
    }
    if versions.is_empty() {
        return Err("no migrations were found".to_owned());
    }
    if !versions.windows(2).all(|pair| pair[0] <= pair[1]) {
        return Err("migration versions must be ordered".to_owned());
    }
    generated.push_str("]),\nignore_missing: false,\nlocking: true,\nno_tx: false,\n});\n");

    let output =
        PathBuf::from(env::var_os("OUT_DIR").ok_or_else(|| "OUT_DIR is unavailable".to_owned())?)
            .join("embedded_migrations.rs");
    fs::write(&output, generated)
        .map_err(|error| format!("cannot write {}: {error}", output.display()))?;
    Ok(())
}

fn parse_filename(file_name: &str) -> Result<(i64, String, &'static str), String> {
    let (version, remainder) = file_name.split_once('_').ok_or_else(|| {
        format!("invalid migration filename {file_name:?}; expected <VERSION>_<DESCRIPTION>.sql")
    })?;
    let version = version
        .parse::<i64>()
        .map_err(|_| format!("invalid migration version in {file_name:?}"))?;
    if version <= 0 {
        return Err(format!(
            "migration version must be positive in {file_name:?}"
        ));
    }
    let (description, migration_type) = if let Some(value) = remainder.strip_suffix(".up.sql") {
        (value, "ReversibleUp")
    } else if let Some(value) = remainder.strip_suffix(".down.sql") {
        (value, "ReversibleDown")
    } else if let Some(value) = remainder.strip_suffix(".sql") {
        (value, "Simple")
    } else {
        return Err(format!("invalid migration filename {file_name:?}"));
    };
    if description.is_empty() {
        return Err(format!("migration description is empty in {file_name:?}"));
    }
    Ok((version, description.replace('_', " "), migration_type))
}
