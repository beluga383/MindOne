//! MindOne 本地执行面的模型与推理引擎能力。

pub mod download;
pub mod hardware;
pub mod install;
pub mod logging;
pub mod model;
pub mod process;
pub mod validation;

pub use download::{
    download_model, probe_model_download, DownloadProgress, ModelDownloadProbeReport,
    ModelDownloadProbeRequest, ModelDownloadRequest, ModelPlatform,
};
pub use hardware::{detect_hardware, GpuProfile, HardwareProfile};
pub use install::{
    EngineCapability, EngineFileIntegrity, EngineInstaller, EngineName, EngineRegistry,
    InstalledEngine,
};
pub use logging::{
    consume_log_monitor_ready, open_log_append_no_follow, read_process_start_marker,
    run_log_monitor, LogMonitorConfig, LogMonitorError, LogMonitorExit, DEFAULT_LOG_CHECK_INTERVAL,
    DEFAULT_LOG_ROTATE_BYTES, LOG_GENERATIONS,
};
pub use model::{ModelRecord, ModelRegistry};
pub use process::{
    is_audited_managed_serve_release, managed_share_slot_id, zeroize_owned_buffer, CleanupReport,
    ServeCleanupStatus, ServeManager, ServeRequest, ServeRuntimeState, ServeStatus,
    AUDITED_MANAGED_LLAMA_CPP_RELEASE, MANAGED_LLAMA_PARALLEL_SLOTS, MANAGED_LLAMA_SLOT_ID,
    MANAGED_SHARE_MAX_CONCURRENT,
};
pub use validation::{
    parse_gguf_split_filename, validate_gguf_split_reports, validate_model, GgufSplitFileName,
    GgufSplitInfo, ModelFormat, ValidationError, ValidationReport,
};
