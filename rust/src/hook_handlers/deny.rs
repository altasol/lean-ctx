use std::io::Read;

use super::HOOK_STDIN_TIMEOUT;

const BINARY_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "ico", "bmp", "svg", "pdf", "zip", "tar", "gz", "bz2",
    "xz", "7z", "rar", "woff", "woff2", "ttf", "otf", "eot", "mp3", "mp4", "wav", "avi", "mov",
    "mkv", "so", "dylib", "dll", "exe", "bin", "o", "a", "class", "pyc", "wasm",
];

/// Handle the `lean-ctx hook deny` subcommand.
///
/// Called by PreToolUse hooks in Replace mode. Denies native Read/Grep/Glob/Shell
/// calls unless an exception applies (binary files, MCP down, etc.).
///
/// Output format matches both Claude Code and Cursor hook protocols.
pub fn handle_deny() {
    let stdin_payload = read_stdin_with_timeout();
    // Debug aid: dump the raw hook payload so unknown tool_name shapes
    // (e.g. Devin's MCP wrapper) can be inspected. All current builds are
    // debug-only, so dump unconditionally. Written to ~/dev/altasol/ to
    // avoid sandbox/jail write restrictions on /tmp and config dirs.
    if let Some(home) = dirs::home_dir() {
        let out = home.join("dev/altasol/deny-payload.json");
        let _ = std::fs::write(&out, &stdin_payload);
    }
    let tool_name = extract_tool_name(&stdin_payload);
    let file_path = extract_file_path(&stdin_payload);

    // Devin's native MCP hook format: agent_action_name="pre_mcp_tool_use"
    // with tool_info.mcp_tool_name. This is always an MCP tool call (ctx_*,
    // linear, github, ...), never a native Read/Grep/Glob/Shell, so allow
    // unconditionally — the deny hook's scope is native-tool redirection.
    if is_devin_mcp_action(&stdin_payload) {
        print_allow();
        return;
    }

    // #805: deny Write/Edit payloads that contain compression markers.
    // These indicate the agent is writing compressed ctx_read output to disk.
    if is_write_tool(&tool_name) {
        if !is_compression_guard_disabled()
            && let Some(content) = extract_write_content(&stdin_payload)
            && has_compression_markers(&content)
        {
            print_deny_compression_markers(&tool_name);
        }
        print_allow();
        return;
    }

    if should_allow(&tool_name, file_path.as_deref()) {
        print_allow();
    } else {
        print_smart_deny(&tool_name, &stdin_payload);
    }
}

fn should_allow(tool_name: &str, file_path: Option<&str>) -> bool {
    if super::is_disabled() {
        return true;
    }

    // GH #1329: lean-ctx MCP tools must never be blocked by the deny hook.
    // Devin (ex-Windsurf) routes MCP calls through its own PreToolUse
    // pipeline, so ctx_* tool invocations hit the deny hook. Allow them.
    if is_lean_ctx_tool(tool_name) {
        return true;
    }

    if !is_mcp_server_reachable() {
        return true;
    }

    if file_path.is_some_and(is_binary_file) {
        return true;
    }

    // GH #1228: Claude/CodeBuddy auto memory must use native Read/Edit even
    // when Replace-mode deny hooks are installed.
    if file_path.is_some_and(|p| {
        crate::core::pathjail::is_harness_auto_memory_path(std::path::Path::new(p))
    }) {
        return true;
    }

    if is_replace_mode_disabled() {
        return true;
    }

    false
}

fn is_lean_ctx_tool(tool_name: &str) -> bool {
    tool_name.starts_with("ctx_") || tool_name == "shell" || is_mcp_wrapper(tool_name)
}

/// Recognise MCP wrapper tool names that carry the real tool name in
/// `input.tool_name` (Devin's `mcp_call_tool` and client-namespaced variants).
///
/// The deny hook's scope is native-tool redirection (Read/Grep/Glob/Shell →
/// ctx_*). `mcp_call_tool` is Devin's MCP bridge: its inner tool_name is
/// always an MCP tool (ctx_*, linear, github, wallaby, ...), never a native
/// Read. Allowing the wrapper unconditionally cannot bypass the deny hook
/// because native tools are not reachable through it. See GH #1329.
fn is_mcp_wrapper(tool_name: &str) -> bool {
    let bare = tool_name
        .rsplit("__")
        .next()
        .unwrap_or(tool_name)
        .rsplit([':', '/'])
        .next()
        .unwrap_or(tool_name);
    bare == "mcp_call_tool" || bare == "mcp_call_tool_with_request_id"
}

/// Detect Devin's native MCP hook format.
///
/// Devin sends MCP tool calls as:
/// ```json
/// {"agent_action_name":"pre_mcp_tool_use","tool_info":{"mcp_server_name":"lean-ctx","mcp_tool_name":"ctx_tree",...}}
/// ```
/// This is always an MCP tool call — never a native Read/Grep/Glob/Shell —
/// so the deny hook allows it unconditionally. See GH #1329.
fn is_devin_mcp_action(payload: &str) -> bool {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(payload) else {
        return false;
    };
    json.get("agent_action_name")
        .and_then(serde_json::Value::as_str)
        == Some("pre_mcp_tool_use")
}

fn is_mcp_server_reachable() -> bool {
    let path = crate::daemon::daemon_pid_path();
    if !path.exists() {
        return true;
    }
    if let Ok(pid_str) = std::fs::read_to_string(&path)
        && let Ok(pid) = pid_str.trim().parse::<u32>()
        && !crate::ipc::process::is_alive(pid)
    {
        return false;
    }
    true
}

fn is_replace_mode_disabled() -> bool {
    matches!(
        std::env::var("LEAN_CTX_REPLACE_MODE"),
        Ok(v) if v.trim() == "0" || v.trim().eq_ignore_ascii_case("off")
    )
}

fn is_binary_file(path: &str) -> bool {
    if let Some(ext) = path.rsplit('.').next() {
        return BINARY_EXTENSIONS.contains(&ext.to_lowercase().as_str());
    }
    false
}

fn extract_tool_name(payload: &str) -> String {
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(payload) {
        // Claude Code / generic: top-level "tool_name".
        if let Some(name) = json.get("tool_name").and_then(serde_json::Value::as_str) {
            return name.to_string();
        }
        // Cursor: hookSpecificInput.toolName.
        if let Some(name) = json
            .get("hookSpecificInput")
            .and_then(|h| h.get("toolName"))
            .and_then(serde_json::Value::as_str)
        {
            return name.to_string();
        }
        // Devin: hookSpecificInput.tool (note: "tool", not "toolName").
        if let Some(name) = json
            .get("hookSpecificInput")
            .and_then(|h| h.get("tool"))
            .and_then(serde_json::Value::as_str)
        {
            return name.to_string();
        }
    }
    "unknown".to_string()
}

fn extract_file_path(payload: &str) -> Option<String> {
    let json: serde_json::Value = serde_json::from_str(payload).ok()?;

    let input = json
        .get("input")
        .or_else(|| json.get("hookSpecificInput").and_then(|h| h.get("input")));

    if let Some(input) = input {
        for key in ["file_path", "path", "filePath"] {
            if let Some(path) = input.get(key).and_then(serde_json::Value::as_str) {
                return Some(path.to_string());
            }
        }
    }
    None
}

fn is_write_tool(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "Write"
            | "write"
            | "WriteFile"
            | "Edit"
            | "edit"
            | "MultiEdit"
            | "StrReplace"
            | "str_replace"
            | "EditNotebook"
    )
}

fn is_compression_guard_disabled() -> bool {
    std::env::var("LEAN_CTX_ALLOW_COMPRESSED_WRITE")
        .is_ok_and(|v| v.trim() == "1" || v.trim().eq_ignore_ascii_case("true"))
}

fn has_compression_markers(content: &str) -> bool {
    if content.contains("[lean-ctx:") || content.contains("--- lean-ctx:") {
        return true;
    }
    // Detect ctx_read build_header corruption (#1323): "filename.ext NNL"
    // followed by " deps " or " exports " on the next line.
    static HEADER_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"(?m)^\S+\.\w+ \d+L\n (?:deps|exports) ").unwrap()
    });
    static MAP_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"(?m)(?:@L\d+-\d+|^\s+API:\s*$|^\S+\.\w+ \d+L\n\s+deps:)").unwrap()
    });
    HEADER_RE.is_match(content) || MAP_RE.is_match(content)
}

fn extract_write_content(payload: &str) -> Option<String> {
    let json: serde_json::Value = serde_json::from_str(payload).ok()?;
    let input = json
        .get("input")
        .or_else(|| json.get("hookSpecificInput").and_then(|h| h.get("input")))?;

    let mut combined = String::new();

    // Check all common content field names across tool variants.
    // For StrReplace we must check BOTH old_string and new_string:
    // if old_string contains markers, the agent read a compressed file
    // and the resulting write will embed markers in the file. (#1302)
    for key in [
        "content",
        "contents",
        "file_text",
        "text",
        "new_string",
        "new_text",
        "old_string",
        "old_text",
    ] {
        if let Some(text) = input.get(key).and_then(serde_json::Value::as_str) {
            combined.push_str(text);
            combined.push('\n');
        }
    }

    // MultiEdit: check edits array for old_text/new_text
    if let Some(edits) = input.get("edits").and_then(|v| v.as_array()) {
        for edit in edits {
            for key in ["old_text", "oldText", "new_text", "newText"] {
                if let Some(t) = edit.get(key).and_then(serde_json::Value::as_str) {
                    combined.push_str(t);
                    combined.push('\n');
                }
            }
        }
    }

    if combined.is_empty() {
        None
    } else {
        Some(combined)
    }
}

fn print_deny_compression_markers(tool_name: &str) {
    let msg = format!(
        "Blocked {tool_name}: payload contains lean-ctx compression markers \
         ([lean-ctx: omitted ...] or similar). Writing compressed ctx_read \
         output to disk corrupts files. Use ctx_read(raw=true) or ctx_expand \
         to recover full content before editing. \
         Set LEAN_CTX_ALLOW_COMPRESSED_WRITE=1 to override."
    );
    let output = serde_json::json!({
        // Grok PreToolUse decision field.
        "decision": "deny",
        "reason": msg,
        "permission": "deny",
        "user_message": msg
    });
    println!("{output}");
    std::process::exit(2);
}

/// Build a smart deny message that includes the exact ctx_* call with mapped arguments.
/// This reduces cognitive load for the LLM and prevents instruction drift.
fn smart_deny_message(tool_name: &str, payload: &str) -> String {
    let args = extract_tool_args(payload);
    match tool_name {
        "Read" | "read" | "ReadFile" | "read_file" => build_ctx_read_hint(&args),
        "Grep" | "grep" | "Search" => build_ctx_search_hint(&args),
        "Glob" | "glob" | "list_dir" => build_ctx_glob_hint(&args),
        "Shell" | "Bash" | "bash" | "run_terminal_command" => build_ctx_shell_hint(&args),
        _ => {
            // Include a prefix of the raw payload so unknown tool_name shapes
            // (e.g. Devin's MCP wrapper) can be diagnosed from the deny message
            // alone. Truncate to keep the message LLM-friendly.
            let prefix: String = payload.chars().take(300).collect();
            format!(
                "[DENIED] tool_name=\"{tool_name}\" blocked. Use the equivalent ctx_* tool — \
                 lean-ctx replace mode is active. (If this is an MCP wrapper, report \
                 this tool_name so is_mcp_wrapper can be extended.) \
                 payload_prefix={prefix}"
            )
        }
    }
}

fn extract_tool_args(payload: &str) -> serde_json::Map<String, serde_json::Value> {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(payload) else {
        return serde_json::Map::new();
    };
    json.get("input")
        .or_else(|| json.get("hookSpecificInput").and_then(|h| h.get("input")))
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default()
}

fn build_ctx_read_hint(args: &serde_json::Map<String, serde_json::Value>) -> String {
    let mut parts = Vec::new();
    if let Some(path) = args
        .get("path")
        .or_else(|| args.get("file_path"))
        .and_then(serde_json::Value::as_str)
    {
        parts.push(format!("path=\"{path}\""));
    }
    if let Some(start) = args
        .get("offset")
        .or_else(|| args.get("start_line"))
        .and_then(serde_json::Value::as_i64)
    {
        parts.push(format!("start_line={start}"));
    }
    if let Some(limit) = args
        .get("limit")
        .or_else(|| args.get("end_line"))
        .and_then(serde_json::Value::as_i64)
    {
        parts.push(format!("limit={limit}"));
    }
    let call = if parts.is_empty() {
        "ctx_read(path=\"<file>\")".to_string()
    } else {
        format!("ctx_read({})", parts.join(", "))
    };
    format!("[DENIED] Native Read blocked. Use: {call} — lean-ctx replace mode is active.")
}

fn build_ctx_search_hint(args: &serde_json::Map<String, serde_json::Value>) -> String {
    let mut parts = Vec::new();
    if let Some(pat) = args
        .get("pattern")
        .or_else(|| args.get("regex"))
        .and_then(serde_json::Value::as_str)
    {
        parts.push(format!("pattern=\"{pat}\""));
    }
    if let Some(path) = args
        .get("path")
        .or_else(|| args.get("include"))
        .and_then(serde_json::Value::as_str)
    {
        parts.push(format!("path=\"{path}\""));
    }
    if let Some(glob) = args.get("glob").and_then(serde_json::Value::as_str) {
        parts.push(format!("include=\"{glob}\""));
    }
    let call = if parts.is_empty() {
        "ctx_search(pattern=\"<pattern>\")".to_string()
    } else {
        format!("ctx_search({})", parts.join(", "))
    };
    format!(
        "[DENIED] Native Grep blocked. Use: {call} — ctx_search also supports action=symbol, action=semantic."
    )
}

fn build_ctx_glob_hint(args: &serde_json::Map<String, serde_json::Value>) -> String {
    let mut parts = Vec::new();
    if let Some(pat) = args
        .get("pattern")
        .or_else(|| args.get("glob_pattern"))
        .and_then(serde_json::Value::as_str)
    {
        parts.push(format!("pattern=\"{pat}\""));
    }
    if let Some(path) = args
        .get("path")
        .or_else(|| args.get("target_directory"))
        .and_then(serde_json::Value::as_str)
    {
        parts.push(format!("path=\"{path}\""));
    }
    let call = if parts.is_empty() {
        "ctx_glob(pattern=\"<glob>\")".to_string()
    } else {
        format!("ctx_glob({})", parts.join(", "))
    };
    format!("[DENIED] Native Glob blocked. Use: {call} — or ctx_tree for directory overview.")
}

fn build_ctx_shell_hint(args: &serde_json::Map<String, serde_json::Value>) -> String {
    let cmd = args
        .get("command")
        .or_else(|| args.get("cmd"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("<command>");
    let short_cmd = if cmd.len() > 80 { &cmd[..80] } else { cmd };
    format!(
        "[DENIED] Native Shell blocked. Use: ctx_shell(command=\"{short_cmd}\") — lean-ctx replace mode is active."
    )
}

fn print_smart_deny(tool_name: &str, payload: &str) {
    let msg = smart_deny_message(tool_name, payload);
    let output = serde_json::json!({
        // Grok PreToolUse decision field.
        "decision": "deny",
        "reason": msg,
        "permission": "deny",
        "user_message": msg
    });
    println!("{output}");
    std::process::exit(2);
}

fn print_allow() {
    println!("{{}}");
}

fn read_stdin_with_timeout() -> String {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = std::io::stdin().read_to_string(&mut buf);
        let _ = tx.send(buf);
    });
    rx.recv_timeout(HOOK_STDIN_TIMEOUT).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_write_tool_recognizes_all_variants() {
        assert!(is_write_tool("Write"));
        assert!(is_write_tool("write"));
        assert!(is_write_tool("Edit"));
        assert!(is_write_tool("StrReplace"));
        assert!(is_write_tool("MultiEdit"));
        assert!(is_write_tool("EditNotebook"));
        assert!(!is_write_tool("Read"));
        assert!(!is_write_tool("Grep"));
        assert!(!is_write_tool("Shell"));
    }

    #[test]
    fn has_compression_markers_detects_lean_ctx_patterns() {
        assert!(has_compression_markers(
            "some text [lean-ctx: omitted 42 lines] more"
        ));
        assert!(has_compression_markers("... [lean-ctx: archived] ..."));
        assert!(!has_compression_markers("[lean-ctx compressed] tail"));
        assert!(!has_compression_markers(
            "[lean-ctx docs](https://example.com)"
        ));
        assert!(!has_compression_markers(
            "normal file content without markers"
        ));
        assert!(!has_compression_markers("lean-ctx is great"));
        assert!(!has_compression_markers(""));
    }

    #[test]
    fn has_compression_markers_detects_footer_marker() {
        assert!(has_compression_markers("content\n--- lean-ctx: end ---\n"));
    }

    #[test]
    fn has_compression_markers_detects_build_header_corruption() {
        // #1323: ctx_read build_header format "mod.rs 1225L\n deps ..."
        assert!(has_compression_markers(
            "mod.rs 1225L\n deps super::foo,bar\n"
        ));
        assert!(has_compression_markers(
            "server_handler.rs 340L\n exports handle_request\n"
        ));
        // Must NOT trigger on normal Rust content
        assert!(!has_compression_markers("let x = 1225;\n deps: vec![]\n"));
        assert!(!has_compression_markers("// mod.rs has 1225 lines\n"));
    }

    #[test]
    fn detects_map_outline_patterns() {
        assert!(has_compression_markers("class pub Foo @L12-34"));
        assert!(has_compression_markers(
            "fn pub run(id:usize) → bool @L372-383"
        ));
        assert!(has_compression_markers("  API:\n    class pub Bar"));
        assert!(has_compression_markers("events.py 1045L\n  deps: foo, bar"));
    }

    #[test]
    fn allows_normal_code() {
        assert!(!has_compression_markers(
            "fn main() { println!(\"hello\"); }"
        ));
        assert!(!has_compression_markers("let x = @L12;"));
    }

    #[test]
    fn extract_write_content_from_cursor_write() {
        let payload = r#"{"hookSpecificInput":{"toolName":"Write","input":{"path":"test.md","contents":"hello [lean-ctx: omitted 5 lines]"}}}"#;
        let content = extract_write_content(payload).unwrap();
        assert!(content.contains("[lean-ctx:"));
    }

    #[test]
    fn extract_write_content_from_claude_code_edit() {
        let payload = r#"{"tool_name":"Edit","input":{"path":"test.rs","new_text":"fn foo() { [lean-ctx: omitted 10 lines] }"}}"#;
        let content = extract_write_content(payload).unwrap();
        assert!(content.contains("[lean-ctx:"));
    }

    #[test]
    fn extract_write_content_from_multi_edit() {
        let payload = r#"{"tool_name":"MultiEdit","input":{"path":"x.rs","edits":[{"new_text":"[lean-ctx: omitted 3 lines]"}]}}"#;
        let content = extract_write_content(payload).unwrap();
        assert!(content.contains("[lean-ctx:"));
    }

    #[test]
    fn extract_write_content_clean_payload_returns_none_for_markers() {
        let payload =
            r#"{"tool_name":"Write","input":{"path":"test.md","contents":"normal content"}}"#;
        let content = extract_write_content(payload).unwrap();
        assert!(!has_compression_markers(&content));
    }

    #[test]
    fn extract_write_content_no_content_returns_none() {
        let payload = r#"{"tool_name":"Write","input":{"path":"test.md"}}"#;
        assert!(extract_write_content(payload).is_none());
    }

    #[test]
    fn extract_write_content_catches_markers_in_old_string() {
        // #1302: StrReplace with compressed old_string means the agent read a
        // compressed file. The resulting write will embed markers in the file.
        let payload = r#"{"tool_name":"StrReplace","input":{"path":"README.md","old_string":"text [lean-ctx: omitted 5 lines] more","new_string":"clean replacement"}}"#;
        let content = extract_write_content(payload).unwrap();
        assert!(
            has_compression_markers(&content),
            "old_string with markers must trigger the guard"
        );
    }

    #[test]
    fn extract_write_content_clean_str_replace_passes() {
        let payload = r#"{"tool_name":"StrReplace","input":{"path":"README.md","old_string":"old text","new_string":"new text"}}"#;
        let content = extract_write_content(payload).unwrap();
        assert!(
            !has_compression_markers(&content),
            "clean StrReplace must not trigger the guard"
        );
    }

    #[test]
    fn should_allow_lean_ctx_tools() {
        assert!(should_allow("ctx_tree", None));
        assert!(should_allow("ctx_read", Some("/tmp/test.rs")));
        assert!(should_allow("ctx_search", None));
        assert!(should_allow("ctx_shell", None));
        assert!(should_allow("ctx_compose", None));
        assert!(should_allow("shell", None));
    }

    #[test]
    fn is_lean_ctx_tool_checks() {
        assert!(is_lean_ctx_tool("ctx_tree"));
        assert!(is_lean_ctx_tool("ctx_read"));
        assert!(is_lean_ctx_tool("shell"));
        assert!(!is_lean_ctx_tool("Read"));
        assert!(!is_lean_ctx_tool("Grep"));
        assert!(!is_lean_ctx_tool("Shell"));
    }

    #[test]
    fn is_mcp_wrapper_recognises_devin_and_namespaced_variants() {
        assert!(is_mcp_wrapper("mcp_call_tool"));
        assert!(is_mcp_wrapper("mcp_call_tool_with_request_id"));
        assert!(is_mcp_wrapper("mcp__lean-ctx__mcp_call_tool"));
        assert!(is_mcp_wrapper("client:mcp_call_tool"));
        assert!(is_mcp_wrapper("client/mcp_call_tool"));
        assert!(!is_mcp_wrapper("Read"));
        assert!(!is_mcp_wrapper("ctx_read"));
        assert!(!is_mcp_wrapper("mcp_call_tool_other"));
    }

    #[test]
    fn is_lean_ctx_tool_allows_mcp_wrapper_unconditionally() {
        // The inner tool_name (ctx_*, linear, github, ...) is opaque to the
        // deny hook; the wrapper itself is always an MCP bridge, never a
        // native Read/Grep/Glob/Shell, so it is whitelisted unconditionally.
        assert!(is_lean_ctx_tool("mcp_call_tool"));
        assert!(is_lean_ctx_tool("mcp__lean-ctx__mcp_call_tool"));
    }

    #[test]
    fn extract_tool_name_devin_hook_specific_input_tool() {
        // Devin uses hookSpecificInput.tool (not toolName) for the outer
        // tool name. Without this, mcp_call_tool calls were denied as
        // tool_name="unknown". See GH #1329.
        let payload = r#"{"hookSpecificInput":{"tool":"mcp_call_tool","input":{"tool_name":"ctx_read","server_name":"lean-ctx","arguments":{}}}}"#;
        assert_eq!(extract_tool_name(payload), "mcp_call_tool");
    }

    #[test]
    fn is_devin_mcp_action_detects_pre_mcp_tool_use() {
        // Devin's native MCP hook format — actual payload captured from
        // a real Devin session. See GH #1329.
        let payload = r#"{"agent_action_name":"pre_mcp_tool_use","trajectory_id":"clean-candle","timestamp":"2026-08-02T12:05:56.355260+00:00","execution_id":"615fea01-83bc-431f-9c69-929b325bca26","tool_info":{"mcp_server_name":"lean-ctx","mcp_tool_name":"ctx_tree","mcp_tool_arguments":{"depth":2,"path":"/Volumes/SHARED/dev/altasol/teciobankas-electron"}}}"#;
        assert!(is_devin_mcp_action(payload));

        // Non-MCP actions must not match.
        let native = r#"{"tool_name":"Read","input":{"file_path":"/tmp/test.rs"}}"#;
        assert!(!is_devin_mcp_action(native));

        // Malformed JSON must not panic.
        assert!(!is_devin_mcp_action("not json"));
    }

    #[test]
    fn should_allow_claude_auto_memory_paths() {
        assert!(should_allow(
            "Read",
            Some("/home/jules/.claude/projects/-slug/memory/MEMORY.md")
        ));
        assert!(
            !should_allow("Read", Some("/home/jules/project/src/main.rs")),
            "ordinary project files stay denied under replace deny hooks"
        );
    }
}
