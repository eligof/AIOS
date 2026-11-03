/// 1-based `(line, col)` of the first occurrence of `needle` in `raw`, or `(1, 1)` if absent.
pub fn locate(raw: &str, needle: &str) -> (usize, usize) {
    for (i, line) in raw.lines().enumerate() {
        if let Some(col) = line.find(needle) {
            return (i + 1, col + 1);
        }
    }
    (1, 1)
}

/// Index of the line whose trimmed text is exactly `[section]`.
fn header_index(lines: &[&str], section: &str) -> Option<usize> {
    let header = format!("[{section}]");
    lines.iter().position(|l| l.trim() == header)
}

/// 1-based `(line, col)` of the header line for `section` (col of the `[`).
fn header_pos(lines: &[&str], idx: usize) -> (usize, usize) {
    let line = lines[idx];
    (idx + 1, line.len() - line.trim_start().len() + 1)
}

/// Line indexes after the header at `header`, up to the next `[table]` header line
/// (lines starting with `[[` do not end the scan).
fn section_body(lines: &[&str], header: usize) -> std::ops::Range<usize> {
    let start = header + 1;
    let end = lines[start..]
        .iter()
        .position(|l| {
            let t = l.trim();
            t.starts_with('[') && !t.starts_with("[[")
        })
        .map_or(lines.len(), |p| start + p);
    start..end
}

/// Position of `key = ...` inside `[section]` (1-based line, col of the key). Falls back to the
/// section header, then to `(1, 1)`. Comments and other sections are never matched.
pub fn locate_key(raw: &str, section: &str, key: &str) -> (usize, usize) {
    let lines: Vec<&str> = raw.lines().collect();
    let Some(h) = header_index(&lines, section) else {
        return (1, 1);
    };
    for i in section_body(&lines, h) {
        let line = lines[i];
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix(key) {
            if rest.trim_start().starts_with('=') {
                return (i + 1, line.len() - trimmed.len() + 1);
            }
        }
    }
    header_pos(&lines, h)
}

/// Position of the first line inside `[section]` containing `needle` (1-based line, col of the
/// match). Falls back to the section header, then to `(1, 1)`.
pub fn locate_value(raw: &str, section: &str, needle: &str) -> (usize, usize) {
    let lines: Vec<&str> = raw.lines().collect();
    let Some(h) = header_index(&lines, section) else {
        return (1, 1);
    };
    for i in section_body(&lines, h) {
        if let Some(col) = lines[i].find(needle) {
            return (i + 1, col + 1);
        }
    }
    header_pos(&lines, h)
}

/// Position of the first existing header among `sections`, else `(1, 1)`.
pub fn locate_section(raw: &str, sections: &[&str]) -> (usize, usize) {
    let lines: Vec<&str> = raw.lines().collect();
    sections
        .iter()
        .find_map(|s| header_index(&lines, s).map(|h| header_pos(&lines, h)))
        .unwrap_or((1, 1))
}

/// 1-based `(line, col)` of a byte offset into `raw`. Offsets past the end clamp to the end;
/// offsets inside a multibyte character move back to its start. `col` counts bytes, not chars.
pub fn offset_to_line_col(raw: &str, offset: usize) -> (usize, usize) {
    let mut offset = offset.min(raw.len());
    while !raw.is_char_boundary(offset) {
        offset -= 1;
    }
    let before = &raw[..offset];
    let line = before.matches('\n').count() + 1;
    let col = match before.rfind('\n') {
        Some(nl) => offset - nl - 1,
        None => offset,
    };
    (line, col + 1)
}
