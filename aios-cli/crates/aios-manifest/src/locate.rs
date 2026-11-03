/// 1-based `(line, col)` of the first occurrence of `needle` in `raw`, or `(1, 1)` if absent.
pub fn locate(raw: &str, needle: &str) -> (usize, usize) {
    for (i, line) in raw.lines().enumerate() {
        if let Some(col) = line.find(needle) {
            return (i + 1, col + 1);
        }
    }
    (1, 1)
}

/// 1-based `(line, col)` of a byte offset into `raw`. Offsets past the end clamp to the end.
pub fn offset_to_line_col(raw: &str, offset: usize) -> (usize, usize) {
    let offset = offset.min(raw.len());
    let before = &raw[..offset];
    let line = before.matches('\n').count() + 1;
    let col = match before.rfind('\n') {
        Some(nl) => offset - nl - 1,
        None => offset,
    };
    (line, col + 1)
}
