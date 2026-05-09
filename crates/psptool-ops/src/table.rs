//! Tiny ASCII-grid table renderer matching Python `prettytable`'s default
//! look — frozen output so that `insta` snapshot tests stay byte-stable.
//!
//! Layout: every cell is wrapped in `| ` … ` |`, header text is centered, body
//! cells follow per-column [`Align`]. Horizontal separator rows are
//! `+`-corners and `-`-fills, recomputed from the per-column widths after the
//! caller has finished adding rows.
//!
//! This is intentionally minimal: just enough to mimic prettytable so the
//! snapshot diff is small, without pulling in a third-party formatter.

use core::fmt::Write as _;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Align {
    Left,
    Center,
    Right,
}

pub struct Table {
    headers: Vec<String>,
    aligns: Vec<Align>,
    rows: Vec<Vec<String>>,
}

impl Table {
    /// New table with `headers` columns. All body cells use the given default
    /// alignment; [`Self::set_align`] overrides per-column.
    pub fn new(headers: impl IntoIterator<Item = impl Into<String>>, default_align: Align) -> Self {
        let headers: Vec<String> = headers.into_iter().map(Into::into).collect();
        let aligns = vec![default_align; headers.len()];
        Self {
            headers,
            aligns,
            rows: Vec::new(),
        }
    }

    /// Append a row. Row length must equal `headers.len()`; mismatched rows
    /// are padded with empty strings or truncated as needed.
    pub fn add_row(&mut self, cells: impl IntoIterator<Item = impl Into<String>>) {
        let mut row: Vec<String> = cells.into_iter().map(Into::into).collect();
        if row.len() < self.headers.len() {
            row.resize(self.headers.len(), String::new());
        } else if row.len() > self.headers.len() {
            row.truncate(self.headers.len());
        }
        self.rows.push(row);
    }

    /// Render to a string. Trailing newline included so a caller can simply
    /// concatenate multiple tables.
    pub fn render(&self) -> String {
        let cols = self.headers.len();
        if cols == 0 {
            return String::new();
        }

        let mut widths = vec![0usize; cols];
        for (i, h) in self.headers.iter().enumerate() {
            widths[i] = widths[i].max(h.chars().count());
        }
        for row in &self.rows {
            for (i, cell) in row.iter().enumerate() {
                widths[i] = widths[i].max(cell.chars().count());
            }
        }

        let mut out = String::new();
        let sep = build_separator(&widths);
        out.push_str(&sep);
        out.push('\n');
        out.push_str(&render_row(
            &self.headers,
            &widths,
            &vec![Align::Center; cols],
        ));
        out.push('\n');
        out.push_str(&sep);
        out.push('\n');
        for row in &self.rows {
            out.push_str(&render_row(row, &widths, &self.aligns));
            out.push('\n');
        }
        out.push_str(&sep);
        out.push('\n');
        out
    }
}

fn build_separator(widths: &[usize]) -> String {
    let mut s = String::from("+");
    for w in widths {
        for _ in 0..(w + 2) {
            s.push('-');
        }
        s.push('+');
    }
    s
}

fn render_row(cells: &[String], widths: &[usize], aligns: &[Align]) -> String {
    let mut s = String::from("|");
    for (i, cell) in cells.iter().enumerate() {
        let w = widths[i];
        let align = aligns.get(i).copied().unwrap_or(Align::Left);
        let cell_w = cell.chars().count();
        let pad = w.saturating_sub(cell_w);
        let _ = match align {
            Align::Left => write!(s, " {cell}{:pad$} |", "", pad = pad),
            Align::Right => write!(s, " {:pad$}{cell} |", "", pad = pad),
            Align::Center => {
                let left = pad / 2;
                let right = pad - left;
                write!(
                    s,
                    " {:left$}{cell}{:right$} |",
                    "",
                    "",
                    left = left,
                    right = right
                )
            }
        };
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_basic_table_with_centered_headers_and_left_body() {
        let mut t = Table::new(["A", "BB"], Align::Left);
        t.add_row(["1", "two"]);
        t.add_row(["100", "x"]);
        let s = t.render();
        assert!(s.starts_with("+-----+-----+\n"), "{s}");
        assert!(s.contains("|  A  | BB  |"), "{s}");
        assert!(s.contains("| 1   | two |"), "{s}");
        assert!(s.ends_with("+-----+-----+\n"));
    }

    #[test]
    fn right_alignment_pads_left() {
        let mut t = Table::new(["X"], Align::Right);
        t.add_row(["12"]);
        t.add_row(["3456"]);
        let s = t.render();
        assert!(s.contains("|   12 |"), "{s}");
        assert!(s.contains("| 3456 |"), "{s}");
    }

    #[test]
    fn empty_columns_returns_empty_string() {
        let t = Table::new(Vec::<&str>::new(), Align::Left);
        assert_eq!(t.render(), "");
    }

    #[test]
    fn short_rows_are_padded() {
        let mut t = Table::new(["a", "b", "c"], Align::Left);
        t.add_row(["1"]); // only 1 cell
        let s = t.render();
        assert!(s.contains("| 1 |   |   |"), "{s}");
    }

    #[test]
    fn long_rows_are_truncated() {
        let mut t = Table::new(["a"], Align::Left);
        t.add_row(["1", "2", "3"]); // extra cells dropped
        let s = t.render();
        assert!(s.contains("| 1 |"), "{s}");
        assert!(!s.contains("| 2 |"), "{s}");
    }
}
