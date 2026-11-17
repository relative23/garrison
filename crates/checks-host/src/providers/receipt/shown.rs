//! What the card shows of a receipt: its fields and the table of its rows.

use garrison_core::observations::{Column, Field, Format, Table};
use garrison_core::time::{self, Written};
use serde_json::Value;

use super::Receipt;
use super::keys::{instant, lookup};

/// Why a `datetime` value is not shown.
const NO_OFFSET: &str = "no time with its offset, such as 2026-11-17T03:00:00Z";

impl Receipt {
    /// The card's fields: when the receipt was reported, and the values its
    /// `fields` select from an object. A `datetime` value that is no instant
    /// is not shown, and `unshown` says so.
    pub(super) fn fields(
        &self,
        document: &Value,
        reported: Option<Written>,
        unshown: &mut Vec<String>,
    ) -> Vec<Field> {
        let mut fields = vec![Field::new(
            "Reported at",
            reported.map(time::isoformat_written),
            Format::Datetime,
        )];
        if document.is_object() {
            for field in &self.fields {
                let mut value = lookup(document, &field.key);
                if field.format == Format::Datetime {
                    value = instant(value).unwrap_or_else(|read| {
                        unshown.push(format!(
                            "{} is not shown: {read} is {NO_OFFSET}.",
                            field.label
                        ));
                        Value::Null
                    });
                }
                fields.push(Field::new(field.label.clone(), value, field.format));
            }
        }
        fields
    }

    /// The table of the rows it shows. A `datetime` cell that is no instant
    /// is not shown, and `unshown` says in how many rows of which column.
    pub(super) fn table(&self, items: &[Value], unshown: &mut Vec<String>) -> Table {
        let mut left = vec![0_usize; self.columns.len()];
        let mut rows = Vec::with_capacity(items.len());
        for item in items {
            let mut row = Vec::with_capacity(self.columns.len());
            for (column, left) in self.columns.iter().zip(left.iter_mut()) {
                let mut value = lookup(item, &column.key);
                if column.format == Format::Datetime {
                    value = instant(value).unwrap_or_else(|_| {
                        *left += 1;
                        Value::Null
                    });
                }
                row.push(value);
            }
            rows.push(row);
        }
        for (column, count) in self.columns.iter().zip(left) {
            if count > 0 {
                let (rows, they) = if count == 1 {
                    ("row", "it holds")
                } else {
                    ("rows", "they hold")
                };
                unshown.push(format!(
                    "The column {} is not shown in {count} {rows}: {they} {NO_OFFSET}.",
                    column.label
                ));
            }
        }
        Table {
            columns: self
                .columns
                .iter()
                .map(|column| Column {
                    label: column.label.clone(),
                    format: column.format,
                })
                .collect(),
            rows,
        }
    }
}
