use serde::Serialize;

/// A Signal message
#[derive(Serialize)]
pub struct Message {
	/// Address of receiver / sender
	address: String,
	/// Message
	body: String,
	/// Date sent
	date_sent: chrono::NaiveDateTime,
	/// Date received
	date_received: chrono::NaiveDateTime,
}

impl Message {
	pub fn new(sql_parameter: &[rusqlite::types::Value]) -> Self {
		Self {
			address: if let rusqlite::types::Value::Text(x) = sql_parameter[2].to_owned() {
				x
			} else {
				String::from("")
			},
			body: if let rusqlite::types::Value::Text(x) = sql_parameter[14].to_owned() {
				x
			} else {
				String::from("")
			},
			date_sent: if let rusqlite::types::Value::Integer(x) = sql_parameter[5] {
				// omit nanoseconds here ...
				chrono::DateTime::from_timestamp(x / 1000, 0)
					.map(|dt| dt.naive_utc())
					.unwrap_or_else(|| chrono::NaiveDateTime::default())
			} else {
				chrono::NaiveDateTime::default()
			},
			date_received: if let rusqlite::types::Value::Integer(x) = sql_parameter[6] {
				// omit nanoseconds here ...
				chrono::DateTime::from_timestamp(x / 1000, 0)
					.map(|dt| dt.naive_utc())
					.unwrap_or_else(|| chrono::NaiveDateTime::default())
			} else {
				chrono::NaiveDateTime::default()
			},
		}
	}
}
