/// Dispaly a progress bar
#[derive(Clone)]
pub struct Progress {
	bar_multi: std::sync::Arc<indicatif::MultiProgress>,
	bar_bytes: Option<indicatif::ProgressBar>,
	bar_frames: Option<indicatif::ProgressBar>,
}

impl Progress {
	pub fn new(bytes_to_read: u64, frames_to_read: u64, hidden: bool) -> Self {
		let sty_bytes = indicatif::ProgressStyle::default_bar()
                    .template("             Bytes read: [{elapsed_precise}] [{bar:50.blue/blue}] {bytes}/{total_bytes}").unwrap()
                    .progress_chars("#>-");
		let sty_frames = indicatif::ProgressStyle::default_bar()
                    .template("Read vs. written frames: [{elapsed_precise}] [{bar:50.cyan/cyan}] {pos:>5}/{len:5}").unwrap()
                    .progress_chars("#>-");

		let bar_multi = indicatif::MultiProgress::new();
		let bar_bytes;
		let bar_frames;

		if hidden {
			bar_bytes = None;
			bar_frames = None;
		} else {
			bar_bytes = Some(bar_multi.add(indicatif::ProgressBar::new(bytes_to_read)));
			bar_bytes.as_ref().unwrap().set_style(sty_bytes);
			bar_frames = Some(bar_multi.add(indicatif::ProgressBar::new(frames_to_read)));
			bar_frames.as_ref().unwrap().set_style(sty_frames);
		}

		Self {
			bar_multi: std::sync::Arc::new(bar_multi),
			bar_bytes,
			bar_frames,
		}
	}

	pub fn set_read_frames(&self, length: u64) {
		if let Some(ref x) = self.bar_frames {
			x.set_length(length)
		};
	}

	pub fn set_written_frames(&self, length: u64) {
		if let Some(ref x) = self.bar_frames {
			x.set_position(length)
		};
	}

	pub fn set_read_bytes(&self, length: u64) {
		if let Some(ref x) = self.bar_bytes {
			x.set_position(length)
		};
	}

	pub fn finish_frames(&self) {
		if let Some(ref x) = self.bar_frames {
			x.finish_and_clear()
		};
	}

	pub fn finish_bytes(&self) {
		if let Some(ref x) = self.bar_bytes {
			x.finish_and_clear()
		};
	}

	pub fn finish_multi(&self) {
		self.bar_multi.clear().unwrap();
	}
}
