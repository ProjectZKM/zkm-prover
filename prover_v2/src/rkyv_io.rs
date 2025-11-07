use std::fs::File;
use std::path::Path;

use anyhow::{Context, Result};
use memmap2::{Advice, Mmap, MmapMut, MmapOptions};
use rayon::prelude::*;

use zkm_core_executor::ExecutionRecord;

use rkyv::{archived_root, util::to_bytes, Deserialize};
use rkyv::de::deserializers::SharedDeserializeMap;

pub fn write_record_mmap_rkyv(path: &Path, record: &ExecutionRecord) -> Result<()> {
    // 1) Serialize into an AlignedVec (temporary buffer only)
    let bytes = to_bytes::<_, 1024>(record).context("rkyv to_bytes")?;

    // 2) Create a temp file in the same directory
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = tempfile::Builder::new()
        .prefix(".rkyv-")
        .tempfile_in(dir)
        .context("create tempfile")?;
    let file: &File = tmp.as_file();

    // 3) Pre-allocate to avoid SIGBUS on mmap write
    file.set_len(bytes.len() as u64)
        .context("set_len for mmap file")?;

    // 4) Writable mapping -> single copy -> async flush
    let mut mmap = unsafe { MmapOptions::new().map_mut(file) }.context("mmap_mut")?;
    let _ = mmap.advise(Advice::Sequential);
    mmap[..].copy_from_slice(&bytes);
    let _ = mmap.flush_async();
    drop(mmap);

    // 5) Atomic replace: prefer persist, fallback to manual rename
    match tmp.persist(path) {
        Ok(_f) => {}
        Err(e) => {
            let src = e.file.path();
            std::fs::rename(src, path).context("rename fallback after persist error")?;
        }
    }
    Ok(())
}

pub fn write_records_parallel_mmap_rkyv(
    records: &[ExecutionRecord],
    seg_dir: &Path,
    base_index: usize,
) -> Result<()> {
    std::fs::create_dir_all(seg_dir).ok();
    (0..records.len())
        .into_par_iter()
        .try_for_each(|k| -> Result<()> {
            let idx = base_index + k;
            let path = seg_dir.join(idx.to_string());
            write_record_mmap_rkyv(&path, &records[k])
        })
}

/// Holder for a read-only mmap and zero-copy archived access.
pub struct ArchivedRecordMap {
    mmap: Mmap,
}

impl ArchivedRecordMap {
    #[inline]
    pub fn archived(&self) -> &rkyv::Archived<ExecutionRecord> {
        unsafe { archived_root::<ExecutionRecord>(&self.mmap[..]) }
    }

    #[inline]
    pub fn advise_sequential(&self) {
        let _ = self.mmap.advise(Advice::Sequential);
    }
}

pub fn open_record_archived_mmap_rkyv(path: &Path) -> Result<ArchivedRecordMap> {
    let file = File::open(path).with_context(|| format!("open {:?}", path))?;
    let mmap = unsafe { MmapOptions::new().map(&file) }.context("mmap readonly")?;
    Ok(ArchivedRecordMap { mmap })
}

/// Owned read (slower than zero-copy, but movable/mutable).
pub fn read_record_owned_mmap_rkyv(path: &Path) -> Result<ExecutionRecord> {
    let file = File::open(path).with_context(|| format!("open {:?}", path))?;
    let mmap = unsafe { MmapOptions::new().map(&file) }.context("mmap readonly")?;
    let _ = mmap.advise(Advice::Sequential);
    let archived = unsafe { archived_root::<ExecutionRecord>(&mmap[..]) };
    let mut deserializer = SharedDeserializeMap::new();
    let record = archived
        .deserialize(&mut deserializer)
        .context("rkyv deserialize")?;
    Ok(record)
}
