use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

use anyhow::{ensure, Context, Result};
use memmap2::{Advice, Mmap, MmapMut, MmapOptions};
use rayon::prelude::*;

use zkm_core_executor::ExecutionRecord;

use rkyv::de::deserializers::SharedDeserializeMap;
use rkyv::ser::serializers::{
    AllocScratch, CompositeSerializer, FallbackScratch, HeapScratch, SharedSerializeMap,
    WriteSerializer,
};
use rkyv::ser::Serializer;
use rkyv::{archived_root, Deserialize};

const SCRATCH_MAIN_BYTES: usize = 4 * 1024 * 1024;

type DefaultScratch = FallbackScratch<HeapScratch<SCRATCH_MAIN_BYTES>, AllocScratch>;
type DefaultSerializer<W> =
    CompositeSerializer<WriteSerializer<W>, DefaultScratch, SharedSerializeMap>;

fn new_serializer<W: io::Write>(writer: W) -> DefaultSerializer<W> {
    CompositeSerializer::new(
        WriteSerializer::new(writer),
        DefaultScratch::default(),
        SharedSerializeMap::default(),
    )
}

pub fn write_record_mmap_rkyv(path: &Path, record: &ExecutionRecord) -> Result<()> {
    let serialized_len = measure_serialized_size(record)?;

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = tempfile::Builder::new()
        .prefix(".rkyv-")
        .tempfile_in(dir)
        .context("create tempfile")?;
    let file: &File = tmp.as_file();

    file.set_len(serialized_len as u64)
        .context("set_len for mmap file")?;

    let mut mmap =
        unsafe { MmapOptions::new().len(serialized_len).map_mut(file) }.context("mmap_mut")?;
    let _ = mmap.advise(Advice::Sequential);

    serialize_record_into_mmap(record, &mut mmap)?;

    let _ = mmap.flush_async();
    drop(mmap);

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
        })?;

    Ok(())
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

fn serialize_record_into_mmap(record: &ExecutionRecord, mmap: &mut MmapMut) -> Result<()> {
    let writer = MmapWriter::new(mmap);
    let mut serializer = new_serializer(writer);
    serializer
        .serialize_value(record)
        .context("rkyv serialize into mmap")?;
    let writer = serializer.into_serializer().into_inner();
    writer.finish()
}

fn measure_serialized_size(record: &ExecutionRecord) -> Result<usize> {
    let writer = CountingWriter::default();
    let mut serializer = new_serializer(writer);
    serializer
        .serialize_value(record)
        .context("rkyv measure serialized size")?;
    Ok(serializer.pos())
}

#[derive(Default)]
struct CountingWriter {
    pos: usize,
}

impl io::Write for CountingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.pos += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct MmapWriter<'a> {
    buffer: &'a mut [u8],
    pos: usize,
}

impl<'a> MmapWriter<'a> {
    fn new(mmap: &'a mut MmapMut) -> Self {
        Self {
            buffer: &mut mmap[..],
            pos: 0,
        }
    }

    fn finish(self) -> Result<()> {
        ensure!(
            self.pos == self.buffer.len(),
            "serialized length {} did not fill mmap {}",
            self.pos,
            self.buffer.len()
        );
        Ok(())
    }
}

impl<'a> io::Write for MmapWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let end = self.pos + buf.len();
        if end > self.buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "mmap writer overflow",
            ));
        }
        self.buffer[self.pos..end].copy_from_slice(buf);
        self.pos = end;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
