use crc::{CRC_32_ISCSI, Crc};
use rnmdb_common::{ErrorKind, Result, RnovError, ids::PageId};
use rnmdb_storage::{Page, PageSize, SingleFileBackend, StorageBackend};

const IMAGE_MAGIC: [u8; 8] = *b"RNOVSQL1";
const IMAGE_VERSION: u16 = 1;
const FRAME_MAGIC: [u8; 8] = *b"RNOVSI01";
const FRAME_VERSION: u16 = 1;
const FRAME_HEADER_LEN: usize = 8 + 2 + 8 + 4 + 4;
const FIRST_IMAGE_PAGE_ID: u64 = 1;
const IMAGE_CRC32C: Crc<u32> = Crc::<u32>::new(&CRC_32_ISCSI);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableExecutorImage {
    catalog: Vec<u8>,
    tables: Vec<DurableTableRows>,
}

impl DurableExecutorImage {
    pub fn new(catalog: Vec<u8>, tables: Vec<DurableTableRows>) -> Self {
        Self { catalog, tables }
    }

    pub fn catalog(&self) -> &[u8] {
        &self.catalog
    }

    pub fn tables(&self) -> &[DurableTableRows] {
        &self.tables
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(&IMAGE_MAGIC);
        write_u16(&mut out, IMAGE_VERSION);
        write_bytes(&mut out, &self.catalog, "catalog image")?;
        write_u32(&mut out, checked_u32(self.tables.len(), "table count")?);
        for table in &self.tables {
            write_table(&mut out, table)?;
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = ImageReader::new(bytes);
        ensure_image_magic(reader.read_exact(8, "image magic")?)?;
        ensure_image_version(reader.read_u16("image version")?)?;
        let catalog = reader.read_bytes("catalog image")?.to_vec();
        let table_count = reader.read_u32("table count")? as usize;
        let mut tables = Vec::with_capacity(table_count);
        for _ in 0..table_count {
            tables.push(read_table(&mut reader)?);
        }
        reader.ensure_complete("durable SQL image")?;
        Ok(Self { catalog, tables })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableTableRows {
    name: String,
    rows: Vec<Vec<u8>>,
}

impl DurableTableRows {
    pub fn new(name: impl Into<String>, rows: Vec<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            rows,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn rows(&self) -> &[Vec<u8>] {
        &self.rows
    }
}

pub fn write_image_to_backend(
    backend: &dyn StorageBackend,
    page_size: PageSize,
    image: &[u8],
) -> Result<()> {
    let frame = encode_page_frame(page_size, image)?;
    for (index, chunk) in frame.chunks(page_size.bytes()).enumerate() {
        let page = Page::new(page_id_for_chunk(index)?, chunk.to_vec())?;
        backend.write_page(page)?;
    }
    backend.sync()?;
    Ok(())
}

pub fn write_image_to_single_file_backend(
    backend: &mut SingleFileBackend,
    page_size: PageSize,
    image: &[u8],
) -> Result<()> {
    let frame = encode_page_frame(page_size, image)?;
    let payloads = frame
        .chunks(page_size.bytes())
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    backend.commit_catalog_pages(&payloads)?;
    Ok(())
}

pub fn read_image_from_backend(backend: &dyn StorageBackend) -> Result<Option<Vec<u8>>> {
    read_image_from_root(backend, PageId::new(FIRST_IMAGE_PAGE_ID))
}

pub fn read_image_from_single_file_backend(backend: &SingleFileBackend) -> Result<Option<Vec<u8>>> {
    let root = backend
        .catalog_root()
        .unwrap_or_else(|| PageId::new(FIRST_IMAGE_PAGE_ID));
    read_image_from_root(backend, root)
}

fn read_image_from_root(backend: &dyn StorageBackend, root: PageId) -> Result<Option<Vec<u8>>> {
    let Some(first_page) = backend.read_page(root)? else {
        return Ok(None);
    };
    let metadata = FrameMetadata::decode(first_page.payload())?;
    let mut frame = first_page.payload().to_vec();
    for index in 1..metadata.page_count {
        frame.extend_from_slice(read_frame_page(backend, root, index)?.payload());
    }
    metadata.extract_image(&frame).map(Some)
}

fn write_table(out: &mut Vec<u8>, table: &DurableTableRows) -> Result<()> {
    write_string(out, table.name())?;
    write_u32(out, checked_u32(table.rows().len(), "row count")?);
    for row in table.rows() {
        write_bytes(out, row, "row image")?;
    }
    Ok(())
}

fn read_table(reader: &mut ImageReader<'_>) -> Result<DurableTableRows> {
    let name = reader.read_string("table name")?;
    let row_count = reader.read_u32("row count")? as usize;
    let mut rows = Vec::with_capacity(row_count);
    for _ in 0..row_count {
        rows.push(reader.read_bytes("row image")?.to_vec());
    }
    Ok(DurableTableRows::new(name, rows))
}

fn encode_page_frame(page_size: PageSize, image: &[u8]) -> Result<Vec<u8>> {
    validate_page_size(page_size)?;
    let page_count = page_count_for_image(page_size, image.len())?;
    let mut frame = Vec::with_capacity(page_count * page_size.bytes());
    write_frame_header(&mut frame, image, page_count)?;
    frame.extend_from_slice(image);
    frame.resize(page_count * page_size.bytes(), 0);
    Ok(frame)
}

fn write_frame_header(out: &mut Vec<u8>, image: &[u8], page_count: usize) -> Result<()> {
    out.extend_from_slice(&FRAME_MAGIC);
    write_u16(out, FRAME_VERSION);
    write_u64(out, checked_u64(image.len(), "durable image length")?);
    write_u32(out, checked_u32(page_count, "durable image page count")?);
    write_u32(out, checksum(image));
    Ok(())
}

fn validate_page_size(page_size: PageSize) -> Result<()> {
    if page_size.bytes() <= FRAME_HEADER_LEN {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "durable image page size is too small",
        ));
    }
    Ok(())
}

fn page_count_for_image(page_size: PageSize, image_len: usize) -> Result<usize> {
    let frame_len = FRAME_HEADER_LEN
        .checked_add(image_len)
        .ok_or_else(|| RnovError::new(ErrorKind::InvalidInput, "durable image length overflow"))?;
    Ok(frame_len.div_ceil(page_size.bytes()))
}

fn read_frame_page(backend: &dyn StorageBackend, root: PageId, index: usize) -> Result<Page> {
    let page_id = page_id_for_root_chunk(root, index)?;
    backend.read_page(page_id)?.ok_or_else(|| {
        RnovError::new(
            ErrorKind::Corruption,
            format!("durable SQL image is missing page {}", page_id.get()),
        )
    })
}

fn page_id_for_chunk(index: usize) -> Result<PageId> {
    page_id_for_root_chunk(PageId::new(FIRST_IMAGE_PAGE_ID), index)
}

fn page_id_for_root_chunk(root: PageId, index: usize) -> Result<PageId> {
    let offset = u64::try_from(index).map_err(|_| {
        RnovError::new(
            ErrorKind::InvalidInput,
            "durable image page index is too large",
        )
    })?;
    root.get()
        .checked_add(offset)
        .map(PageId::new)
        .ok_or_else(|| RnovError::new(ErrorKind::InvalidInput, "durable image page id overflow"))
}

fn ensure_image_magic(bytes: &[u8]) -> Result<()> {
    if bytes == IMAGE_MAGIC {
        return Ok(());
    }
    Err(RnovError::new(
        ErrorKind::Corruption,
        "invalid durable SQL image magic",
    ))
}

fn ensure_image_version(version: u16) -> Result<()> {
    if version == IMAGE_VERSION {
        return Ok(());
    }
    Err(RnovError::new(
        ErrorKind::Corruption,
        format!("unsupported durable SQL image version {version}"),
    ))
}

fn checked_u32(value: usize, name: &'static str) -> Result<u32> {
    u32::try_from(value)
        .map_err(|_| RnovError::new(ErrorKind::InvalidInput, format!("{name} is too large")))
}

fn checked_u64(value: usize, name: &'static str) -> Result<u64> {
    u64::try_from(value)
        .map_err(|_| RnovError::new(ErrorKind::InvalidInput, format!("{name} is too large")))
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_string(out: &mut Vec<u8>, value: &str) -> Result<()> {
    write_bytes(out, value.as_bytes(), "string")
}

fn write_bytes(out: &mut Vec<u8>, value: &[u8], name: &'static str) -> Result<()> {
    write_u32(out, checked_u32(value.len(), name)?);
    out.extend_from_slice(value);
    Ok(())
}

fn checksum(bytes: &[u8]) -> u32 {
    IMAGE_CRC32C.checksum(bytes)
}

struct FrameMetadata {
    image_len: usize,
    page_count: usize,
    checksum: u32,
}

impl FrameMetadata {
    fn decode(payload: &[u8]) -> Result<Self> {
        let mut reader = FrameReader::new(payload);
        ensure_frame_magic(reader.read_exact(8, "frame magic")?)?;
        ensure_frame_version(reader.read_u16("frame version")?)?;
        let image_len = checked_usize(reader.read_u64("image length")?, "image length")?;
        let page_count = reader.read_u32("image page count")? as usize;
        let checksum = reader.read_u32("image checksum")?;
        let page_size = PageSize::new(payload.len());
        validate_frame_metadata(page_size, image_len, page_count)?;
        Ok(Self {
            image_len,
            page_count,
            checksum,
        })
    }

    fn extract_image(&self, frame: &[u8]) -> Result<Vec<u8>> {
        let image_end = FRAME_HEADER_LEN
            .checked_add(self.image_len)
            .ok_or_else(|| {
                RnovError::new(ErrorKind::Corruption, "durable image length overflow")
            })?;
        let image = frame
            .get(FRAME_HEADER_LEN..image_end)
            .ok_or_else(|| RnovError::new(ErrorKind::Corruption, "truncated durable SQL image"))?;
        ensure_frame_checksum(image, self.checksum)?;
        Ok(image.to_vec())
    }
}

fn validate_frame_metadata(page_size: PageSize, image_len: usize, page_count: usize) -> Result<()> {
    let expected = page_count_for_image(page_size, image_len)?;
    if page_count == expected {
        return Ok(());
    }
    Err(RnovError::new(
        ErrorKind::Corruption,
        "durable SQL image page count does not match length",
    ))
}

fn ensure_frame_magic(bytes: &[u8]) -> Result<()> {
    if bytes == FRAME_MAGIC {
        return Ok(());
    }
    Err(RnovError::new(
        ErrorKind::Corruption,
        "invalid durable SQL frame magic",
    ))
}

fn ensure_frame_version(version: u16) -> Result<()> {
    if version == FRAME_VERSION {
        return Ok(());
    }
    Err(RnovError::new(
        ErrorKind::Corruption,
        format!("unsupported durable SQL frame version {version}"),
    ))
}

fn ensure_frame_checksum(image: &[u8], expected: u32) -> Result<()> {
    if checksum(image) == expected {
        return Ok(());
    }
    Err(RnovError::new(
        ErrorKind::Corruption,
        "durable SQL image checksum mismatch",
    ))
}

fn checked_usize(value: u64, name: &'static str) -> Result<usize> {
    usize::try_from(value)
        .map_err(|_| RnovError::new(ErrorKind::Corruption, format!("{name} is too large")))
}

struct ImageReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> ImageReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read_u16(&mut self, name: &'static str) -> Result<u16> {
        Ok(u16::from_be_bytes(self.read_fixed(name)?))
    }

    fn read_u32(&mut self, name: &'static str) -> Result<u32> {
        Ok(u32::from_be_bytes(self.read_fixed(name)?))
    }

    fn read_string(&mut self, name: &'static str) -> Result<String> {
        String::from_utf8(self.read_bytes(name)?.to_vec())
            .map_err(|_| RnovError::new(ErrorKind::Corruption, format!("{name} is not utf-8")))
    }

    fn read_bytes(&mut self, name: &'static str) -> Result<&'a [u8]> {
        let len = self.read_u32(name)? as usize;
        self.read_exact(len, name)
    }

    fn read_fixed<const N: usize>(&mut self, name: &'static str) -> Result<[u8; N]> {
        let bytes = self.read_exact(N, name)?;
        let mut fixed = [0_u8; N];
        fixed.copy_from_slice(bytes);
        Ok(fixed)
    }

    fn read_exact(&mut self, len: usize, name: &'static str) -> Result<&'a [u8]> {
        let end = self.position.checked_add(len).ok_or_else(|| {
            RnovError::new(ErrorKind::Corruption, format!("{name} length overflow"))
        })?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| RnovError::new(ErrorKind::Corruption, format!("truncated {name}")))?;
        self.position = end;
        Ok(bytes)
    }

    fn ensure_complete(&self, name: &'static str) -> Result<()> {
        if self.position == self.bytes.len() {
            return Ok(());
        }
        Err(RnovError::new(
            ErrorKind::Corruption,
            format!("{name} has trailing bytes"),
        ))
    }
}

struct FrameReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> FrameReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read_u16(&mut self, name: &'static str) -> Result<u16> {
        Ok(u16::from_be_bytes(self.read_fixed(name)?))
    }

    fn read_u32(&mut self, name: &'static str) -> Result<u32> {
        Ok(u32::from_be_bytes(self.read_fixed(name)?))
    }

    fn read_u64(&mut self, name: &'static str) -> Result<u64> {
        Ok(u64::from_be_bytes(self.read_fixed(name)?))
    }

    fn read_fixed<const N: usize>(&mut self, name: &'static str) -> Result<[u8; N]> {
        let bytes = self.read_exact(N, name)?;
        let mut fixed = [0_u8; N];
        fixed.copy_from_slice(bytes);
        Ok(fixed)
    }

    fn read_exact(&mut self, len: usize, name: &'static str) -> Result<&'a [u8]> {
        let end = self.position.checked_add(len).ok_or_else(|| {
            RnovError::new(ErrorKind::Corruption, format!("{name} length overflow"))
        })?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| RnovError::new(ErrorKind::Corruption, format!("truncated {name}")))?;
        self.position = end;
        Ok(bytes)
    }
}
