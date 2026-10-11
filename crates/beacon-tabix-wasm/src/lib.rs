use std::io::{BufRead, Cursor, Read};
use noodles_bgzf as bgzf;
use noodles_core::{Position, Region};
use noodles_csi::binning_index::{index::reference_sequence::bin::Chunk, BinningIndex};
use noodles_tabix as tabix;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum QueryError {
    #[error("Failed to parse Tabix index: {0}")]
    IndexParseError(#[from] std::io::Error),
    #[error("Chromosome '{0}' not present in index")]
    ChromosomeNotFound(String),
    #[error("Invalid coordinate position: {0}")]
    InvalidPosition(usize),
    #[error("No genomic chunks overlap target locus")]
    NoOverlappingChunks,
    #[error("VCF parsing error: {0}")]
    VcfParseError(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HostFetchPlan {
    pub file_offset_start: u64,
    pub file_offset_end: u64,
    pub virtual_offset_start: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VariantMatch {
    pub chrom: String,
    pub pos: usize,
    pub reference: String,
    pub alternatives: Vec<String>,
    pub info: String,
}

pub struct TabixQueryEngine {
    index: tabix::Index,
}

impl TabixQueryEngine {
    pub fn from_index_bytes(index_bytes: &[u8]) -> Result<Self, QueryError> {
        let mut reader = tabix::io::Reader::new(Cursor::new(index_bytes));
        let index = reader.read_index()?;
        Ok(Self { index })
    }

    pub fn plan_fetch(&self, chrom: &str, pos: usize) -> Result<HostFetchPlan, QueryError> {
        let position = Position::try_from(pos).map_err(|_| QueryError::InvalidPosition(pos))?;
        let region = Region::new(chrom, position..=position);
        let header = self.index.header().ok_or_else(|| {
            QueryError::VcfParseError("Missing Tabix header".into())
        })?;

        let reference_sequence_id = self
            .index
            .reference_sequence_names(header)
            .get_index_of(chrom)
            .ok_or_else(|| QueryError::ChromosomeNotFound(chrom.to_string()))?;

        let chunks: Vec<Chunk> = self
            .index
            .query(reference_sequence_id, region.interval())
            .map_err(|e| QueryError::VcfParseError(e.to_string()))?;

        if chunks.is_empty() {
            return Err(QueryError::NoOverlappingChunks);
        }

        let first_chunk = &chunks[0];
        let v_start = first_chunk.start();
        let v_end = first_chunk.end();

        let file_offset_start = v_start.compressed();
        let file_offset_end = v_end.compressed().max(file_offset_start + 65536);

        Ok(HostFetchPlan {
            file_offset_start,
            file_offset_end,
            virtual_offset_start: u64::from(v_start),
        })
    }

    pub fn scan_block(
        &self,
        bgzf_chunk_bytes: &[u8],
        target_pos: usize,
    ) -> Result<Option<VariantMatch>, QueryError> {
        let mut decoder = bgzf::Reader::new(Cursor::new(bgzf_chunk_bytes));
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)?;

        let cursor = Cursor::new(decompressed);
        let mut lines = cursor.lines();

        while let Some(Ok(line)) = lines.next() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            let fields: Vec<&str> = line.split('\t').collect();
            if fields.len() < 8 {
                continue;
            }
            if let Ok(line_pos) = fields[1].parse::<usize>() {
                if line_pos == target_pos {
                    return Ok(Some(VariantMatch {
                        chrom: fields[0].to_string(),
                        pos: line_pos,
                        reference: fields[3].to_string(),
                        alternatives: fields[4].split(',').map(|s| s.to_string()).collect(),
                        info: fields[7].to_string(),
                    }));
                } else if line_pos > target_pos {
                    break;
                }
            }
        }
        Ok(None)
    }
}
