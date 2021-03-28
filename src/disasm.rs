use memflow::mem::VirtualMemory;
use memflow::types::{size, Address};
use memflow_win32::error::*;
use memflow_win32::win32::Win32Process;

use crate::pbar::PBar;
use iced_x86::{Decoder, DecoderOptions};
use pelite::PeFile;

use std::collections::BTreeMap;

#[derive(Default)]
pub struct Disasm {
    map: BTreeMap<Address, Address>,
    inverse_map: BTreeMap<Address, Vec<Address>>,
    globals: Vec<Address>,
}

impl Disasm {
    #[allow(unused)]
    pub fn reset(&mut self) {
        self.map.clear();
        self.inverse_map.clear();
        self.globals.clear();
    }

    pub fn collect_globals(
        &mut self,
        process: &mut Win32Process<impl VirtualMemory>,
    ) -> Result<()> {
        self.reset();
        let modules = process.module_list()?;

        let mut image = vec![0; size::kb(128)];

        const CHUNK_SIZE: usize = size::mb(2);
        let mut bytes = vec![0; CHUNK_SIZE + 32];

        let mut pb = PBar::new(modules.iter().map(|m| m.size as u64).sum::<u64>(), true);

        for m in modules.into_iter() {
            process
                .virt_mem
                .virt_read_raw_into(m.base, &mut image)
                .data_part()?;
            let pefile =
                PeFile::from_bytes(&image).map_err(|_| Error::Other("Failed to parse header"))?;

            const IMAGE_SCN_CNT_CODE: u32 = 0x20;

            for section in pefile
                .section_headers()
                .iter()
                .filter(|s| (s.Characteristics & IMAGE_SCN_CNT_CODE) != 0)
            {
                let start = m.base.as_u64() + section.VirtualAddress as u64;
                let end = start + section.VirtualSize as u64;

                let mut addr = start;

                while addr < end {
                    let end = std::cmp::min(end, addr + CHUNK_SIZE as u64);
                    process
                        .virt_mem
                        .virt_read_raw_into(addr.into(), &mut bytes)
                        .data_part()?;

                    let mut decoder = Decoder::new(
                        process.proc_info.proc_arch.bits().into(),
                        &bytes,
                        DecoderOptions::NONE,
                    );

                    decoder.set_ip(addr);

                    addr += CHUNK_SIZE as u64;

                    for (ip, addr) in decoder
                        .into_iter()
                        .filter(|i| i.ip() < end) // we do not overflow the limit
                        .inspect(|i| addr = i.ip() + i.len() as u64) // sets addr to next instruction addr
                        .filter(|i| i.is_ip_rel_memory_operand()) // uses IP relative memory
                        .filter(|i| i.near_branch_target() == 0) // is not a branch (call/jump)
                        .map(|i| (i.ip().into(), i.ip_rel_memory_address().into()))
                    {
                        self.map.insert(ip, addr);
                    }
                }
            }

            pb.add(m.size as u64);
        }

        for (&k, &v) in &self.map {
            self.inverse_map.entry(v).or_default().push(k);
        }

        self.globals = self.inverse_map.keys().copied().collect();

        pb.finish();

        Ok(())
    }

    pub fn map(&self) -> &BTreeMap<Address, Address> {
        &self.map
    }

    pub fn inverse_map(&self) -> &BTreeMap<Address, Vec<Address>> {
        &self.inverse_map
    }

    pub fn globals(&self) -> &Vec<Address> {
        &self.globals
    }
}