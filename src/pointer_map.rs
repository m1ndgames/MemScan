use crate::pbar::PBar;
use memflow::error::*;
use memflow::mem::VirtualMemory;
use memflow::types::{size, Address};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::ops::Bound::Included;

#[derive(Default)]
pub struct PointerMap {
    map: BTreeMap<Address, Address>,
    inverse_map: BTreeMap<Address, Vec<Address>>,
    pointers: Vec<Address>,
}

impl PointerMap {
    #[allow(unused)]
    pub fn reset(&mut self) {
        self.map.clear();
        self.inverse_map.clear();
        self.pointers.clear();
    }

    pub fn create_map<T: VirtualMemory>(&mut self, mem: &mut T, size_addr: usize) -> Result<()> {
        self.reset();

        let mem_map = mem.virt_page_map_range(size::mb(16), Address::null(), (1u64 << 47).into());

        let mut buf = vec![0; 0x1000 + size_addr - 1];
        let mut pb = PBar::new(
            mem_map.iter().map(|(_, size)| *size as u64).sum::<u64>(),
            true,
        );

        for &(addr, size) in &mem_map {
            for off in (0..size).step_by(0x1000) {
                mem.virt_read_raw_into(addr + off, buf.as_mut_slice())
                    .data_part()?;

                for (o, buf) in buf.windows(size_addr).enumerate() {
                    let addr = addr + off + o;
                    let mut arr = [0; 8];
                    // TODO: Fix for Big Endian
                    arr[0..buf.len()].copy_from_slice(buf);
                    let out_addr = Address::from(u64::from_le_bytes(arr));
                    if mem_map
                        .binary_search_by(|&(a, s)| {
                            if out_addr >= a && out_addr < a + s {
                                Ordering::Equal
                            } else {
                                a.cmp(&out_addr)
                            }
                        })
                        .is_ok()
                    {
                        self.map.insert(addr, out_addr);
                    }
                }

                pb.add(0x1000);
            }
        }

        for (&k, &v) in &self.map {
            self.inverse_map.entry(v).or_default().push(k);
        }

        self.pointers = self.map.keys().copied().collect();

        pb.finish();

        Ok(())
    }

    pub fn map(&self) -> &BTreeMap<Address, Address> {
        &self.map
    }

    pub fn inverse_map(&self) -> &BTreeMap<Address, Vec<Address>> {
        &self.inverse_map
    }

    pub fn pointers(&self) -> &Vec<Address> {
        &self.pointers
    }

    fn walk_down_range(
        &self,
        addr: Address,
        (lrange, urange): (usize, usize),
        max_levels: usize,
        level: usize,
        startpoints: &[Address],
        out: &mut Vec<(Address, Vec<(Address, isize)>)>,
        (final_addr, tmp): (Address, &mut Vec<(Address, isize)>),
        pb: &mut PBar,
        (pb_start, pb_end): (f32, f32),
    ) {
        let min = Address::from(addr.as_u64().saturating_sub(urange as _));
        let max = Address::from(addr.as_u64().saturating_add(lrange as _));

        // Find the lower bound
        let idx = startpoints.binary_search(&min).unwrap_or_else(|x| x);

        let mut iter = startpoints
            .iter()
            .skip(idx)
            .copied()
            .take_while(|&v| v <= max);

        // Pick next match
        let mut m = iter.next();

        // Go through the rest
        for e in iter {
            let off = signed_diff(addr, e).abs();
            // If abs offset is smaller, overwrite
            // < biasses more towards positive end
            if off < signed_diff(addr, m.unwrap()).abs() {
                m = Some(e);
            }
        }

        // Push match if found
        if let Some(e) = m {
            let off = signed_diff(addr, e);
            let mut cloned = tmp.clone();
            cloned.push((e, off));
            cloned.reverse();
            out.push((final_addr, cloned));
        }

        // Recurse downwards if possible
        if level < max_levels {
            let mut last = min;
            for (&k, vec) in self.inverse_map.range((Included(&min), Included(&max))) {
                // Calculate the starting fraction
                let frac_start = (last - min) as f32 / (max - min) as f32;
                let new_start = pb_start + (pb_end - pb_start) * frac_start;

                // Calculate the ending fraction
                let frac_end = (k - min) as f32 / (max - min) as f32;
                let new_end = pb_start + (pb_end - pb_start) * frac_end;

                last = k;

                let off = signed_diff(addr, k);
                tmp.push((k, off));

                // Calculate how much space each subitem uses in the fraction
                let part = (new_end - new_start) / vec.len() as f32;

                for (i, &v) in vec.iter().enumerate() {
                    self.walk_down_range(
                        v,
                        (lrange, urange),
                        max_levels,
                        level + 1,
                        startpoints,
                        out,
                        (final_addr, tmp),
                        pb,
                        (
                            new_start + part * i as f32,
                            new_start + part * (i + 1) as f32,
                        ),
                    );
                }
                tmp.pop();

                if (new_end - pb_start) >= 0.00001 {
                    pb.set((new_end * 100000.0).round() as u64);
                }
            }
        }
    }

    pub fn find_matches_addrs(
        &self,
        range: (usize, usize),
        max_depth: usize,
        search_for: &[Address],
        entry_points: &[Address],
    ) -> Vec<(Address, Vec<(Address, isize)>)> {
        let mut matches = vec![];

        let mut pb = PBar::new(100000, false);

        let part = 1.0 / search_for.len() as f32;

        for (i, &m) in search_for.iter().enumerate() {
            self.walk_down_range(
                m,
                range,
                max_depth,
                1,
                entry_points,
                &mut matches,
                (m, &mut vec![]),
                &mut pb,
                (part * i as f32, part * (i + 1) as f32),
            );
            pb.set((100000.0 * part * (i + 1) as f32).round() as u64);
        }

        pb.finish();

        matches
    }

    pub fn find_matches(
        &self,
        range: (usize, usize),
        max_depth: usize,
        search_for: &[Address],
    ) -> Vec<(Address, Vec<(Address, isize)>)> {
        self.find_matches_addrs(range, max_depth, search_for, &self.pointers)
    }
}

pub fn signed_diff(a: Address, b: Address) -> isize {
    a.as_u64()
        .checked_sub(b.as_u64())
        .map(|a| a as isize)
        .unwrap_or_else(|| -((b - a) as isize))
}