use memflow::connector::{ConnectorInventory, ConnectorArgs};
use memflow::{ConnectorInstance};
use simplelog::{LevelFilter, TermLogger, Config, TerminalMode};
use memflow_win32::win32::{Kernel, Win32Process};
use memflow_win32::{Error, Result};
use memflow::types::{size, Address};
use memflow::virt_mem::{VirtualMemory, VirtualReadData};

pub fn get_connector() -> ConnectorInstance {
    TermLogger::init(LevelFilter::Trace, Config::default(), TerminalMode::Mixed);

    let inventory = unsafe {
        ConnectorInventory::scan_path("C:/Users/flori/.local/lib/memflow/")
    }.unwrap();

    let args: Vec<String> = vec![String::from("device"), String::from("FPGA"), String::from("memmap"), String::from("memmap.toml")];
    let conn_args = if args.len() > 1 {
        ConnectorArgs::parse(&args[1]).expect("unable to parse arguments")
    } else {
        ConnectorArgs::new()
    };

    let connector = unsafe {
        inventory.create_connector("pcileech", &conn_args)
    }.unwrap();

    return connector
}

pub fn modules(program: &str) -> Result<()> {
    TermLogger::init(LevelFilter::Warn, Config::default(), TerminalMode::Mixed).unwrap();

    let mut connector= get_connector();

    // find ntoskrnl
    let mut kernel = Kernel::builder(connector)
        .build_default_caches()
        .build()
        .unwrap();

    // find program
    let process_info = kernel
        .process_info(program)
        .expect("unable to find process");
    println!("process info: {:?}", process_info);

    let mut process = Win32Process::with_kernel(kernel, process_info);
    println!("found process: {:?}", process);

    let module_info = process.module_info(program).unwrap();
    println!("found module: {:?}", module_info);

    let modules = process.module_list()?;
    println!("modules: {:?}", modules);

    let process_mod = modules.into_iter().find(|m| m.name == program)
        .ok_or(Error::Other("Could not find the module"))?;
    println!("process module info: {:?}", process_mod);

    let base = process_mod.base;
    println!("base address: {:?}", base);

    let p1_address: i32 = 0x052EAF30;

    let mem_map = process.virt_mem.virt_page_map(size::mb(16), Address::null(), (1u64 << 47).into());

    for (addr, size) in mem_map {
        println!("{:x}, {:x}", addr, size);
    }

    //let data = process.virt_mem.virt_read_addr(Address::from(p1_address));
    //println!("data: {:?}", data);

    /*
    for i in 0..process_mod.size {
        let mut buf = vec![0; p1_address.len()];
        process.virt_mem.virt_read_raw_into(base + i, &mut buf).data_part()?;
        if target_str == buf.as_slice() {
            println!("Match found at {:x}!", base + i);
        }
    }

     */


    Ok(())
}