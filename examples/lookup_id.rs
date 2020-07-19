use pciids::PciIdData;

use anyhow::{Context, Result};

#[derive(structopt::StructOpt)]
struct Args {
    #[structopt(long = "pci-ids-file")]
    #[cfg_attr(
        target_os = "linux",
        structopt(default_value = "/usr/share/misc/pci.ids")
    )]
    #[cfg_attr(target_os = "redox", structopt(default_value = "/share/misc/pci.ids"))]
    pci_ids_file: String,

    #[structopt(subcommand)]
    subcommand: Subcommand,
}

fn parse_from_hex_u8(src: &str) -> Result<u8> {
    let num = u8::from_str_radix(src, 16)?;
    Ok(num)
}

fn parse_from_hex_u16(src: &str) -> Result<u16> {
    let num = u16::from_str_radix(src, 16)?;
    Ok(num)
}

fn parse_from_hex_u16u16(src: &str) -> Result<(u16, u16)> {
    let n = u32::from_str_radix(src, 16)?;
    Ok(((n >> 16) as u16, (0xFF & n) as u16))
}

#[derive(Debug, PartialEq, structopt::StructOpt)]
enum Subcommand {
    Device(Device),
    Class(Class),
}

#[derive(Debug, PartialEq, structopt::StructOpt)]
struct Device {
    #[structopt(parse(try_from_str = parse_from_hex_u16))]
    vendor: u16,

    #[structopt(parse(try_from_str = parse_from_hex_u16))]
    device: Option<u16>,

    #[structopt(parse(try_from_str = parse_from_hex_u16u16))]
    subsystem: Option<(u16, u16)>,
}

#[derive(Debug, PartialEq, structopt::StructOpt)]
struct Class {
    #[structopt(parse(try_from_str = parse_from_hex_u8))]
    class: u8,

    #[structopt(parse(try_from_str = parse_from_hex_u8))]
    subclass: Option<u8>,

    #[structopt(parse(try_from_str = parse_from_hex_u8))]
    prog_interface: Option<u8>,
}

#[paw::main]
fn main(args: Args) -> Result<()> {
    let mut pci_id_data = PciIdData::new();
    let pci_id_file_contents =
        std::fs::read_to_string(args.pci_ids_file).expect("cannot read file");
    pci_id_data.add_pci_ids_data(&mut pci_id_file_contents.as_bytes())?;

    match args.subcommand {
        Subcommand::Device(d) => print_device(d, &pci_id_data)?,
        Subcommand::Class(c) => print_class(c, &pci_id_data)?,
    };
    Ok(())
}

fn print_device(device_args: Device, pci_data: &PciIdData) -> Result<()> {
    let mut msg = String::from(format!(
        "Looking up about vendor[:device][:subsystem]: {:01$X}",
        device_args.vendor, 4
    ));
    if let Some(device) = device_args.device {
        msg.push_str(format!(":{:01$X}", device, 4).as_str());
        if let Some(subsystem) = device_args.subsystem {
            msg.push_str(format!(".{:02$X}{:02$X}", subsystem.0, subsystem.1, 4).as_str());
        }
    }
    println!("{}", msg);

    let vendor = pci_data
        .get_vendor(&device_args.vendor)
        .context("Vendor not found.")?;
    println!("Vendor name: {}", vendor.name);
    if let Some(device) = device_args.device {
        println!("Device name: {}", device);
        if let Some(subsystem) = device_args.subsystem {
            println!("Subsystem name: {} {}", subsystem.0, subsystem.1);
        } else {
            println!("Subsystem not found.");
        }
    }
    Ok(())
}

fn print_class(class_args: Class, pci_data: &PciIdData) -> Result<()> {
    let mut msg = String::from(format!(
        "Looking up info about class[:subclass][.prog_interface]: {:01$X}",
        class_args.class, 2
    ));
    if let Some(subclass) = class_args.subclass {
        msg.push_str(format!(":{:01$X}", subclass, 2).as_str());
        if let Some(prog_interface) = class_args.prog_interface {
            msg.push_str(format!(".{:01$X}", prog_interface, 2).as_str());
        }
    }
    println!("{}", msg);

    let class = pci_data
        .get_class(&class_args.class)
        .context("Vendor not found")?;
    println!("Class name: {}", class.name);
    if let Some(subclass_id) = &class_args.subclass {
        let subclass = class
            .get_subclass(&subclass_id)
            .context("Subclass not found")?;
        println!("Subclass name: {}", subclass.name);
        if let Some(prog_interface_id) = &class_args.prog_interface {
            let prog_interface = subclass
                .get_prog_interface(prog_interface_id)
                .context("Programming interface not found.")?;
            println!("Programming interface name: {}", prog_interface.name);
        }
    }
    Ok(())
}
