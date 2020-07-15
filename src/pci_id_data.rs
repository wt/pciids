use std::collections::HashMap;
use std::concat;

use anyhow::{anyhow, Context, Result};
use log::{debug, info};
use pest::Parser;
use pest_derive::Parser;

#[derive(Debug)]
pub struct PciIdData {
    vendors: PciVendors,
    classes: PciClasses,
}

impl PciIdData {
    pub fn new() -> Self {
        PciIdData {
            vendors: PciVendors::new(),
            classes: PciClasses::new(),
        }
    }

    pub fn add_pci_ids_data(self: &mut PciIdData, pciids_data_stream: &mut dyn std::io::Read) -> Result<(), std::io::Error> {
        let mut num_vendors = 0;
        let mut num_devices = 0;
        let mut num_subsystems = 0;
        let mut num_classes = 0;
        let mut num_subclasses = 0;
        let mut num_prog_ifs = 0;

        info!("Parsing pci.id data!");
        let mut unparsed_data = String::new();
        pciids_data_stream.read_to_string(&mut unparsed_data)?;
        if let Ok(parse) = PciIdsParser::parse(Rule::file, &unparsed_data) {
            let mut current_vendor_id: Option<u16> = None;
            let mut current_device_id: Option<u16> = None;
            let mut current_class_id: Option<u8> = None;
            let mut current_subclass_id: Option<u8> = None;

            for line_pair in parse {
                match line_pair.as_rule() {
                    Rule::vendor_line => {
                        num_vendors += 1;
                        info!("vendor: {:#?}", &line_pair);

                        // set only current_vendor_id
                        // unset all others
                        current_device_id = None; //set this Some(id)
                        current_class_id = None;
                        current_subclass_id = None;

                        if let Ok((vendor_id, vendor_name)) = get_vendor_id_and_name(line_pair) {
                            current_vendor_id = Some(vendor_id);
                            let pci_vendor = PciVendor::new(vendor_id, &vendor_name);
                            self.vendors.insert(vendor_id, pci_vendor);
                        }
                    }
                    Rule::device_line => {
                        num_devices += 1;
                        info!("device: {:#?}", &line_pair);

                        // leave current_vendor_id set
                        // set only current_device_id
                        // unset all others
                        current_class_id = None;
                        current_subclass_id = None;

                        if let Ok((device_id, device_name)) = get_device_id_and_name(line_pair) {
                            current_device_id = Some(device_id);
                            let pci_device = PciDevice::new(device_id, &device_name);
                            if let Some(vendor) =
                                self.vendors.get_mut(&current_vendor_id.unwrap())
                            {
                                vendor.devices.insert(device_id, pci_device);
                            }
                            debug!(
                                "devices {:?}",
                                self.vendors[&current_vendor_id.unwrap()].devices
                            );
                        }
                    }
                    Rule::subsystem_line => {
                        num_subsystems += 1;
                        info!("subsystem: {:#?}", &line_pair);
                        // leave current_vendor_id set
                        // leave current_device_id set
                        // unset all others
                        current_class_id = None;
                        current_subclass_id = None;

                        if let Ok((subvendor_id, subdevice_id, subsystem_name)) =
                            get_subsystem_ids_and_name(line_pair)
                        {
                            if let Some(vendor) =
                                self.vendors.get_mut(&current_vendor_id.unwrap())
                            {
                                if let Some(device) =
                                    vendor.devices.get_mut(&current_device_id.unwrap())
                                {
                                    let pci_subsystem = PciSubsystem::new(
                                        subvendor_id,
                                        subdevice_id,
                                        &subsystem_name,
                                    );
                                    device
                                        .subsystems
                                        .insert((subvendor_id, subdevice_id), pci_subsystem);
                                }
                            }
                        }
                    }
                    Rule::class_line => {
                        num_classes += 1;
                        info!("class: {:#?}", &line_pair);

                        // set only current_class_id
                        // unset all others
                        current_vendor_id = None;
                        current_device_id = None;
                        current_subclass_id = None;

                        if let Ok((class_id, class_name)) = get_class_id_and_name(line_pair) {
                            current_class_id = Some(class_id);
                            let pci_class = PciClass::new(class_id, &class_name);
                            self.classes.insert(class_id, pci_class);
                        }
                    }
                    Rule::subclass_line => {
                        // uset all but class id
                        // set current subclass id
                        num_subclasses += 1;
                        info!("subclass: {:#?}", &line_pair);

                        // leave current_class_id set
                        // set only current_subclass_id
                        // unset all others
                        current_vendor_id = None;
                        current_device_id = None;

                        if let Ok((subclass_id, subclass_name)) = get_subclass_id_and_name(line_pair) {
                            current_subclass_id = Some(subclass_id);
                            let pci_subclass = PciSubclass::new(subclass_id, &subclass_name);
                            if let Some(class) =
                                self.classes.get_mut(&current_class_id.unwrap())
                            {
                                class.subclasses.insert(subclass_id, pci_subclass);
                            }
                            debug!(
                                "subclasss {:?}",
                                self.classes[&current_class_id.unwrap()].subclasses
                            );
                        }
                    }
                    Rule::prog_if_line => {
                        // uset all but class and subclass ids
                        // set current programming interface id
                        num_prog_ifs += 1;
                        info!("programming interface: {:#?}", &line_pair);

                        // leave current_class_id set
                        // leave current_subclass_id set
                        // unset all others
                        current_vendor_id = None;
                        current_device_id = None;

                        if let Ok((prog_if_id, prog_if_name)) = get_prog_if_id_and_name(line_pair) {
                            let pci_prog_if = PciProgInterface::new(prog_if_id, &prog_if_name);
                            if let Some(class) =
                                self.classes.get_mut(&current_class_id.unwrap())
                            {
                                if let Some(subclass) =
                                    class.subclasses.get_mut(&current_subclass_id.unwrap())
                                {
                                    subclass.prog_interfaces.insert(prog_if_id, pci_prog_if);
                                }
                            }
                            debug!(
                                "prog_ifs {:?}",
                                self.classes[&current_class_id.unwrap()].subclasses[&current_class_id.unwrap()].prog_interfaces
                            );
                        }
                    }
                    Rule::EOI => info!("End of input reached."),
                    _ => info!("Encoutered an unexpected type."),
                }
            }
            info!(
                concat!(
                    "Number of objects imported from the pci.ids database: ",
                    "vendors({}), devices({}), subsystems({}), classes({}), ",
                    "subclasses({}), and programming interfaces({})"
                ),
                num_vendors, num_devices, num_subsystems, num_classes, num_subclasses, num_prog_ifs
            );
        } else {
            info!("Couldn't parse pci.ids file.");
        }

        Ok(())
    }
}

type PciVendors = HashMap<u16, PciVendor>;

#[derive(Debug)]
struct PciVendor {
    id: u16,
    name: String,
    devices: HashMap<u16, PciDevice>,
}

impl PciVendor {
    fn new(id: u16, name: &str) -> Self {
        PciVendor {
            id,
            name: String::from(name),
            devices: HashMap::new(),
        }
    }
}

#[derive(Debug)]
struct PciDevice {
    id: u16,
    name: String,
    subsystems: HashMap<(u16, u16), PciSubsystem>,
}

impl PciDevice {
    fn new(id: u16, name: &str) -> Self {
        PciDevice {
            id,
            name: String::from(name),
            subsystems: HashMap::new(),
        }
    }
}

#[derive(Debug)]
struct PciSubsystem {
    subvendor_id: u16,
    subdevice_id: u16,
    name: String,
}

impl PciSubsystem {
    fn new(subvendor_id: u16, subdevice_id: u16, name: &str) -> Self {
        PciSubsystem {
            subvendor_id,
            subdevice_id,
            name: String::from(name),
        }
    }
}

type PciClasses = HashMap<u8, PciClass>;

#[derive(Debug)]
struct PciClass {
    id: u8,
    name: String,
    subclasses: HashMap<u8, PciSubclass>,
}

impl PciClass {
    fn new(id: u8, name: &str) -> Self {
        PciClass {
            id,
            name: String::from(name),
            subclasses: HashMap::new(),
        }
    }
}

#[derive(Debug)]
struct PciSubclass {
    id: u8,
    name: String,
    prog_interfaces: HashMap<u8, PciProgInterface>,
}

impl PciSubclass {
    fn new(id: u8, name: &str) -> Self {
        PciSubclass {
            id,
            name: String::from(name),
            prog_interfaces: HashMap::new(),
        }
    }
}

#[derive(Debug)]
struct PciProgInterface {
    id: u8,
    name: String,
}

impl PciProgInterface {
    fn new(id: u8, name: &str) -> Self {
        PciProgInterface {
            id,
            name: String::from(name),
        }
    }
}

#[derive(Parser)]
#[grammar = "pciids.pest"]
struct PciIdsParser;

fn get_vendor_id_and_name(line_pair: pest::iterators::Pair<Rule>) -> Result<(u16, &str)> {
    let mut vendor_id = None;
    let mut vendor_name = None;
    for vendor_pair in line_pair.into_inner() {
        match vendor_pair.as_rule() {
            Rule::vendor_id => {
                vendor_id = Some(
                    u16::from_str_radix(vendor_pair.as_str(), 16)
                        .with_context(|| format!("Invalid vendor_id: {}", vendor_pair.as_str()))?,
                );
                debug!("vendor_id: {}", &vendor_id.unwrap());
            }
            Rule::vendor_name => {
                vendor_name = Some(vendor_pair.as_str());
                debug!("vendor_name: {}", &vendor_name.unwrap());
            }
            _ => {
                return Err(anyhow!("unknown vendor_pair:\n{:#?}", vendor_pair));
            }
        }
    }

    match (vendor_id, vendor_name) {
        (Some(id), Some(name)) => Ok((id, name)),
        _ => Err(anyhow!(
            "Couldn't find vendor id/name. This should never be seen by a user."
        )),
    }
}

fn get_device_id_and_name(line_pair: pest::iterators::Pair<Rule>) -> Result<(u16, &str)> {
    let mut device_id = None;
    let mut device_name = None;
    for device_pair in line_pair.into_inner() {
        match device_pair.as_rule() {
            Rule::device_id => {
                device_id = Some(
                    u16::from_str_radix(device_pair.as_str(), 16)
                        .with_context(|| format!("Invalid device_id: {}", device_pair.as_str()))?,
                );
                debug!("device_id: {}", &device_id.unwrap());
            }
            Rule::device_name => {
                device_name = Some(device_pair.as_str());
                debug!("device_name: {}", &device_name.unwrap());
            }
            _ => {
                return Err(anyhow!("unknown device_pair:\n{:#?}", device_pair));
            }
        }
    }

    match (device_id, device_name) {
        (Some(id), Some(name)) => Ok((id, name)),
        _ => Err(anyhow!(
            "Couldn't find device id/name. This should never be seen by a user."
        )),
    }
}

fn get_subsystem_ids_and_name(line_pair: pest::iterators::Pair<Rule>) -> Result<(u16, u16, &str)> {
    //let Ok((subvendor_id, subdevice_id, device_name)) = get_subsystem_ids_and_name(line_pair) {
    let mut subvendor_id = None;
    let mut subdevice_id = None;
    let mut subsystem_name = None;
    for subsystem_pair in line_pair.into_inner() {
        match subsystem_pair.as_rule() {
            Rule::subsystem_id => {
                println!("{:#?}", subsystem_pair);
                for subsystem_id_pair in subsystem_pair.into_inner() {
                    match subsystem_id_pair.as_rule() {
                        Rule::subvendor_id => {
                            subvendor_id = Some(
                                u16::from_str_radix(subsystem_id_pair.as_str(), 16).with_context(
                                    || {
                                        format!(
                                            "Invalid subvendor_id: {}",
                                            subsystem_id_pair.as_str()
                                        )
                                    },
                                )?,
                            );
                            debug!("subvendor_id: {}", &subvendor_id.unwrap());
                        }
                        Rule::subdevice_id => {
                            subdevice_id = Some(
                                u16::from_str_radix(subsystem_id_pair.as_str(), 16).with_context(
                                    || {
                                        format!(
                                            "Invalid subvendor_id: {}",
                                            subsystem_id_pair.as_str()
                                        )
                                    },
                                )?,
                            );
                            debug!("subdevice_id: {}", &subdevice_id.unwrap());
                        }
                        _ => {
                            return Err(anyhow!(
                                "unknown subsystem_pair:\n{:#?}",
                                subsystem_id_pair
                            ));
                        }
                    }
                }
            }
            Rule::subsystem_name => {
                subsystem_name = Some(subsystem_pair.as_str());
                debug!("subsystem_name: {}", &subsystem_name.unwrap());
                println!("{:#?}", subsystem_pair.as_str());
            }
            _ => {
                return Err(anyhow!("unknown subsystem_pair:\n{:#?}", subsystem_pair));
            }
        }
    }

    match (subvendor_id, subdevice_id, subsystem_name) {
        (Some(subvendor_id), Some(subdevice_id), Some(name)) => {
            Ok((subvendor_id, subdevice_id, name))
        }
        _ => Err(anyhow!(
            "Couldn't find subsystem ids/name. This should never be seen by a user."
        )),
    }
}

fn get_class_id_and_name(line_pair: pest::iterators::Pair<Rule>) -> Result<(u8, &str)> {
    let mut class_id = None;
    let mut class_name = None;
    for class_pair in line_pair.into_inner() {
        match class_pair.as_rule() {
            Rule::class_id => {
                class_id = Some(
                    u8::from_str_radix(class_pair.as_str(), 16)
                        .with_context(|| format!("Invalid class_id: {}", class_pair.as_str()))?,
                );
                debug!("class_id: {}", &class_id.unwrap());
            }
            Rule::class_name => {
                class_name = Some(class_pair.as_str());
                debug!("class_name: {}", &class_name.unwrap());
            }
            _ => {
                return Err(anyhow!("unknown class_pair:\n{:#?}", class_pair));
            }
        }
    }

    match (class_id, class_name) {
        (Some(id), Some(name)) => Ok((id, name)),
        _ => Err(anyhow!(
            "Couldn't find class id/name. This should never be seen by a user."
        )),
    }
}

fn get_subclass_id_and_name(line_pair: pest::iterators::Pair<Rule>) -> Result<(u8, &str)> {
    let mut subclass_id = None;
    let mut subclass_name = None;
    for subclass_pair in line_pair.into_inner() {
        match subclass_pair.as_rule() {
            Rule::subclass_id => {
                subclass_id = Some(
                    u8::from_str_radix(subclass_pair.as_str(), 16)
                        .with_context(|| format!("Invalid subclass_id: {}", subclass_pair.as_str()))?,
                );
                debug!("subclass_id: {}", &subclass_id.unwrap());
            }
            Rule::subclass_name => {
                subclass_name = Some(subclass_pair.as_str());
                debug!("subclass_name: {}", &subclass_name.unwrap());
            }
            _ => {
                return Err(anyhow!("unknown subclass_pair:\n{:#?}", subclass_pair));
            }
        }
    }

    match (subclass_id, subclass_name) {
        (Some(id), Some(name)) => Ok((id, name)),
        _ => Err(anyhow!(
            "Couldn't find subclass id/name. This should never be seen by a user."
        )),
    }
}

fn get_prog_if_id_and_name(line_pair: pest::iterators::Pair<Rule>) -> Result<(u8, &str)> {
    let mut prog_if_id = None;
    let mut prog_if_name = None;
    for prog_if_pair in line_pair.into_inner() {
        match prog_if_pair.as_rule() {
            Rule::prog_if_id => {
                prog_if_id = Some(
                    u8::from_str_radix(prog_if_pair.as_str(), 16)
                        .with_context(|| format!("Invalid prog_if_id: {}", prog_if_pair.as_str()))?,
                );
                debug!("prog_if_id: {}", &prog_if_id.unwrap());
            }
            Rule::prog_if_name => {
                prog_if_name = Some(prog_if_pair.as_str());
                debug!("prog_if_name: {}", &prog_if_name.unwrap());
            }
            _ => {
                return Err(anyhow!("unknown prog_if_pair:\n{:#?}", prog_if_pair));
            }
        }
    }

    match (prog_if_id, prog_if_name) {
        (Some(id), Some(name)) => Ok((id, name)),
        _ => Err(anyhow!(
            "Couldn't find programming interface id/name. This should never be seen by a user."
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;

    fn hex_char_width<T>() -> usize {
        2 * std::mem::size_of::<T>()
    }

    #[test]
    fn test_vendor_parse() -> Result<()> {
        let expected_vendor_id = format!("{:0u16width$X}", rand::random::<u16>(), u16width=hex_char_width::<u16>());
        let expected_vendor_name = "Fake vendor";

        let unparsed_data = format!("{} {}", expected_vendor_id, expected_vendor_name);
        println!("Unparsed_data: {:?}", &unparsed_data);

        let mut parsed_data = PciIdsParser::parse(Rule::vendor_line, &unparsed_data)?;

        let vendor_line_pair = parsed_data.next().ok_or(anyhow!("No vendor line."))?;
        let mut line_inners = match vendor_line_pair.as_rule() {
            Rule::vendor_line => {
                Ok(vendor_line_pair.into_inner())
            },
            _ => {Err(anyhow!("Vendor line didn't parse as such."))},
        }?;
        let end = parsed_data.next();
        assert!(end.is_none(), "Something found after vendor line.");

        let vendor_id_pair = line_inners.next().ok_or(anyhow!("No vendor id."))?;
        assert_eq!(vendor_id_pair.as_str(), expected_vendor_id, "Vendor id doesn't match.");
        let vendor_name_pair = line_inners.next().ok_or(anyhow!("No vendor name."))?;
        assert_eq!(vendor_name_pair.as_str(), expected_vendor_name, "Vendor name doesn't match.");
        let end = line_inners.next();
        assert!(end.is_none(), "Something found after vendor name.");
        Ok(())
    }

    #[test]
    fn test_vendor_values() -> Result<()> {
        let expected_vendor_id = rand::random::<u16>();
        let expected_vendor_name = "Fake vendor";

        let unparsed_data = format!("{:0u16width$X} {}", expected_vendor_id, expected_vendor_name, u16width=hex_char_width::<u16>());
        println!("Unparsed_data: {:?}", &unparsed_data);

        let mut parsed_data = PciIdsParser::parse(Rule::vendor_line, &unparsed_data)?;

        let vendor_line_pair = parsed_data.next().ok_or(anyhow!("No vendor line."))?;
        let (vendor_id, vendor_name) = get_vendor_id_and_name(vendor_line_pair)?;
        assert_eq!(vendor_id, expected_vendor_id);
        assert_eq!(vendor_name, expected_vendor_name);
        Ok(())
    }

    #[test]
    fn test_device_parse() -> Result<()> {
        let expected_device_id = format!("{:0u16width$X}", rand::random::<u16>(), u16width=hex_char_width::<u16>());
        let expected_device_name = "Fake device";

        let unparsed_data = format!("\t{} {}", expected_device_id, expected_device_name);
        println!("Unparsed_data: {:?}", &unparsed_data);

        let mut parsed_data = PciIdsParser::parse(Rule::device_line, &unparsed_data)?;

        let device_line_pair = parsed_data.next().ok_or(anyhow!("No device line."))?;
        let mut line_inners = match device_line_pair.as_rule() {
            Rule::device_line => {
                Ok(device_line_pair.into_inner())
            },
            _ => {Err(anyhow!("Device line didn't parse as such."))},
        }?;
        let end = parsed_data.next();
        assert!(end.is_none(), "Something found after device line.");

        let device_id_pair = line_inners.next().ok_or(anyhow!("No device id."))?;
        assert_eq!(device_id_pair.as_str(), expected_device_id, "Device id doesn't match.");
        let device_name_pair = line_inners.next().ok_or(anyhow!("No device name."))?;
        assert_eq!(device_name_pair.as_str(), expected_device_name, "Device name doesn't match.");
        let end = line_inners.next();
        assert!(end.is_none(), "Something found after device name.");
        Ok(())
    }

    #[test]
    fn test_device_values() -> Result<()> {
        let expected_device_id = rand::random::<u16>();
        let expected_device_name = "Fake device";

        let unparsed_data = format!("\t{:0u16width$X} {}", expected_device_id, expected_device_name, u16width=hex_char_width::<u16>());
        println!("Unparsed_data: {:?}", &unparsed_data);

        let mut parsed_data = PciIdsParser::parse(Rule::device_line, &unparsed_data)?;

        let device_line_pair = parsed_data.next().ok_or(anyhow!("No device line."))?;
        let (device_id, device_name) = get_device_id_and_name(device_line_pair)?;
        assert_eq!(device_id, expected_device_id);
        assert_eq!(device_name, expected_device_name);
        Ok(())
    }

    #[test]
    fn test_subsystem_parse() -> Result<()> {
        let expected_subvendor_id = format!("{:0u16width$X}", rand::random::<u16>(), u16width=hex_char_width::<u16>());
        let expected_subdevice_id = format!("{:0u16width$X}", rand::random::<u16>(), u16width=hex_char_width::<u16>());
        let expected_subsystem_name = "Fake subsystem";

        let unparsed_data = format!("\t\t{} {} {}", expected_subvendor_id, expected_subdevice_id, expected_subsystem_name);
        println!("Unparsed_data: {:?}", &unparsed_data);

        let mut parsed_data = PciIdsParser::parse(Rule::subsystem_line, &unparsed_data)?;

        let subsystem_line_pair = parsed_data.next().ok_or(anyhow!("No subsystem line."))?;
        let mut line_inners = match subsystem_line_pair.as_rule() {
            Rule::subsystem_line => {
                Ok(subsystem_line_pair.into_inner())
            },
            _ => {Err(anyhow!("Subsystem line didn't parse as such."))},
        }?;
        let end = parsed_data.next();
        assert!(end.is_none(), "Something found after subsystem line.");

        let subsystem_id_pairs = line_inners.next().ok_or(anyhow!("No system id."))?;
        let mut subsystem_id_inners = match subsystem_id_pairs.as_rule() {
            Rule::subsystem_id => {
                Ok(subsystem_id_pairs.into_inner())
            },
            _ => {Err(anyhow!("Subsystem line ids didn't parse as such."))},
        }?;
        let end = parsed_data.next();
        assert!(end.is_none(), "Some id found after subsystem ids.");

        let subvendor_id_pair = subsystem_id_inners.next().ok_or(anyhow!("No subvendor id."))?;
        assert_eq!(subvendor_id_pair.as_str(), expected_subvendor_id, "Subvendor id doesn't match.");
        let subdevice_id_pair = subsystem_id_inners.next().ok_or(anyhow!("No subdevice id."))?;
        assert_eq!(subdevice_id_pair.as_str(), expected_subdevice_id, "Subdevice id doesn't match.");
        let subsystem_name_pair = line_inners.next().ok_or(anyhow!("No subsystem name."))?;
        assert_eq!(subsystem_name_pair.as_str(), expected_subsystem_name, "Subsystem name doesn't match.");
        let end = subsystem_id_inners.next();
        assert!(end.is_none(), "Something found after subsystem name.");
        Ok(())
    }

    #[test]
    fn test_subsystem_values() -> Result<()> {
        let expected_subvendor_id = rand::random::<u16>();
        let expected_subdevice_id = rand::random::<u16>();
        let expected_subsystem_name = "Fake subsystem";

        let unparsed_data = format!("\t\t{:0u16width$X} {:0u16width$X} {}", expected_subvendor_id, expected_subdevice_id, expected_subsystem_name, u16width=hex_char_width::<u16>());
        println!("Unparsed_data: {:?}", &unparsed_data);

        let mut parsed_data = PciIdsParser::parse(Rule::subsystem_line, &unparsed_data)?;

        let subsystem_line_pair = parsed_data.next().ok_or(anyhow!("No subsystem line."))?;
        let (subvendor_id, subdevice_id, subsystem_name) = get_subsystem_ids_and_name(subsystem_line_pair)?;
        assert_eq!(subvendor_id, expected_subvendor_id);
        assert_eq!(subdevice_id, expected_subdevice_id);
        assert_eq!(subsystem_name, expected_subsystem_name);
        Ok(())
    }

    #[test]
    fn test_class_parse() -> Result<()> {
        let expected_class_id = format!("{:0u8width$X}", rand::random::<u8>(), u8width=hex_char_width::<u8>());
        let expected_class_name = "Fake class";

        let unparsed_data = format!("C {} {}", expected_class_id, expected_class_name);
        println!("Unparsed_data: {:?}", &unparsed_data);

        let mut parsed_data = PciIdsParser::parse(Rule::class_line, &unparsed_data)?;

        let class_line_pair = parsed_data.next().ok_or(anyhow!("No class line."))?;
        let mut line_inners = match class_line_pair.as_rule() {
            Rule::class_line => {
                Ok(class_line_pair.into_inner())
            },
            _ => {Err(anyhow!("Class line didn't parse as such."))},
        }?;
        let end = parsed_data.next();
        assert!(end.is_none(), "Something found after class line.");

        let class_id_pair = line_inners.next().ok_or(anyhow!("No class id."))?;
        assert_eq!(class_id_pair.as_str(), expected_class_id, "Class id doesn't match.");
        let class_name_pair = line_inners.next().ok_or(anyhow!("No class name."))?;
        assert_eq!(class_name_pair.as_str(), expected_class_name, "Class name doesn't match.");
        let end = line_inners.next();
        assert!(end.is_none(), "Something found after class name.");
        Ok(())
    }

    #[test]
    fn test_class_values() -> Result<()> {
        let expected_class_id = rand::random::<u8>();
        let expected_class_name = "Fake class";

        let unparsed_data = format!("C {:0u8width$X} {}", expected_class_id, expected_class_name, u8width=hex_char_width::<u8>());
        println!("Unparsed_data: {:?}", &unparsed_data);

        let mut parsed_data = PciIdsParser::parse(Rule::class_line, &unparsed_data)?;

        let class_line_pair = parsed_data.next().ok_or(anyhow!("No class line."))?;
        let (class_id, class_name) = get_class_id_and_name(class_line_pair)?;
        assert_eq!(class_id, expected_class_id);
        assert_eq!(class_name, expected_class_name);
        Ok(())
    }

    #[test]
    fn test_subclass_parse() -> Result<()> {
        let expected_subclass_id = format!("{:0u8width$X}", rand::random::<u8>(), u8width=hex_char_width::<u8>());
        let expected_subclass_name = "Fake subclass";

        let unparsed_data = format!("\t{} {}", expected_subclass_id, expected_subclass_name);
        println!("Unparsed_data: {:?}", &unparsed_data);

        let mut parsed_data = PciIdsParser::parse(Rule::subclass_line, &unparsed_data)?;

        let subclass_line_pair = parsed_data.next().ok_or(anyhow!("No prodgramming interface line."))?;
        let mut line_inners = match subclass_line_pair.as_rule() {
            Rule::subclass_line => {
                Ok(subclass_line_pair.into_inner())
            },
            _ => {Err(anyhow!("Programming interface line didn't parse as such."))},
        }?;
        let end = parsed_data.next();
        assert!(end.is_none(), "Something found after subclass line.");

        let subclass_id_pair = line_inners.next().ok_or(anyhow!("No subclass id."))?;
        assert_eq!(subclass_id_pair.as_str(), expected_subclass_id, "Subclass id doesn't match.");
        let subclass_name_pair = line_inners.next().ok_or(anyhow!("No subclass name."))?;
        assert_eq!(subclass_name_pair.as_str(), expected_subclass_name, "Subclass name doesn't match.");
        let end = line_inners.next();
        assert!(end.is_none(), "Something found after subclass name.");
        Ok(())
    }

    #[test]
    fn test_subclass_values() -> Result<()> {
        let expected_subclass_id = rand::random::<u8>();
        let expected_subclass_name = "Fake subclass";

        let unparsed_data = format!("\t{:0u8width$X} {}", expected_subclass_id, expected_subclass_name, u8width=hex_char_width::<u8>());
        println!("Unparsed_data: {:?}", &unparsed_data);

        let mut parsed_data = PciIdsParser::parse(Rule::subclass_line, &unparsed_data)?;

        let subclass_line_pair = parsed_data.next().ok_or(anyhow!("No subclass line."))?;
        let (subclass_id, subclass_name) = get_subclass_id_and_name(subclass_line_pair)?;
        assert_eq!(subclass_id, expected_subclass_id);
        assert_eq!(subclass_name, expected_subclass_name);
        Ok(())
    }

    #[test]
    fn test_prog_if_parse() -> Result<()> {
        let expected_prog_if_id = format!("{:0u8width$X}", rand::random::<u8>(), u8width=hex_char_width::<u8>());
        let expected_prog_if_name = "Fake programming interface";

        let unparsed_data = format!("\t\t{} {}", expected_prog_if_id, expected_prog_if_name);
        println!("Unparsed_data: {:?}", &unparsed_data);

        let mut parsed_data = PciIdsParser::parse(Rule::prog_if_line, &unparsed_data)?;

        let prog_if_line_pair = parsed_data.next().ok_or(anyhow!("No programming interface line."))?;
        let mut line_inners = match prog_if_line_pair.as_rule() {
            Rule::prog_if_line => {
                Ok(prog_if_line_pair.into_inner())
            },
            _ => {Err(anyhow!("Programming interface line didn't parse as such."))},
        }?;
        let end = parsed_data.next();
        assert!(end.is_none(), "Something found after programming interface line.");

        let prog_if_id_pair = line_inners.next().ok_or(anyhow!("No programming interface id."))?;
        assert_eq!(prog_if_id_pair.as_str(), expected_prog_if_id, "Programming interface id doesn't match.");
        let prog_if_name_pair = line_inners.next().ok_or(anyhow!("No programming interface name."))?;
        assert_eq!(prog_if_name_pair.as_str(), expected_prog_if_name, "Programming interface name doesn't match.");
        let end = line_inners.next();
        assert!(end.is_none(), "Something found after programming interface name.");
        Ok(())
    }

    #[test]
    fn test_prog_if_values() -> Result<()> {
        let expected_prog_if_id = rand::random::<u8>();
        let expected_prog_if_name = "Fake programming interface";

        let unparsed_data = format!("\t\t{:0u8width$X} {}", expected_prog_if_id, expected_prog_if_name, u8width=2);
        println!("Unparsed_data: {:?}", &unparsed_data);

        let mut parsed_data = PciIdsParser::parse(Rule::prog_if_line, &unparsed_data)?;

        let prog_if_line_pair = parsed_data.next().ok_or(anyhow!("No programming interface line."))?;
        let (prog_if_id, prog_if_name) = get_prog_if_id_and_name(prog_if_line_pair)?;
        assert_eq!(prog_if_id, expected_prog_if_id);
        assert_eq!(prog_if_name, expected_prog_if_name);
        Ok(())
    }
}
