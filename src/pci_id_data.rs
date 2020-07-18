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

    pub fn add_pci_ids_data(
        &mut self,
        pciids_data_stream: &mut dyn std::io::Read,
    ) -> Result<()> {
        let mut num_vendors = 0;
        let mut num_classes = 0;

        info!("Parsing pci.id data!");
        let mut unparsed_data = String::new();
        pciids_data_stream.read_to_string(&mut unparsed_data)?;
        if let Err(parse) = PciIdsParser::parse(Rule::file, &unparsed_data) {
            println!("{:?}", parse);
        }
        if let Ok(parse) = PciIdsParser::parse(Rule::file, &unparsed_data) {
            for line_pair in parse {
                match line_pair.as_rule() {
                    Rule::vendor => {
                        num_vendors += 1;
                        info!("vendor: {:#?}", &line_pair);
                        self.add_vendor_from_vendor_pairs(&mut line_pair.into_inner())?;
                    }
                    Rule::class => {
                        num_classes += 1;
                        info!("class: {:#?}", &line_pair);
                        self.add_class_from_class_pairs(&mut line_pair.into_inner())?;
                    }
                    Rule::EOI => info!("End of input reached."),
                    _ => unreachable!(),
                }
            }
            info!(
                concat!(
                    "Number of objects imported from the pci.ids database: ",
                    "vendors({}) and classes({})",
                ),
                num_vendors, num_classes
            );
        } else {
            info!("Couldn't parse pci.ids file.");
        }

        Ok(())
    }

    fn add_vendor_from_vendor_pairs(
        &mut self,
        vendor_pairs: &mut pest::iterators::Pairs<Rule>,
    ) -> Result<()> {
        let vendor_id_pair = vendor_pairs.next().ok_or(anyhow!("No vendor id found."))?;
        let vendor_id = u16::from_str_radix(vendor_id_pair.as_str(), 16)
            .with_context(|| format!("Invalid vendor_id: {}", vendor_id_pair.as_str()))?;
        let vendor_name = vendor_pairs
            .next()
            .ok_or(anyhow!("No vendor name found."))?
            .as_str();
        let mut pci_vendor = PciVendor::new(vendor_id, &vendor_name);
        while let Some(device_pair) = vendor_pairs.next() {
            pci_vendor.add_device_from_device_pairs(&mut device_pair.into_inner())?;
        }
        self.vendors.entry(vendor_id).or_insert(pci_vendor);
        Ok(())
    }

    fn add_class_from_class_pairs(
        &mut self,
        class_pairs: &mut pest::iterators::Pairs<Rule>,
    ) -> Result<()> {
        let class_id_pair = class_pairs.next().ok_or(anyhow!("No class id found."))?;
        let class_id = u8::from_str_radix(class_id_pair.as_str(), 16)
            .with_context(|| format!("Invalid class_id: {}", class_id_pair.as_str()))?;
        let class_name = class_pairs
            .next()
            .ok_or(anyhow!("No class name found."))?
            .as_str();
        let mut class = PciClass::new(class_id, &class_name);
        while let Some(subclass_pair) = class_pairs.next() {
            class.add_subclass_from_subclass_pairs(&mut subclass_pair.into_inner())?;
        }
        self.classes.entry(class_id).or_insert(class);
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

    fn add_device_from_device_pairs(
        &mut self,
        device_pairs: &mut pest::iterators::Pairs<Rule>,
    ) -> Result<()> {
        let device_id_pair = device_pairs.next().ok_or(anyhow!("No device id found."))?;
        let device_id = u16::from_str_radix(device_id_pair.as_str(), 16)
            .with_context(|| format!("Invalid device: {}", device_id_pair.as_str()))?;
        let device_name = device_pairs
            .next()
            .ok_or(anyhow!("No device name found."))?
            .as_str();
        let mut pci_device = PciDevice::new(device_id, &device_name);
        while let Some(subsystem_pair) = device_pairs.next() {
            pci_device.add_subsystem_from_subsystem_pairs(&mut subsystem_pair.into_inner())?;
        }
        self.devices.entry(device_id).or_insert(pci_device);
        Ok(())
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

    fn add_subsystem_from_subsystem_pairs(
        &mut self,
        subsystem_pairs: &mut pest::iterators::Pairs<Rule>,
    ) -> Result<()> {
        let subsystem_id_pair = subsystem_pairs
            .next()
            .ok_or(anyhow!("No subsystem id found."))?;
        let mut subsystem_id_inners = match subsystem_id_pair.as_rule() {
            Rule::subsystem_id => Ok(subsystem_id_pair.into_inner()),
            _ => Err(anyhow!("Tried to add non subsystem to subsystem data.")),
        }?;
        let subvendor_id_pair = subsystem_id_inners
            .next()
            .ok_or(anyhow!("No subvendor id found."))?;
        let subvendor_id = u16::from_str_radix(subvendor_id_pair.as_str(), 16)?;
        debug!("subvendor_id_pair: {:#?}", &subvendor_id_pair);
        let subdevice_id_pair = subsystem_id_inners
            .next()
            .ok_or(anyhow!("No subdevice id found."))?;
        let subdevice_id = u16::from_str_radix(subdevice_id_pair.as_str(), 16)?;
        let subsystem_name = subsystem_pairs
            .next()
            .ok_or(anyhow!("No subsystem name found."))?
            .as_str();
        let pci_subsystem = PciSubsystem::new(subvendor_id, subdevice_id, &subsystem_name);
        self.subsystems
            .entry((subvendor_id, subdevice_id))
            .or_insert(pci_subsystem);
        Ok(())
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

    fn add_subclass_from_subclass_pairs(
        &mut self,
        subclass_pairs: &mut pest::iterators::Pairs<Rule>,
    ) -> Result<()> {
        let subclass_id_pair = subclass_pairs
            .next()
            .ok_or(anyhow!("No subclass id found."))?;
        let subclass_id = u8::from_str_radix(subclass_id_pair.as_str(), 16)
            .with_context(|| format!("Invalid subclass: {}", subclass_id_pair.as_str()))?;
        let subclass_name = subclass_pairs
            .next()
            .ok_or(anyhow!("No subclass name found."))?
            .as_str();
        let mut subclass = PciSubclass::new(subclass_id, &subclass_name);
        while let Some(prog_if_pair) = subclass_pairs.next() {
            subclass.add_prog_if_from_prog_if_pairs(&mut prog_if_pair.into_inner())?;
        }
        self.subclasses.entry(subclass_id).or_insert(subclass);
        Ok(())
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

    fn add_prog_if_from_prog_if_pairs(
        &mut self,
        prog_if_pairs: &mut pest::iterators::Pairs<Rule>,
    ) -> Result<()> {
        let prog_if_id_pair = prog_if_pairs
            .next()
            .ok_or(anyhow!("No programming interface id found."))?;
        let prog_if_id = u8::from_str_radix(prog_if_id_pair.as_str(), 16).with_context(|| {
            format!(
                "Invalid programming interface: {}",
                prog_if_id_pair.as_str()
            )
        })?;
        let prog_if_name = prog_if_pairs
            .next()
            .ok_or(anyhow!("No programming interface name found."))?
            .as_str();
        let prog_if = PciProgInterface::new(prog_if_id, &prog_if_name);
        self.prog_interfaces.entry(prog_if_id).or_insert(prog_if);
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use pest::consumes_to;
    use std::vec::Vec;

    fn hex_char_width<T>() -> usize {
        2 * std::mem::size_of::<T>()
    }

    fn as_max_len_hex_string<T: std::fmt::UpperHex>(n: T) -> String {
        format!("{:0width$X}", n, width = hex_char_width::<T>())
    }

    struct FakeVendorData {
        expected_id: u16,
        expected_id_hex_string: String,
        expected_name: String,
        unparsed_data: String,
        simple_unparsed_data: String,
        devices: Vec<FakeDeviceData>,
    }

    impl FakeVendorData {
        fn new_with_devices(devices: Vec<FakeDeviceData>) -> Self {
            let expected_id = rand::random::<_>();
            let expected_name = format!("Fake vendor ({})", as_max_len_hex_string(expected_id));
            let simple_unparsed_data = format!("{} {}", as_max_len_hex_string(expected_id), expected_name);
            let full_unparsed_data = devices.iter().map(|d| d.unparsed_data.clone()).fold(simple_unparsed_data.clone(), |acc, x| format!("{}\n{}", acc, x));
            FakeVendorData {
                expected_id: expected_id,
                expected_id_hex_string: as_max_len_hex_string(expected_id),
                expected_name: expected_name.clone(),
                unparsed_data: full_unparsed_data,
                simple_unparsed_data: simple_unparsed_data,
                devices: devices,
            }
        }

        fn new() -> Self {
            Self::new_with_devices(Vec::<_>::new())
        }

        fn check(&self, vendor: &PciVendor) -> Result<()> {
            assert_eq!(vendor.id, self.expected_id);
            assert_eq!(vendor.name, self.expected_name);
            Ok(())
        }
    }

    #[test]
    fn test_vendor_simple_parse() -> Result<()> {
        let fake_vendor_data = FakeVendorData::new();

        println!("Unparsed_data: {:?}", &fake_vendor_data.unparsed_data);

        pest::parses_to! {
            parser: PciIdsParser,
            input: &fake_vendor_data.unparsed_data,
            rule: Rule::vendor,
            tokens: [
                vendor(0, fake_vendor_data.unparsed_data.len(), [
                    vendor_id(0, 4),
                    vendor_name(5, fake_vendor_data.unparsed_data.len())
                ])
            ]
        };

        let mut parsed_data = PciIdsParser::parse(Rule::vendor, &fake_vendor_data.unparsed_data)?;

        let vendor_pair = parsed_data.next().ok_or(anyhow!("No vendor line."))?;
        let mut vendor_inners = match vendor_pair.as_rule() {
            Rule::vendor => Ok(vendor_pair.into_inner()),
            x => Err(anyhow!(format!(
                "Vendor line didn't parse as such. Parsed as {:?}",
                x
            ))),
        }?;
        let end = parsed_data.next();
        assert!(end.is_none(), "Something found after vendor line.");

        let vendor_id_pair = vendor_inners.next().ok_or(anyhow!("No vendor id."))?;
        assert_eq!(
            vendor_id_pair.as_str(),
            fake_vendor_data.expected_id_hex_string,
            "Vendor id doesn't match."
        );
        let vendor_name_pair = vendor_inners.next().ok_or(anyhow!("No vendor name."))?;
        assert_eq!(
            vendor_name_pair.as_str(),
            fake_vendor_data.expected_name,
            "Vendor name doesn't match."
        );
        let end = vendor_inners.next();
        assert!(end.is_none(), "Something found after vendor name.");
        Ok(())
    }

    #[test]
    fn test_vendor_simple_add() -> Result<()> {
        let fake_vendor_data = FakeVendorData::new();

        println!("Unparsed_data: {:?}", &fake_vendor_data.unparsed_data);

        pest::parses_to! {
            parser: PciIdsParser,
            input: &fake_vendor_data.unparsed_data,
            rule: Rule::vendor,
            tokens: [
                vendor(0, fake_vendor_data.unparsed_data.len(), [
                    vendor_id(0, 4),
                    vendor_name(5, fake_vendor_data.unparsed_data.len())
                ])
            ]
        };

        let mut parsed_vendor = PciIdsParser::parse(Rule::vendor, &fake_vendor_data.unparsed_data)?;
        println!("parsed_vendor: {:#?}", &parsed_vendor);
        let vendor_pair = parsed_vendor.next().context("No parsed vendor.")?;
        println!("vendor_pair: {:#?}", &vendor_pair);

        let mut pci_data = PciIdData::new();
        pci_data.add_vendor_from_vendor_pairs(&mut vendor_pair.into_inner())?;

        let vendor = &pci_data.vendors[&fake_vendor_data.expected_id];
        fake_vendor_data.check(vendor)?;

        Ok(())
    }

    #[test]
    fn test_vendor_complex_add() -> Result<()> {
        let fake_subsystem_data = FakeSubsystemData::new();
        let fake_device_data = FakeDeviceData::new_with_subsystems(vec![fake_subsystem_data]);
        let fake_vendor_data = FakeVendorData::new_with_devices(vec![fake_device_data]);

        println!("Unparsed_data: {:?}", &fake_vendor_data.unparsed_data);

        let vendor_end = fake_vendor_data.simple_unparsed_data.len();
        let device_start = vendor_end + 1;
        println!("{}", device_start);
        let device_end = device_start + fake_vendor_data.devices[0].simple_unparsed_data.len();
        println!("{}", device_end);
        let subsystem_start = device_end + 1;

        pest::parses_to! {
            parser: PciIdsParser,
            input: &fake_vendor_data.unparsed_data,
            rule: Rule::vendor,
            tokens: [
                vendor(0, fake_vendor_data.unparsed_data.len(), [
                    vendor_id(0, 4),
                    vendor_name(5, vendor_end),
                    device(device_start + 0, fake_vendor_data.unparsed_data.len(), [
                        device_id(device_start + 1, device_start + 5),
                        device_name(device_start + 6, device_end),
                        subsystem(subsystem_start, fake_vendor_data.unparsed_data.len(), [
                            subsystem_id(subsystem_start + 2, subsystem_start+11, [
                                subvendor_id(subsystem_start+2, subsystem_start+6),
                                subdevice_id(subsystem_start+7, subsystem_start+11)
                            ]),
                            subsystem_name(subsystem_start+12, fake_vendor_data.unparsed_data.len()),
                        ])
                    ])
                ])
            ]
        };

        let mut parsed_vendor = PciIdsParser::parse(Rule::vendor, &fake_vendor_data.unparsed_data)?;
        println!("parsed_vendor: {:#?}", &parsed_vendor);
        let vendor_pair = parsed_vendor.next().context("No parsed vendor.")?;
        println!("vendor_pair: {:#?}", &vendor_pair);

        let mut pci_data = PciIdData::new();
        pci_data.add_vendor_from_vendor_pairs(&mut vendor_pair.into_inner())?;
        println!("pci_data: {:#?}", pci_data);

        let vendor = &pci_data.vendors[&fake_vendor_data.expected_id];
        fake_vendor_data.check(&vendor)?;

        let device = &vendor.devices[&fake_vendor_data.devices[0].expected_id];
        fake_vendor_data.devices[0].check(device)?;

        let subsystem = &device.subsystems[&(
            fake_vendor_data.devices[0].subsystems[0].expected_subvendor_id,
            fake_vendor_data.devices[0].subsystems[0].expected_subdevice_id,
        )];
        fake_vendor_data.devices[0].subsystems[0].check(&subsystem)?;

        Ok(())
    }

    struct FakeDeviceData {
        expected_id: u16,
        expected_id_hex_string: String,
        expected_name: String,
        unparsed_data: String,
        simple_unparsed_data: String,
        subsystems: Vec<FakeSubsystemData>,
    }

    impl FakeDeviceData {
        fn new_with_subsystems(subsystems: Vec<FakeSubsystemData>) -> Self {
            let expected_id = rand::random::<_>();
            let expected_id_hex_string = as_max_len_hex_string(expected_id);
            let expected_name = format!("Fake device ({})", as_max_len_hex_string(expected_id));
            let simple_unparsed_data = format!("\t{} {}", as_max_len_hex_string(expected_id), expected_name);
            let full_unparsed_data = subsystems.iter().map(|d| d.unparsed_data.clone()).fold(simple_unparsed_data.clone(), |acc, x| format!("{}\n{}", acc, x));
            FakeDeviceData {
                expected_id: expected_id,
                expected_id_hex_string: expected_id_hex_string.clone(),
                expected_name: expected_name.clone(),
                unparsed_data: full_unparsed_data,
                simple_unparsed_data: simple_unparsed_data,
                subsystems: subsystems,
            }
        }

        fn new() -> Self {
            Self::new_with_subsystems(Vec::<_>::new())
        }

        fn check(&self, device: &PciDevice) -> Result<()> {
            assert_eq!(device.id, self.expected_id);
            assert_eq!(device.name, self.expected_name);
            Ok(())
        }
    }

    #[test]
    fn test_device_simple_parse() -> Result<()> {
        let fake_device_data = FakeDeviceData::new();

        println!("Unparsed_data: {:?}", &fake_device_data.unparsed_data);

        pest::parses_to! {
            parser: PciIdsParser,
            input: &fake_device_data.unparsed_data,
            rule: Rule::device,
            tokens: [
                device(0, fake_device_data.unparsed_data.len(), [
                    device_id(1, 5),
                    device_name(6, fake_device_data.unparsed_data.len())
                ])
            ]
        };

        let mut parsed_device = PciIdsParser::parse(Rule::device, &fake_device_data.unparsed_data)?;

        let device_pair = parsed_device.next().ok_or(anyhow!("No device line."))?;
        let mut device_inners = match device_pair.as_rule() {
            Rule::device => Ok(device_pair.into_inner()),
            x => Err(anyhow!(format!(
                "Device line didn't parse as such. Parsed as {:?}",
                x
            ))),
        }?;
        let end = parsed_device.next();
        assert!(end.is_none(), "Something found after device line.");

        let device_id_pair = device_inners.next().ok_or(anyhow!("No device id."))?;
        assert_eq!(
            device_id_pair.as_str(),
            fake_device_data.expected_id_hex_string,
            "Device id doesn't match."
        );
        let device_name_pair = device_inners.next().ok_or(anyhow!("No device name."))?;
        assert_eq!(
            device_name_pair.as_str(),
            fake_device_data.expected_name,
            "Device name doesn't match."
        );
        let end = device_inners.next();
        assert!(end.is_none(), "Something found after device name.");
        Ok(())
    }

    #[test]
    fn test_device_simple_add() -> Result<()> {
        let fake_device_data = FakeDeviceData::new();

        println!("Unparsed_data: {:?}", &fake_device_data.unparsed_data);

        let mut parsed_device = PciIdsParser::parse(Rule::device, &fake_device_data.unparsed_data)?;
        println!("parsed_device: {:#?}", &parsed_device);
        let device_pair = parsed_device.next().context("No parsed device.")?;
        println!("device_pair: {:#?}", &device_pair);

        let mut vendor_data = PciVendor::new(rand::random::<_>(), "Fake vendor");
        vendor_data.add_device_from_device_pairs(&mut device_pair.into_inner())?;
        println!("vendor_data: {:#?}", vendor_data);

        let device_data = &vendor_data.devices[&fake_device_data.expected_id];
        assert_eq!(device_data.id, fake_device_data.expected_id);
        assert_eq!(device_data.name, fake_device_data.expected_name);
        Ok(())
    }

    #[test]
    fn test_device_complex_add() -> Result<()> {
        let fake_subsystem_data = FakeSubsystemData::new();
        let fake_device_data = FakeDeviceData::new_with_subsystems(vec![fake_subsystem_data]);

        println!("Unparsed_data: {:?}", &fake_device_data.unparsed_data);

        let unparsed_device_string_len = fake_device_data.simple_unparsed_data.len();

        pest::parses_to! {
            parser: PciIdsParser,
            input: &fake_device_data.unparsed_data,
            rule: Rule::device,
            tokens: [
                device(0, fake_device_data.unparsed_data.len(), [
                    device_id(1, 5),
                    device_name(6, unparsed_device_string_len),
                    subsystem(unparsed_device_string_len+1, fake_device_data.unparsed_data.len(), [
                        subsystem_id(unparsed_device_string_len + 3, unparsed_device_string_len+12, [
                            subvendor_id(unparsed_device_string_len+3, unparsed_device_string_len+7),
                            subdevice_id(unparsed_device_string_len+8, unparsed_device_string_len+12)
                        ]),
                        subsystem_name(unparsed_device_string_len+13, fake_device_data.unparsed_data.len()),
                    ])
                ])
            ]
        };

        let mut parsed_device = PciIdsParser::parse(Rule::device, &fake_device_data.unparsed_data)?;
        println!("parsed_device: {:#?}", &parsed_device);
        let device_pair = parsed_device.next().context("No parsed device.")?;
        println!("device_pair: {:#?}", &device_pair);

        let mut vendor = PciVendor::new(rand::random::<_>(), "Fake vendor");
        vendor.add_device_from_device_pairs(&mut device_pair.into_inner())?;
        println!("vendor: {:#?}", vendor);

        let device = &vendor.devices[&fake_device_data.expected_id];
        fake_device_data.check(device)?;

        let subsystem = &device.subsystems[&(
            fake_device_data.subsystems[0].expected_subvendor_id,
            fake_device_data.subsystems[0].expected_subdevice_id,
        )];
        fake_device_data.subsystems[0].check(&subsystem)?;

        Ok(())
    }

    struct FakeSubsystemData {
        expected_subvendor_id: u16,
        expected_subvendor_id_hex_string: String,
        expected_subdevice_id: u16,
        expected_subdevice_id_hex_string: String,
        expected_subsystem_name: String,
        unparsed_data: String,
    }

    impl FakeSubsystemData {
        fn new() -> Self {
            let expected_subvendor_id = rand::random::<_>();
            let expected_subvendor_id_hex_string = as_max_len_hex_string(expected_subvendor_id);
            let expected_subdevice_id = rand::random::<_>();
            let expected_subdevice_id_hex_string = as_max_len_hex_string(expected_subdevice_id);
            let expected_subsystem_name = format!(
                "Fake subsystem ({}:{})",
                as_max_len_hex_string(expected_subvendor_id),
                as_max_len_hex_string(expected_subdevice_id)
            );
            FakeSubsystemData {
                expected_subvendor_id: expected_subvendor_id,
                expected_subvendor_id_hex_string: expected_subvendor_id_hex_string.clone(),
                expected_subdevice_id: expected_subdevice_id,
                expected_subdevice_id_hex_string: expected_subdevice_id_hex_string.clone(),
                expected_subsystem_name: expected_subsystem_name.clone(),
                unparsed_data: format!(
                    "\t\t{} {} {}",
                    expected_subvendor_id_hex_string,
                    expected_subdevice_id_hex_string,
                    expected_subsystem_name
                ),
            }
        }

        fn check(&self, subsystem: &PciSubsystem) -> Result<()> {
            assert_eq!(subsystem.subvendor_id, self.expected_subvendor_id);
            assert_eq!(subsystem.subdevice_id, self.expected_subdevice_id);
            assert_eq!(subsystem.name, self.expected_subsystem_name);
            Ok(())
        }
    }

    #[test]
    fn test_subsystem_simple_parse() -> Result<()> {
        let fake_subsystem_data = FakeSubsystemData::new();

        println!("Unparsed_data: {:?}", &fake_subsystem_data.unparsed_data);

        pest::parses_to! {
            parser: PciIdsParser,
            input: &fake_subsystem_data.unparsed_data,
            rule: Rule::subsystem,
            tokens: [
                subsystem(0, fake_subsystem_data.unparsed_data.len(), [
                    subsystem_id(2, 11, [
                        subvendor_id(2, 6),
                        subdevice_id(7, 11)
                    ]),
                    subsystem_name(12, fake_subsystem_data.unparsed_data.len())
                ])
            ]
        };

        let mut parsed_data =
            PciIdsParser::parse(Rule::subsystem_line, &fake_subsystem_data.unparsed_data)?;

        let subsystem_id_pairs = parsed_data.next().ok_or(anyhow!("No subsystem ids."))?;
        let mut subsystem_id_inners = match subsystem_id_pairs.as_rule() {
            Rule::subsystem_id => Ok(subsystem_id_pairs.into_inner()),
            x => Err(anyhow!(format!(
                "Subsystem ids didn't parse as such. Parsed as {:?}",
                x
            ))),
        }?;

        let subvendor_id_pair = subsystem_id_inners
            .next()
            .ok_or(anyhow!("No subvendor id."))?;
        match subvendor_id_pair.as_rule() {
            Rule::subvendor_id => Ok(()),
            _ => Err(anyhow!(format!(
                "Subvendor id didn't parse as such. Parsed as {:?}",
                subvendor_id_pair.as_rule()
            ))),
        }?;

        let subdevice_id_pair = subsystem_id_inners
            .next()
            .ok_or(anyhow!("No subdevice id."))?;
        match subdevice_id_pair.as_rule() {
            Rule::subdevice_id => Ok(()),
            _ => Err(anyhow!(format!(
                "Subdevice id didn't parse as such. Parsed as {:?}",
                subdevice_id_pair.as_rule()
            ))),
        }?;

        let end = subsystem_id_inners.next();
        assert!(end.is_none(), "Something found after subsystem ids.");

        let subsystem_name_pair = parsed_data.next().ok_or(anyhow!("No subsystem name."))?;
        match subsystem_name_pair.as_rule() {
            Rule::subsystem_name => Ok(()),
            _ => Err(anyhow!(format!(
                "Subvendor name didn't parse as such. Parsed as {:?}",
                subsystem_name_pair.as_rule()
            ))),
        }?;

        let end = parsed_data.next();
        assert!(end.is_none(), "Something found after subsystem name.");

        assert_eq!(
            subvendor_id_pair.as_str(),
            fake_subsystem_data.expected_subvendor_id_hex_string,
            "Subvendor id doesn't match."
        );
        assert_eq!(
            subdevice_id_pair.as_str(),
            fake_subsystem_data.expected_subdevice_id_hex_string,
            "Subdevice id doesn't match."
        );
        assert_eq!(
            subsystem_name_pair.as_str(),
            fake_subsystem_data.expected_subsystem_name,
            "Subsystem name doesn't match."
        );
        Ok(())
    }

    #[test]
    fn test_subsystem_simple_add() -> Result<()> {
        let fake_subsystem_data = FakeSubsystemData::new();

        println!("Unparsed_data: {:?}", &fake_subsystem_data.unparsed_data);

        let mut parsed_subsystem =
            PciIdsParser::parse(Rule::subsystem, &fake_subsystem_data.unparsed_data)?;
        println!("parsed_subsystem: {:#?}", &parsed_subsystem);
        let subsystem_pair = parsed_subsystem.next().context("No parsed subsystem.")?;
        println!("parsed_subsystem: {:#?}", &subsystem_pair);

        let mut device = PciDevice::new(rand::random::<_>(), "Fake device");
        device.add_subsystem_from_subsystem_pairs(&mut subsystem_pair.into_inner())?;
        println!("{:#?}", &device);

        let subsystem = &device.subsystems[&(
            fake_subsystem_data.expected_subvendor_id,
            fake_subsystem_data.expected_subdevice_id,
        )];
        fake_subsystem_data.check(&subsystem)?;

        Ok(())
    }

    struct FakeClassData {
        expected_id: u8,
        expected_id_hex_string: String,
        expected_name: String,
        unparsed_data: String,
        simple_unparsed_data: String,
        subclasses: Vec<FakeSubclassData>,
    }

    impl FakeClassData {
        fn new_with_subclasses(subclasses: Vec<FakeSubclassData>) -> Self {
            let expected_id = rand::random::<_>();
            let expected_id_hex_string = as_max_len_hex_string(expected_id);
            let expected_name = format!("Fake class ({})", as_max_len_hex_string(expected_id));
            let simple_unparsed_data = format!("C {} {}", expected_id_hex_string, expected_name);
            let full_unparsed_data = subclasses.iter().map(|d| d.unparsed_data.clone()).fold(simple_unparsed_data.clone(), |acc, x| format!("{}\n{}", acc, x));
            FakeClassData {
                expected_id: expected_id,
                expected_id_hex_string: expected_id_hex_string.clone(),
                expected_name: expected_name.clone(),
                unparsed_data: full_unparsed_data,
                simple_unparsed_data: simple_unparsed_data,
                subclasses: subclasses,
            }
        }

        fn new() -> Self {
            Self::new_with_subclasses(Vec::<_>::new())
        }

        fn check(&self, class: &PciClass) -> Result<()> {
            assert_eq!(class.id, self.expected_id);
            assert_eq!(class.name, self.expected_name);
            Ok(())
        }
    }

    #[test]
    fn test_class_simple_parse() -> Result<()> {
        let fake_class_data = FakeClassData::new();

        println!("Unparsed_data: {:?}", &fake_class_data.unparsed_data);

        pest::parses_to! {
            parser: PciIdsParser,
            input: &fake_class_data.unparsed_data,
            rule: Rule::class,
            tokens: [
                class(0, fake_class_data.unparsed_data.len(), [
                    class_id(2, 4),
                    class_name(5, fake_class_data.unparsed_data.len())
                ])
            ]
        };

        let mut parsed_data = PciIdsParser::parse(Rule::class, &fake_class_data.unparsed_data)?;

        let class_pair = parsed_data.next().ok_or(anyhow!("No class line."))?;
        let mut class_inners = match class_pair.as_rule() {
            Rule::class => Ok(class_pair.into_inner()),
            x => Err(anyhow!(format!(
                "Class line didn't parse as such. Parsed as {:?}",
                x
            ))),
        }?;
        let end = parsed_data.next();
        assert!(end.is_none(), "Something found after class line.");

        let class_id_pair = class_inners.next().ok_or(anyhow!("No class id."))?;
        assert_eq!(
            class_id_pair.as_str(),
            fake_class_data.expected_id_hex_string,
            "Class id doesn't match."
        );
        let class_name_pair = class_inners.next().ok_or(anyhow!("No class name."))?;
        assert_eq!(
            class_name_pair.as_str(),
            fake_class_data.expected_name,
            "Class name doesn't match."
        );
        let end = class_inners.next();
        assert!(end.is_none(), "Something found after class name.");
        Ok(())
    }

    #[test]
    fn test_class_simple_add() -> Result<()> {
        let fake_class_data = FakeClassData::new();

        println!("Unparsed_data: {:?}", &fake_class_data.unparsed_data);

        pest::parses_to! {
            parser: PciIdsParser,
            input: &fake_class_data.unparsed_data,
            rule: Rule::class,
            tokens: [
                class(0, fake_class_data.unparsed_data.len(), [
                    class_id(2, 4),
                    class_name(5, fake_class_data.unparsed_data.len())
                ])
            ]
        };

        let mut parsed_class = PciIdsParser::parse(Rule::class, &fake_class_data.unparsed_data)?;
        println!("parsed_class: {:#?}", &parsed_class);
        let class_pair = parsed_class.next().context("No parsed class.")?;
        println!("class_pair: {:#?}", &class_pair);

        let mut pci_data = PciIdData::new();
        pci_data.add_class_from_class_pairs(&mut class_pair.into_inner())?;

        let class = &pci_data.classes[&fake_class_data.expected_id];
        fake_class_data.check(class)?;

        Ok(())
    }

    #[test]
    fn test_class_complex_add() -> Result<()> {
        let fake_prog_if_data = FakeProgIfaceData::new();
        let fake_subclass_data = FakeSubclassData::new_with_prog_ifs(vec![fake_prog_if_data]);
        let fake_class_data = FakeClassData::new_with_subclasses(vec![fake_subclass_data]);

        println!("Unparsed_data: {:?}", &fake_class_data.unparsed_data);

        let class_end = fake_class_data.simple_unparsed_data.len();
        let subclass_start = class_end + 1;
        println!("{}", subclass_start);
        let subclass_end = subclass_start + fake_class_data.subclasses[0].simple_unparsed_data.len();
        println!("{}", subclass_end);
        let prog_if_start = subclass_end + 1;

        pest::parses_to! {
            parser: PciIdsParser,
            input: &fake_class_data.unparsed_data,
            rule: Rule::class,
            tokens: [
                class(0, fake_class_data.unparsed_data.len(), [
                    class_id(2, 4),
                    class_name(5, class_end),
                    subclass(subclass_start + 0, fake_class_data.unparsed_data.len(), [
                        subclass_id(subclass_start + 1, subclass_start + 3),
                        subclass_name(subclass_start + 4, subclass_end),
                        prog_if(prog_if_start, fake_class_data.unparsed_data.len(), [
                            prog_if_id(prog_if_start+2, prog_if_start+4),
                            prog_if_name(prog_if_start+5, fake_class_data.unparsed_data.len()),
                        ])
                    ])
                ])
            ]
        };

        let mut parsed_class = PciIdsParser::parse(Rule::class, &fake_class_data.unparsed_data)?;
        println!("parsed_class: {:#?}", &parsed_class);
        let class_pair = parsed_class.next().context("No parsed class.")?;
        println!("class_pair: {:#?}", &class_pair);

        let mut pci_data = PciIdData::new();
        pci_data.add_class_from_class_pairs(&mut class_pair.into_inner())?;
        println!("pci_data: {:#?}", pci_data);

        let class = &pci_data.classes[&fake_class_data.expected_id];
        fake_class_data.check(&class)?;

        let subclass = &class.subclasses[&fake_class_data.subclasses[0].expected_id];
        fake_class_data.subclasses[0].check(subclass)?;

        let prog_if = &subclass.prog_interfaces[&fake_class_data.subclasses[0].prog_ifs[0].expected_id];
        fake_class_data.subclasses[0].prog_ifs[0].check(&prog_if)?;

        Ok(())
    }

    struct FakeSubclassData {
        expected_id: u8,
        expected_id_hex_string: String,
        expected_name: String,
        unparsed_data: String,
        simple_unparsed_data: String,
        prog_ifs: Vec<FakeProgIfaceData>,
    }

    impl FakeSubclassData {
        fn new_with_prog_ifs(prog_ifs: Vec<FakeProgIfaceData>) -> Self {
            let expected_id = rand::random::<_>();
            let expected_id_hex_string = as_max_len_hex_string(expected_id);
            let expected_name = format!("Fake subclass ({})", as_max_len_hex_string(expected_id));
            let simple_unparsed_data = format!("\t{} {}", expected_id_hex_string, expected_name);
            let full_unparsed_data = prog_ifs.iter().map(|d| d.unparsed_data.clone()).fold(simple_unparsed_data.clone(), |acc, x| format!("{}\n{}", acc, x));
            FakeSubclassData {
                expected_id: expected_id,
                expected_id_hex_string: expected_id_hex_string.clone(),
                expected_name: expected_name.clone(),
                unparsed_data: full_unparsed_data,
                simple_unparsed_data: simple_unparsed_data,
                prog_ifs: prog_ifs,
            }
        }

        fn new() -> Self {
            Self::new_with_prog_ifs(Vec::<_>::new())
        }

        fn check(&self, subclass: &PciSubclass) -> Result<()> {
            assert_eq!(subclass.id, self.expected_id);
            assert_eq!(subclass.name, self.expected_name);
            Ok(())
        }
    }

    #[test]
    fn test_subclass_simple_parse() -> Result<()> {
        let fake_subclass_data = FakeSubclassData::new();

        println!("Unparsed_data: {:?}", &fake_subclass_data.unparsed_data);

        pest::parses_to! {
            parser: PciIdsParser,
            input: &fake_subclass_data.unparsed_data,
            rule: Rule::subclass,
            tokens: [
                subclass(0, fake_subclass_data.unparsed_data.len(), [
                    subclass_id(1, 3),
                    subclass_name(4, fake_subclass_data.unparsed_data.len())
                ])
            ]
        };

        let mut parsed_data =
            PciIdsParser::parse(Rule::subclass, &fake_subclass_data.unparsed_data)?;

        let subclass_pair = parsed_data.next().ok_or(anyhow!("No subclass line."))?;
        let mut subclass_inners = match subclass_pair.as_rule() {
            Rule::subclass => Ok(subclass_pair.into_inner()),
            x => Err(anyhow!(format!(
                "Subclass line didn't parse as such. Parsed as {:?}",
                x
            ))),
        }?;
        let end = parsed_data.next();
        assert!(end.is_none(), "Something found after subclass line.");

        let subclass_id_pair = subclass_inners.next().ok_or(anyhow!("No subclass id."))?;
        assert_eq!(
            subclass_id_pair.as_str(),
            fake_subclass_data.expected_id_hex_string,
            "Subclass id doesn't match."
        );
        let subclass_name_pair = subclass_inners.next().ok_or(anyhow!("No subclass name."))?;
        assert_eq!(
            subclass_name_pair.as_str(),
            fake_subclass_data.expected_name,
            "Subclass name doesn't match."
        );
        let end = subclass_inners.next();
        assert!(end.is_none(), "Something found after subclass name.");
        Ok(())
    }

    #[test]
    fn test_subclass_simple_add() -> Result<()> {
        let fake_subclass_data = FakeSubclassData::new();

        println!("Unparsed_data: {:?}", &fake_subclass_data.unparsed_data);

        let mut parsed_subclass =
            PciIdsParser::parse(Rule::subclass, &fake_subclass_data.unparsed_data)?;
        println!("parsed_subclass: {:#?}", &parsed_subclass);
        let subclass_pair = parsed_subclass.next().context("No parsed class")?;
        println!("parsed_subclass: {:#?}", &subclass_pair);

        let mut class = PciClass::new(rand::random::<_>(), "Fake class");
        class.add_subclass_from_subclass_pairs(&mut subclass_pair.into_inner())?;
        println!("{:#?}", &class);

        let subclass = &class.subclasses[&fake_subclass_data.expected_id];
        fake_subclass_data.check(&subclass)?;

        Ok(())
    }

    #[test]
    fn test_subclass_complex_add() -> Result<()> {
        let fake_prog_if_data = FakeProgIfaceData::new();
        let fake_subclass_data = FakeSubclassData::new_with_prog_ifs(vec![fake_prog_if_data]);

        println!("Unparsed_data: {:?}", &fake_subclass_data.simple_unparsed_data);

        let unparsed_subclass_string_len = fake_subclass_data.simple_unparsed_data.len();

        println!("{}", unparsed_subclass_string_len);

        pest::parses_to! {
            parser: PciIdsParser,
            input: &fake_subclass_data.unparsed_data,
            rule: Rule::subclass,
            tokens: [
                subclass(0, fake_subclass_data.unparsed_data.len(), [
                    subclass_id(1, 3),
                    subclass_name(4, unparsed_subclass_string_len),
                    prog_if(unparsed_subclass_string_len+1, fake_subclass_data.unparsed_data.len(), [
                        prog_if_id(unparsed_subclass_string_len+3, unparsed_subclass_string_len+5),
                        prog_if_name(unparsed_subclass_string_len+6, fake_subclass_data.unparsed_data.len()),
                    ])
                ])
            ]
        };

        let mut parsed_subclass = PciIdsParser::parse(Rule::subclass, &fake_subclass_data.unparsed_data)?;
        println!("parsed_subclass: {:#?}", &parsed_subclass);
        let subclass_pair = parsed_subclass.next().context("No parsed subclass.")?;
        println!("subclass_pair: {:#?}", &subclass_pair);

        let mut class = PciClass::new(rand::random::<_>(), "Fake class");
        class.add_subclass_from_subclass_pairs(&mut subclass_pair.into_inner())?;
        println!("class: {:#?}", class);

        let subclass = &class.subclasses[&fake_subclass_data.expected_id];
        fake_subclass_data.check(subclass)?;

        Ok(())
    }

    struct FakeProgIfaceData {
        expected_id: u8,
        expected_id_hex_string: String,
        expected_name: String,
        unparsed_data: String,
    }

    impl FakeProgIfaceData {
        fn new() -> Self {
            let expected_id = rand::random::<_>();
            let expected_id_hex_string = as_max_len_hex_string(expected_id);
            let expected_name = format!(
                "Fake programming interface ({})",
                as_max_len_hex_string(expected_id)
            );
            FakeProgIfaceData {
                expected_id: expected_id,
                expected_id_hex_string: expected_id_hex_string.clone(),
                expected_name: expected_name.clone(),
                unparsed_data: format!("\t\t{} {}", expected_id_hex_string, expected_name),
            }
        }

        fn check(&self, class: &PciProgInterface) -> Result<()> {
            assert_eq!(class.id, self.expected_id);
            assert_eq!(class.name, self.expected_name);
            Ok(())
        }
    }

    #[test]
    fn test_prog_if_simple_parse() -> Result<()> {
        let fake_prog_if_data = FakeProgIfaceData::new();

        println!("Unparsed_data: {:?}", &fake_prog_if_data.unparsed_data);

        pest::parses_to! {
            parser: PciIdsParser,
            input: &fake_prog_if_data.unparsed_data,
            rule: Rule::prog_if,
            tokens: [
                prog_if(0, fake_prog_if_data.unparsed_data.len(), [
                    prog_if_id(2, 4),
                    prog_if_name(5, fake_prog_if_data.unparsed_data.len())
                ])
            ]
        };

        let mut parsed_data = PciIdsParser::parse(Rule::prog_if, &fake_prog_if_data.unparsed_data)?;

        let prog_if_pair = parsed_data.next().ok_or(anyhow!("No prog_if line."))?;
        let mut prog_if_inners = match prog_if_pair.as_rule() {
            Rule::prog_if => Ok(prog_if_pair.into_inner()),
            x => Err(anyhow!(format!(
                "Subclass line didn't parse as such. Parsed as {:?}",
                x
            ))),
        }?;
        let end = parsed_data.next();
        assert!(end.is_none(), "Something found after prog_if line.");

        let prog_if_id_pair = prog_if_inners.next().ok_or(anyhow!("No prog_if id."))?;
        assert_eq!(
            prog_if_id_pair.as_str(),
            fake_prog_if_data.expected_id_hex_string,
            "Subclass id doesn't match."
        );
        let prog_if_name_pair = prog_if_inners.next().ok_or(anyhow!("No prog_if name."))?;
        assert_eq!(
            prog_if_name_pair.as_str(),
            fake_prog_if_data.expected_name,
            "Subclass name doesn't match."
        );
        let end = prog_if_inners.next();
        assert!(end.is_none(), "Something found after prog_if name.");
        Ok(())
    }

    #[test]
    fn test_prog_if_simple_add() -> Result<()> {
        let fake_prog_if_data = FakeProgIfaceData::new();

        println!("Unparsed_data: {:?}", &fake_prog_if_data.unparsed_data);

        let mut parsed_prog_if =
            PciIdsParser::parse(Rule::prog_if, &fake_prog_if_data.unparsed_data)?;
        println!("parsed_prog_if: {:#?}", &parsed_prog_if);
        let prog_if_pair = parsed_prog_if
            .next()
            .context("No parsed programming interface")?;
        println!("parsed_prog_if: {:#?}", &prog_if_pair);

        let mut subclass = PciSubclass::new(rand::random::<_>(), "Fake subclass");
        subclass.add_prog_if_from_prog_if_pairs(&mut prog_if_pair.into_inner())?;
        println!("{:#?}", &subclass);

        let prog_if = &subclass.prog_interfaces[&fake_prog_if_data.expected_id];
        fake_prog_if_data.check(&prog_if)?;

        Ok(())
    }

    #[test]
    fn test_full_parse() -> Result<()> {
        let vendors = vec![
            FakeVendorData::new_with_devices(
                vec![FakeDeviceData::new_with_subsystems(
                    vec![FakeSubsystemData::new(),
                         FakeSubsystemData::new()
                    ]
                )]
            ),
            FakeVendorData::new_with_devices(vec![FakeDeviceData::new()]),
            FakeVendorData::new(),
        ];

        let classes = vec![
            FakeClassData::new_with_subclasses(
                vec![FakeSubclassData::new_with_prog_ifs(
                    vec![FakeProgIfaceData::new(),
                         FakeProgIfaceData::new()]
                )]
            ),
            FakeClassData::new_with_subclasses(vec![FakeSubclassData::new()]),
            FakeClassData::new(),
        ];

        let vendor_data = vendors.iter().map(|d| d.unparsed_data.clone()).fold(String::new(), |acc, x| format!("{}\n{}", acc, x));
        let class_data = classes.iter().map(|d| d.unparsed_data.clone()).fold(String::new(), |acc, x| format!("{}\n{}", acc, x));
        let unparsed_data = vendor_data + &class_data;

        println!("Unparsed_data: {:?}", unparsed_data);

        let mut pci_data = PciIdData::new();
        pci_data.add_pci_ids_data(&mut unparsed_data.as_bytes())?;
        println!("{:#?}", &pci_data);

        for vendor in vendors {
            if !pci_data.vendors.contains_key(&vendor.expected_id) {
                return Err(anyhow!("Vendor didn't parse correctly: {}", vendor.simple_unparsed_data));
            }
            for device in vendor.devices {
                if !pci_data.vendors[&vendor.expected_id].devices.contains_key(&device.expected_id) {
                    return Err(anyhow!("Device didn't parse correctly: {}", device.simple_unparsed_data));
                }
                for subsystem in device.subsystems {
                    if !pci_data.vendors[&vendor.expected_id].devices[&device.expected_id].subsystems.contains_key(&(subsystem.expected_subvendor_id, subsystem.expected_subdevice_id)) {
                        return Err(anyhow!("Subsystem didn't parse correctly: {}", device.simple_unparsed_data));
                    }
                }
            }
        }

        for class in classes {
            if !pci_data.classes.contains_key(&class.expected_id) {
                return Err(anyhow!("Class didn't parse correctly: {}", class.simple_unparsed_data));
            }
            for subclass in class.subclasses {
                if !pci_data.classes[&class.expected_id].subclasses.contains_key(&subclass.expected_id) {
                    return Err(anyhow!("Subclass didn't parse correctly: {}", subclass.simple_unparsed_data));
                }
                for prog_if in subclass.prog_ifs {
                    if !pci_data.classes[&class.expected_id].subclasses[&subclass.expected_id].prog_interfaces.contains_key(&prog_if.expected_id) {
                        return Err(anyhow!("Programming interface didn't parse correctly: {}", subclass.simple_unparsed_data));
                    }
                }
            }
        }

        Ok(())
    }
}
