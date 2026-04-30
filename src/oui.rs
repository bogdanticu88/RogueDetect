// Common OUI prefixes — extend this list or replace with full IEEE database for production.
// Format: (prefix_as_u32, vendor_name)
static OUI_TABLE: &[(u32, &str)] = &[
    (0x000393, "Apple"),
    (0x0017F2, "Apple"),
    (0x002332, "Apple"),
    (0x3C0754, "Apple"),
    (0xA45E60, "Apple"),
    (0xF0DBE2, "Apple"),
    (0x001E65, "Dell"),
    (0x14FEB5, "Dell"),
    (0xB083FE, "Dell"),
    (0x001C23, "HP"),
    (0x3C4A92, "HP"),
    (0xD8D385, "HP"),
    (0x000C29, "VMware"),
    (0x000569, "VMware"),
    (0x005056, "VMware"),
    (0x0003FF, "Microsoft"),
    (0x7C1E52, "Microsoft"),
    (0x000EC6, "Cisco"),
    (0x001143, "Cisco"),
    (0x0017595, "Cisco"),
    (0x0050C2, "IEEE 802.1"),
    (0xB827EB, "Raspberry Pi Foundation"),
    (0xDCA632, "Raspberry Pi Foundation"),
    (0xE45F01, "Raspberry Pi Foundation"),
    (0x2CCF67, "Raspberry Pi Foundation"),
    (0x001A11, "Google"),
    (0xF4F5E8, "Google"),
    (0x001B63, "Intel"),
    (0x0021D7, "Intel"),
    (0x8C8D28, "Intel"),
    (0x001CF0, "Netgear"),
    (0x20E52A, "Netgear"),
    (0x001060, "Ubiquiti"),
    (0x788A20, "Ubiquiti"),
    (0x001D7E, "Cisco-Linksys"),
    (0xC8D3A3, "TP-Link"),
    (0x50C7BF, "TP-Link"),
];

pub fn lookup(oui: u32) -> Option<String> {
    OUI_TABLE
        .iter()
        .find(|(prefix, _)| *prefix == oui)
        .map(|(_, name)| name.to_string())
}
