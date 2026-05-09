//! Readable name lookup for [`EntryType`] bytes.
//!
//! Ported from PSPTool `file.py:File.DIRECTORY_ENTRY_TYPES` and
//! `BIOS_DIRECTORY_ENTRY_TYPES`. PSPTool's `get_readable_type()` formatting is
//! `"<NAME>~0x<hh>"` for known types and `"0x<hh>"` for unknown ones; in BIOS
//! directories the BIOS-specific overrides take priority and types `0x61` /
//! `0x62` are rendered as bare `"APOB"` / `"BIOS"` (no name~hex suffix).

use psptool_core::EntryType;

/// PSP-directory readable name for `t`, when known.
const fn psp_name(t: u8) -> Option<&'static str> {
    Some(match t {
        0x00 => "AMD_PUBLIC_KEY",
        0x01 => "PSP_FW_BOOT_LOADER",
        0x02 => "PSP_FW_TRUSTED_OS",
        0x03 => "PSP_FW_RECOVERY_BOOT_LOADER",
        0x04 => "PSP_NV_DATA",
        0x05 => "BIOS_PUBLIC_KEY",
        0x06 => "BIOS_RTM_FIRMWARE",
        0x07 => "BIOS_RTM_SIGNATURE",
        0x08 => "SMU_OFFCHIP_FW",
        0x09 => "SEC_DBG_PUBLIC_KEY",
        0x0A => "OEM_PSP_FW_PUBLIC_KEY",
        0x0B => "SOFT_FUSE_CHAIN_01",
        0x0C => "PSP_BOOT_TIME_TRUSTLETS",
        0x0D => "PSP_BOOT_TIME_TRUSTLETS_KEY",
        0x10 => "PSP_AGESA_RESUME_FW",
        0x12 => "SMU_OFF_CHIP_FW_2",
        0x13 => "DEBUG_UNLOCK",
        0x15 => "TEE_IP_KEY_MGR_DRIVER",
        0x1A => "PSP_S3_NV_DATA_OR_SEV_DRIVER",
        0x1B => "TEE_BOOT_DRIVER",
        0x1C => "TEE_SOC_DRIVER",
        0x1D => "TEE_FBG_DRIVER",
        0x1F => "TEE_INTERFACE_DRIVER",
        0x20 => "HARDWARE_IP_CONFIG",
        0x21 => "WRAPPED_IKEK",
        0x22 => "TOKEN_UNLOCK",
        0x23 => "PSP_DIAG_BL",
        0x24 => "SEC_GASKET",
        0x25 => "MP2_FW",
        0x26 => "MP2_FW_2",
        0x27 => "USER_MODE_UNIT_TEST",
        0x28 => "DRIVER_ENTRIES",
        0x29 => "KVM_IMAGE",
        0x2A => "MP5_FW",
        0x2B => "EMBEDDED_FW_STRUCTURE",
        0x2C => "TEE_WRITE_ONCE_NVRAM",
        0x2D => "S0I3_DRIVER",
        0x2E => "PREMIUM_CHIPSET_MP0_DXIO_FW",
        0x2F => "PREMIUM_CHIPSET_MP1_FW",
        0x30 => "ABL0",
        0x31 => "ABL1",
        0x32 => "ABL2",
        0x33 => "ABL3",
        0x34 => "ABL4",
        0x35 => "ABL5",
        0x36 => "ABL6",
        0x37 => "ABL7",
        0x38 => "SEV_DATA",
        0x39 => "SEV_CODE",
        0x3A => "FW_PSP_WHITELIST",
        0x3C => "VBIOS_PRELOAD",
        0x3D => "WLAN_UMAC",
        0x3E => "WLAN_IMAC",
        0x3F => "WLAN_BT",
        0x40 => "PSP_FW_L2_PTR",
        0x41 => "FW_IMC",
        0x42 => "FW_GEC_OR_DXIO_PHY_SRAM_FW",
        0x43 => "DXIO_PHY_SRAM_FW_PUBKEY",
        0x44 => "FW_XHCI",
        0x45 => "TOS_SECURITY_POLICY",
        0x46 => "ANOTHER_FET",
        0x47 => "DRTM_TA",
        0x48 => "PSP_FW_L2A_PTR",
        0x49 => "BIOS_L2AB_PTR",
        0x4A => "PSP_FW_L2B_PTR",
        0x4B => "RESERVED",
        0x4C => "PREMIUM_CHIPSET_SEC_POLICY",
        0x4D => "PREMIUM_CHIPSET_DEBUG_UNLOCK",
        0x4E => "PMU_PUBKEY",
        0x4F => "UMC_FW",
        0x50 => "BL_PUBLIC_KEY",
        0x51 => "TOS_PUBLIC_KEY",
        0x52 => "OEM_PSP_BL_USER_APP",
        0x53 => "OEM_PSP_BL_USER_APP_KEY",
        0x54 => "PSP_NVRAM",
        0x55 => "BL_ROLLBACK_SPL",
        0x56 => "TOS_ROLLBACK_SPL",
        0x57 => "PSP_BL_CVIP_TABLE",
        0x58 => "DMCU_ERAM",
        0x59 => "DMCU_ISR",
        0x5A => "MSMU_BINARY_0",
        0x5B => "MSMU_BINARY_1",
        0x5C => "SPI_ROM_CONFIG",
        0x5D => "MPIO_FW",
        0x5E => "DF_TOPOLOGY",
        0x5F => "FW_PSP_SMUSCS_OR_TPMLITE",
        0x64 => "TEE_RAS_DRIVER",
        0x65 => "TEE_RAS_TRUSTED_APP",
        0x67 => "TEE_FHP_DRIVER_FW",
        0x68 => "TEE_SPDM_DRIVER_FW",
        0x69 => "TEE_DPE_DRIVER_FW",
        0x6A => "TEE_PRE_MEM_DRIVER_FW",
        0x6B => "TEE_MP_RAS_DRIVER_FW",
        0x6C => "TEE_POST_MEM_DRIVER_FW",
        0x70 => "BIOS_L2_PTR",
        0x71 => "PSP_DMCUB_CODE",
        0x72 => "PSP_DMCUB_DATA",
        0x73 => "PSP_FW_BOOT_LOADER",
        0x74 => "PSP_PLATFORM_DRIVER",
        0x75 => "FW_SOFT_FUSING_BINARY",
        0x76 => "REGISTER_INIT_BIN",
        0x80 => "OEM_SYS_TA",
        0x81 => "OEM_SYS_TA_SIGNING_KEY",
        0x82 => "IKEK_OEM",
        0x84 => "TKEK_OEM",
        0x85 => "AMF_FW1",
        0x86 => "AMF_FW2",
        0x87 => "MFD_MPM_FACTORY",
        0x88 => "MFD_MPM_WLAN_FW",
        0x89 => "MPM_DRIVER",
        0x8A => "USB4_PHY_FW",
        0x8B => "FIPS_CERTIFICATION_MODULE",
        0x8C => "MPDMA_TF_FW",
        0x8D => "IKEK_TA",
        0x8E => "SEC_FW_DATA_RECORDER",
        0x8F => "OFFCHIP_USB4_FW",
        0x90 => "CCX_CORE_INIT_AND_PM",
        0x91 => "GMI3_PHY_FW",
        0x92 => "MPDMA_MPDACC_TIERED_MEMORY_PAGE_MIGRATION_FW",
        0x93 => "PROM21_FW",
        0x94 => "LSDMA_FW",
        0x95 => "C20_PHY_FW",
        0x96 => "NPU_FW",
        0x97 => "AMD_SFFS_PUBKEY",
        0x98 => "CPU_FEAT_CONFIG_TBL",
        0x99 => "PMF_BINARY",
        0x9A => "REDUCED_MSMU_SIZE",
        0x9B => "GFX_IMU_LX7_CODE",
        0x9C => "GFX_IMU_LX7_DATA",
        0x9D => "FW_ROM_OR_FIPS_SRAM",
        0x9E => "SFDR_DATA",
        0x9F => "REG_ACCESS_WHITELIST",
        0xA0 => "CPU_S3_IMAGE",
        0xA2 => "UZSC_RESET_WORKAROUND",
        0xA3 => "USB_NATIVE_DP",
        0xA4 => "USB_TYPEC_DP",
        0xA5 => "USB_SS_FW",
        0xA6 => "USB4",
        0xA7 => "OFFCHIP_XHCI_SATA_PCIE",
        0xAA => "ASP_LIBSEC",
        0xAB => "ART_FMC_IMG",
        0xAC => "ART_RUNTIME_FW",
        0xAD => "ART_KEY_DATABASE",
        0xAE => "SEC_ASP_LIBROM_OVERLAY_FW",
        0xB0 => "MPM_CONTEXT",
        _ => return None,
    })
}

/// BIOS-only override name for `t`, when known. PSPTool keeps these in a
/// separate dict because their bytes overlap with PSP-directory types.
const fn bios_override_name(t: u8) -> Option<&'static str> {
    Some(match t {
        0x60 => "APCB",
        0x61 => "APOB",
        0x62 => "BIOS",
        0x63 => "APOB_NV_COPY",
        0x64 => "PMU_CODE",
        0x65 => "PMU_DATA",
        0x66 => "MICROCODE_PATCH",
        0x67 => "CORE_MCE_DATA",
        0x68 => "APCB_COPY",
        0x69 => "EARLY_VGA_IMAGE",
        0x6B => "COREBOOT_VBOOT_CONTEXT",
        0x6D => "ROM_ARMOR_BIOS_NVSTORE",
        0x6E => "DEBUG_UNIT",
        0x6F => "OEM_LOGO_IMAGE",
        0x77 => "DDRPHY_PCU_FW",
        0x7B => "MPRAS_TRUSTRED_APP_IMG",
        0x7C => "OC_SWEET_SPOT_PROFILE",
        _ => return None,
    })
}

/// PSPTool-compatible readable type rendering.
///
/// Mirrors `File.get_readable_type`:
/// * For BIOS directories, `0x61` → `"APOB"` and `0x62` → `"BIOS"` (bare name).
/// * For BIOS directories, other entries in `BIOS_DIRECTORY_ENTRY_TYPES` →
///   `"<NAME>~0x<hh>"`.
/// * Otherwise the PSP-directory name is used: `"<NAME>~0x<hh>"`.
/// * Unknown types render as `"0x<hh>"`.
pub fn readable_type(t: EntryType, is_bios_directory: bool) -> String {
    let byte = t.get();
    if is_bios_directory {
        if byte == 0x62 {
            return "BIOS".to_string();
        }
        if byte == 0x61 {
            return "APOB".to_string();
        }
        if let Some(name) = bios_override_name(byte) {
            return format!("{name}~{:#x}", byte);
        }
    }
    if let Some(name) = psp_name(byte) {
        return format!("{name}~{:#x}", byte);
    }
    format!("{:#x}", byte)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn psp_named_type_uses_name_tilde_hex() {
        assert_eq!(readable_type(EntryType(0x21), false), "WRAPPED_IKEK~0x21");
        assert_eq!(
            readable_type(EntryType(0x01), false),
            "PSP_FW_BOOT_LOADER~0x1"
        );
    }

    #[test]
    fn unknown_type_falls_back_to_hex() {
        assert_eq!(readable_type(EntryType(0xEE), false), "0xee");
        assert_eq!(readable_type(EntryType(0x11), false), "0x11");
    }

    #[test]
    fn bios_override_for_0x62_is_bare_bios() {
        assert_eq!(readable_type(EntryType(0x62), true), "BIOS");
    }

    #[test]
    fn bios_override_for_0x61_is_bare_apob() {
        assert_eq!(readable_type(EntryType(0x61), true), "APOB");
    }

    #[test]
    fn bios_override_for_other_uses_name_tilde_hex() {
        assert_eq!(readable_type(EntryType(0x66), true), "MICROCODE_PATCH~0x66");
        assert_eq!(readable_type(EntryType(0x60), true), "APCB~0x60");
    }

    #[test]
    fn bios_override_does_not_apply_to_psp_directory() {
        // 0x66 is in BIOS overrides, but in a PSP directory it falls through
        // to the PSP table — which has no entry for 0x66, so it's unknown.
        assert_eq!(readable_type(EntryType(0x66), false), "0x66");
        // 0x60 likewise: not in the PSP table → unknown.
        assert_eq!(readable_type(EntryType(0x60), false), "0x60");
    }
}
