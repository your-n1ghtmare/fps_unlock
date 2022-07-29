#pragma once

namespace detail {

    inline constexpr auto k_dos_hdr_magic = 0x5a4du;
    inline constexpr auto k_nt_hdrs_magic = 0x4550u;

    enum struct e_machine : std::uint16_t {
        unknown,
        target_host = 0x1u,
        i386 = 0x14cu,
        r3000 = 0x162u,
        r4000 = 0x166u,
        r10000 = 0x168u,
        wcemipsv2 = 0x169u,
        alpha = 0x184u,
        sh3 = 0x1a2u,
        sh3dsp = 0x1a3u,
        sh3e = 0x1a4u,
        sh4 = 0x1a6u,
        sh5 = 0x1a8u,
        arm = 0x1c0u,
        thumb = 0x1c2u,
        armnt = 0x1c4u,
        am33 = 0x1d3u,
        powerpc = 0x1f0u,
        powerpcfp = 0x1f1u,
        ia64 = 0x200u,
        mips16 = 0x266u,
        alpha64 = 0x284u,
        mipsfpu = 0x366u,
        mipsfpu16 = 0x466u,
        axp64 = 0x284u,
        tricore = 0x520u,
        cef = 0xcefu,
        ebc = 0xebcu,
        amd64 = 0x8664u,
        m32r = 0x9041u,
        arm64 = 0xaa64u,
        cee = 0xc0eeu
    };

    enum struct e_subsystem : std::uint16_t {
        unknown,
        native,
        win_gui,
        win_cui,
        os2_cui = 5u,
        posix_cui = 7u,
        native_win,
        win_ce_gui,
        efi_app,
        efi_boot_service_driver,
        efi_runtime_driver,
        efi_rom,
        xbox,
        win_boot_application = 16u,
        xbox_code_catalog
    };

    enum struct e_data_dir : std::uint8_t {
        entry_export,
        entry_import,
        entry_resource,
        entry_exception,
        entry_security,
        entry_base_reloc,
        entry_debug,
        entry_copyright,
        entry_arch = 7u,
        entry_global_ptr,
        entry_tls,
        entry_load_cfg,
        entry_bound_import,
        entry_iat,
        entry_delay_import,
        entry_com_descriptor,
        res0,
        max
    };
    ENUM_UNDERLYING_OPERATOR(e_data_dir);
}

