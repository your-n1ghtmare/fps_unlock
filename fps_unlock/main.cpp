#include "main.hpp"

#define BYTESEQ( value ) \
    [ & ] ( ) { \
        static_assert( std::is_same_v< const char*, std::decay_t< decltype( value ) > > || std::is_pointer_v< decltype( value ) > ); \
    \
        constexpr auto k_size = detail::byte_seq_t< sizeof( value ) >::measure( value ); \
    \
        return detail::byte_seq_t< k_size >{ [ & ] ( ) { return value; }, std::make_index_sequence< k_size >{} }; \
    }( ) \

#define HASH( str ) [ ] ( ) { constexpr auto k_hash = hash( str ); return k_hash; }( )

#define THROW_IF_DBG( exception ) return

template < typename _char_t >
	requires is_char_v< _char_t >
ALWAYS_INLINE constexpr hash_t hash(const _char_t* const str, const std::size_t len) {

	constexpr auto k_basis = 0x811c9dc5u;
	constexpr auto k_prime = 0x1000193u;


	auto hash = k_basis;

	for (std::size_t i{}; i < len; ++i) {
		hash ^= str[i];
		hash *= k_prime;
	}

	return hash;
}

template < typename _char_t >
	requires is_char_v< _char_t >
ALWAYS_INLINE constexpr hash_t hash(const _char_t* const str) {
	std::size_t len{};
	while (str[++len] != '\0')
		;

	return hash(str, len);
}

struct code_section_t {

	ALWAYS_INLINE constexpr code_section_t() = default;

	code_section_t(const detail::x86_pe_image_t* const image) {
		if (image->m_dos_hdr.e_magic != detail::k_dos_hdr_magic)
			THROW_IF_DBG("invalid dos hdr.");

		const auto nt_hdrs = image->nt_hdrs();
		if (nt_hdrs->m_sig != detail::k_nt_hdrs_magic)
			THROW_IF_DBG("invalid nt hdrs.");

		m_start = image;
		m_start.self_offset(nt_hdrs->m_opt_hdr.m_code_base);

		m_end = m_start.offset(nt_hdrs->m_opt_hdr.m_code_size);
	}

	detail::address_t m_start{}, m_end{};
};

bool c_main::wait_for_all_modules(modules_t& modules) const {

	detail::peb()->for_each_ldr_data_table_entry([&](detail::ldr_data_table_entry_t* const entry) {
		modules.insert_or_assign(
			hash(entry->m_base_dll_name.m_buffer, entry->m_base_dll_name.m_len / sizeof(wchar_t)),
			entry->m_dll_base.as< detail::x86_pe_image_t* >()
		);

		return false;
		}, detail::e_ldr_data_table::in_load_order);

	return modules.find(HASH("samp.dll")) == modules.end();
}

bool c_main::is_samp_loaded() const {

	static DWORD samp = 0;
	if (!samp) {
		samp = (DWORD)GetModuleHandleA("samp.dll");
		if (samp == 0xFFFFFFFF) samp = 0;
	}

	if (!samp)
		return false;

	if (*(unsigned char*)(samp + 0x129) == 0xF4)
		return *reinterpret_cast<void**>(samp + 0x21A0F8) != nullptr;

	else if (*(unsigned char*)(samp + 0x129) == 0x0C)
		return *reinterpret_cast<void**>(samp + 0x21A100) != nullptr;

	else if (*(unsigned char*)(samp + 0x129) == 0x00) {

		if (*(unsigned char*)(samp + 0x140) == 0xD0)
			return *reinterpret_cast<void**>(samp + 0x26E8DC) != nullptr;

		else if (*(unsigned char*)(samp + 0x140) == 0xB0)
			return *reinterpret_cast<void**>(samp + 0x26EA0C) != nullptr;
	}

	else if (*(unsigned char*)(samp + 0x129) == 0x31)
		return *reinterpret_cast<void**>(samp + 0x2ACA24) != nullptr;

	return false;
}

void* c_main::mem_cpy(void* dest, const void* src, size_t len) {

	if (dest == nullptr || src == nullptr || len == 0)
		return nullptr;

	MEMORY_BASIC_INFORMATION mbi;
	VirtualQuery(dest, &mbi, sizeof(mbi));
	VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &mbi.Protect);

	void* ret = memcpy(dest, src, len);
	VirtualProtect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &mbi.Protect);
	FlushInstructionCache(GetCurrentProcess(), dest, len);
	return ret;
}

int c_main::mem_set(void* _dest, int c, size_t len) {

	byte* dest = static_cast<byte*>(_dest);
	byte  buf[4096];
	memset(buf, c, (len > 4096) ? 4096 : len);
	for (;; ) {
		if (len > 4096) {
			if (!mem_cpy(dest, buf, 4096)) return 0;
			dest += 4096;
			len -= 4096;
		}
		else {
			if (!mem_cpy(dest, buf, len)) return 0;
			break;
		}
	}
	return 1;
}

BOOL APIENTRY DllMain(HMODULE h_module, DWORD ul_reason_for_call, LPVOID lp_reserved) {

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH: {

		DisableThreadLibraryCalls(h_module);

		std::jthread{ []() { g_main->init(); } }.detach();
		break;
	}
	case DLL_PROCESS_DETACH:

		g_main->uninit();
		break;
	}
	return TRUE;
}

void c_main::init() {

	modules_t modules{};

	while (wait_for_all_modules(modules))
		std::this_thread::sleep_for(std::chrono::milliseconds{ 100u });

	while (!is_samp_loaded())
		std::this_thread::sleep_for(std::chrono::milliseconds{ 100u });

	const code_section_t samp{ modules.at(HASH("samp.dll")) };

	m_fps_unlock_addr = BYTESEQ("E8 ? ? ? ? A1 ? ? ? ? 85 C0 74 ? 8B 80").search(
		samp.m_start, samp.m_end);

	const auto addr_ptr = reinterpret_cast<void*>(m_fps_unlock_addr);
	mem_cpy(addr_ptr, "\x90\x90\x90\x90\x90", 5);
}


void c_main::uninit() {

	const auto addr_ptr = reinterpret_cast<void*>(m_fps_unlock_addr);
	mem_cpy(addr_ptr, "\xE8\x9B\xF7\xFF\xFF", 5);
}
