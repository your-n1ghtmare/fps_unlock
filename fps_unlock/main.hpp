#pragma once



#ifdef _MSC_VER
#define ALWAYS_INLINE __forceinline
#else
#define ALWAYS_INLINE __attribute__ ( ( always_inline ) ) inline
#endif

namespace __sdk_constant_holder { template < auto _value > inline constexpr auto k_value = _value; }

#define CONSTANT( constant ) __sdk_constant_holder::k_value< constant >

#define ENUM_UNDERLYING_OPERATOR( enum_t ) \
    ALWAYS_INLINE constexpr auto operator -( const enum_t value ) { \
        return static_cast< std::underlying_type_t< enum_t > >( value ); \
    } \

#define ENUM_BIT_OPERATOR( enum_t, op, ret_underlying ) \
    template < typename _value_t > \
        requires std::_Is_any_of_v< _value_t, enum_t, std::underlying_type_t< enum_t > > \
    ALWAYS_INLINE constexpr auto operator op( const enum_t lhs, const _value_t rhs ) { \
        using underlying_t = std::underlying_type_t< enum_t >; \
        \
        using ret_t = std::conditional_t< ret_underlying, underlying_t, enum_t >; \
        \
        return static_cast< ret_t >( \
            static_cast< underlying_t >( lhs ) op static_cast< underlying_t >( rhs ) \
        ); \
    } \
    \
    ALWAYS_INLINE constexpr auto operator op( const std::underlying_type_t< enum_t > lhs, const enum_t rhs ) { \
        using underlying_t = std::underlying_type_t< enum_t >; \
        \
        using ret_t = std::conditional_t< ret_underlying, underlying_t, enum_t >; \
        \
        return static_cast< ret_t >( \
            static_cast< underlying_t >( lhs ) op static_cast< underlying_t >( rhs ) \
        ); \
    } \
    \
    template < typename _value_t > \
        requires std::_Is_any_of_v< _value_t, enum_t, std::underlying_type_t< enum_t > > \
    ALWAYS_INLINE auto& operator op##=( enum_t& lhs, const _value_t rhs ) { \
        using underlying_t = std::underlying_type_t< enum_t >; \
        \
        using ret_t = std::conditional_t< ret_underlying, underlying_t, enum_t >; \
        \
        return reinterpret_cast< ret_t& >( \
            reinterpret_cast< underlying_t& >( lhs ) op##= static_cast< underlying_t >( rhs ) \
        ); \
    } \

#define ENUM_BIT_OPERATORS( enum_t, ret_underlying ) \
    ENUM_BIT_OPERATOR( enum_t, |, ret_underlying ) \
    \
    ENUM_BIT_OPERATOR( enum_t, &, ret_underlying ) \
    \
    ENUM_BIT_OPERATOR( enum_t, ^, ret_underlying ) \
    \
    ALWAYS_INLINE constexpr auto operator ~( const enum_t value ) { \
        using underlying_t = std::underlying_type_t< enum_t >; \
        \
        using ret_t = std::conditional_t< ret_underlying, underlying_t, enum_t >; \
        \
        return static_cast< ret_t >( ~static_cast< underlying_t >( value ) ); \
    } \

#include <windows.h>
#include <intrin.h>

#include <array>
#include <vector>
#include <deque>
#include <thread>
#include <algorithm>
#include <functional>
#include <optional>
#include <type_traits>

#include "mem.hpp"
#include "base_address.hpp"



namespace detail {

    using address_t = detail::base_address_t< std::uintptr_t >;
    using x86_pe_image_t = detail::pe_image_t< false >;


#if defined( _WIN32 ) || defined( _WIN64 )
    enum struct e_ldr_data_table : std::uint8_t {
        in_load_order,
        in_mem_order,
        in_init_order,
        max
    };
    ENUM_UNDERLYING_OPERATOR(e_ldr_data_table);

    struct rtl_balanced_node_t {
        rtl_balanced_node_t* m_child[2u]{},
            * m_left{}, * m_right{};

        address_t               m_parent_value{};
    };

    template < bool _wide >
    struct rtl_str_t {
        using char_t = std::conditional_t< _wide, wchar_t, char >;

        std::uint16_t    m_len{},
            m_max_len{};

        char_t* m_buffer{};
    };

    struct rtl_user_process_params_t {
        std::uint32_t   m_max_len{},
            m_len{},
            m_flags{},
            m_debug_flags{};

        address_t       m_con_handle{};
        std::uint32_t   m_con_flags{};

        address_t       m_standard_input{},
            m_standard_output{},
            m_standard_error{};

        struct {
            rtl_str_t< false >  m_dos_path{};
            address_t           m_handle{};
        }                   m_cur_dir{};

        rtl_str_t< true >   m_dll_path{},
            m_image_path_name{},
            m_cmd_line{};

        address_t           m_env{};
        std::uint32_t       m_starting_x{},
            m_starting_y{},
            m_count_x{},
            m_count_y{},
            m_count_chars_x{},
            m_count_chars_y{},
            m_file_attribute{},
            m_wnd_flags{},
            m_show_wnd_flags{};

        rtl_str_t< true >   m_wnd_title{},
            m_desktop_info{},
            m_shell_info{},
            m_runtime_data{};

        struct {
            std::uint16_t       m_flags{}, m_len{};
            std::uint32_t       m_timestamp{};

            rtl_str_t< false >  m_dos_path{};
        }                   m_cur_dirs[32u]{};

        std::uintptr_t      m_env_size{},
            m_env_ver{};
        address_t           m_pckg_dependency_data{};
        std::uint32_t       m_proc_group_id{},
            m_ldr_threads{};
    };

    struct ldr_data_t {
        std::uint32_t   m_len{};
        std::uint8_t    m_initialized{};
        address_t       m_ss_handle{};

        union {
            struct {
                LIST_ENTRY  m_in_load_order,
                    m_in_mem_order,
                    m_in_init_order;
            };

            LIST_ENTRY m_entries[-e_ldr_data_table::max]{};
        }               m_module_lists{};

        std::uintptr_t  m_entry_in_progress{};
        std::uint8_t    m_shutdown_in_progress{};
        std::uintptr_t  m_shutdown_thread_id{};
    };

    struct ldr_data_table_entry_t {
        union {
            struct {
                LIST_ENTRY  m_in_load_order,
                    m_in_mem_order,
                    m_in_init_order;
            };

            LIST_ENTRY m_entries[-e_ldr_data_table::max]{};
        }                   m_links{};

        address_t           m_dll_base{},
            m_ep{};
        std::uint32_t       m_image_size{};
        rtl_str_t< true >   m_full_dll_name{},
            m_base_dll_name{};
        std::uint8_t        m_flag_group[4u]{};
        std::uint32_t       m_flags{};
        std::uint16_t       m_obsolete_load_count{},
            m_tls_index{};
        LIST_ENTRY          m_hash_links{};
        std::uint32_t       m_timedata_stamp{};
        address_t           m_ep_activation_context{},
            m_lock{},
            m_ddag_node{};
        LIST_ENTRY          m_node_module_link{};
        address_t           m_load_context{},
            m_parent_dll_base{},
            m_switch_back_context{};
        rtl_balanced_node_t m_base_addr_index_node{},
            m_mapping_info_index_node{};
        address_t           m_original_base{};
        LARGE_INTEGER       m_load_time{};
        std::uint32_t       m_base_name_hash_value{},
            m_load_reason{},
            m_implicit_path_options{},
            m_ref_count{};
    };

    struct peb_t {

        ALWAYS_INLINE void for_each_ldr_data_table_entry(
            const std::function< bool(ldr_data_table_entry_t* const) >& fn, const e_ldr_data_table type
        ) {
            const auto list = &m_ldr->m_module_lists.m_entries[-type];

            for (auto i = list->Flink; i != list; i = i->Flink) {
                const auto entry = CONTAINING_RECORD(i, ldr_data_table_entry_t, m_links.m_entries[-type]);
                if (!entry)
                    continue;

                if (fn(entry))
                    break;
            }
        }

        std::uint8_t                m_inherited_addr_space{},
            m_read_image_file_exec_options{},
            m_being_debugged{},
            m_bit_field{};

        address_t                   m_mutant{}, m_image_base_addr{};
        ldr_data_t* m_ldr{};
        rtl_user_process_params_t* m_process_params{};

        address_t                   m_subsystem_data{},
            m_process_heap{};

        RTL_CRITICAL_SECTION* m_fast_peb_lock{};
        address_t                   m_atl_thunks_list{},
            m_ifeo_key{};

        std::uint32_t               m_cross_process_flags{};

        union {
            address_t   m_kernel_callback_table{},
                m_user_shared_info;
        };

        std::uint32_t               m_reserved0{},
            m_atl_thunks_list32{};
        address_t                   m_api_set_map{};
        std::uint32_t               m_tls_expansion_cnt{};
        address_t                   m_tls_bitmap{};
        std::uint32_t               m_tls_bitmap_bits[2u]{};

        address_t                   m_read_only_shared_mem_base{},
            m_hotpatch_info{},
            * m_read_only_static_srv_data{},
            m_ansi_code_page_data{},
            m_oem_code_page_data{},
            m_unicode_case_table_data{};

        std::uint32_t               m_processors_count{},
            m_nt_global_flag{};

        LARGE_INTEGER               m_critical_section_timeout{};
        address_t                   m_heap_segment_reserve{},
            m_heap_segment_commit{},
            m_heap_decommit_total_free_threshold{},
            m_heap_decommit_free_block_threshold{};

        std::uint32_t               m_heaps_count{},
            m_max_heaps_count{};

        address_t                   m_process_heaps{},
            m_gdi_shared_handle_table{},
            m_process_starter_helper{};

        std::uint32_t               m_gdi_attribute_list{};
        RTL_CRITICAL_SECTION* m_ldr_lock{};

        std::uint32_t               m_os_major_ver{},
            m_os_minor_ver{};

        std::uint16_t               m_os_build_number{},
            m_oscsd_ver{};

        std::uint32_t               m_os_patform_id{},
            m_image_subsystem{},
            m_image_subsystem_major_ver{},
            m_image_subsystem_minor_ver{};

        std::uintptr_t              m_active_process_affinity_mask{};
#ifdef _WIN32
        std::uint32_t               m_gdi_handle_buffer[34u]{};
#else
        std::uint32_t               m_gdi_handle_buffer[60u]{};
#endif

        address_t                   m_post_process_init_routine{},
            m_tls_expansion_bitmap{};
        std::uint32_t               m_tls_expansion_bitmap_bits[32u]{},
            m_session_id{};

        ULARGE_INTEGER              m_app_compat_flags{},
            m_app_compat_flags_user{};

        address_t                   m_shim_data{},
            m_app_compat_info{};

        rtl_str_t< true >           m_csd_ver{};
        address_t                   m_activation_context_data{},
            m_process_asm_storage_map{},
            m_sys_default_activation_context_data_map{},
            m_sys_asm_storage_map{},
            m_min_stack_commit{},
            m_fls_callback{};

        LIST_ENTRY                  m_fls_list_head{};
        address_t                   m_fls_bitmap{};
        std::uint32_t               m_fls_bitmap_bits[4u]{},
            m_fls_high_index{};

        address_t                   m_wer_registration_data{},
            m_wer_ship_assert{},
            m_context_data{},
            m_image_hdr_hash{};

        std::uint32_t               m_tracing_flags{};
        std::uint64_t               m_csr_srv_read_only_shared_mem_base{};

        address_t                   m_tpp_worker_list_lock{};
        LIST_ENTRY                  m_tpp_worker_list{};

        address_t                   m_wait_on_addr_hash_table[128u]{};
    };

    ALWAYS_INLINE peb_t* peb()
    {

#if defined( _M_X64 ) || defined( __amd64__ )
        return reinterpret_cast<peb_t*>(__readgsqword(0x60ul));
#elif defined( _M_IX86 ) || defined( __i386__ )
        return reinterpret_cast<peb_t*>(__readfsdword(0x30ul));
#elif defined( _M_ARM ) || defined( __arm__ )
        return *reinterpret_cast<peb_t**>(_MoveFromCoprocessor(15, 0, 13, 0, 2) + 0x30);
#elif defined( _M_ARM64 ) || defined( __aarch64__ )
        return *reinterpret_cast<peb_t**>(__getReg(18) + 0x60);
#elif defined( _M_IA64 ) || defined( __ia64__ )
        return *reinterpret_cast<peb_t**>(static_cast<std::uint8_t*>(_rdteb()) + 0x60u);
#elif defined( _M_ALPHA )
        return *reinterpret_cast<peb_t**>(static_cast<std::uint8_t*>(_rdteb()) + 0x30u);
#elif defined( _M_MIPS )
        return *reinterpret_cast<peb_t**>(*reinterpret_cast<std::uintptr_t*>(0x7ffff030u) + 0x30u);
#elif defined( _M_PPC )
        return *reinterpret_cast<peb_t**>(__gregister_get(13) + 0x30);
#else
#error "unsupported architecture"
#endif
    }
#endif

    template < typename _value_t >
    ALWAYS_INLINE _value_t load_from_reg(_value_t value) {

        return value;

    }

    template < std::size_t _size >
        requires (_size >= 1u)
    struct byte_seq_t {
    private:
        static constexpr auto k_wildcard = '?';
        static constexpr auto k_delimiter = ' ';
        static constexpr auto k_not = '!';
    public:
        struct byte_t {
            enum struct e_type : std::uint8_t {
                invalid,
                equal,
                not_equal,
                wildcard
            };

            ALWAYS_INLINE bool valid(const std::uint8_t byte) const {
                if (m_type == e_type::invalid)
                    return false;

                return m_type == e_type::wildcard
                    || (m_value == byte) ^ (m_type == e_type::not_equal);
            }

            e_type          m_type{};
            std::uint8_t    m_value{};
        };

        using bytes_t = std::array< byte_t, _size >;

        template < typename _value_t >
            requires (!std::_Is_any_of_v< std::decay_t< _value_t >, std::string_view, const char* >)
        static consteval std::size_t measure(const _value_t) {
            return _size;
        }

        static consteval std::size_t measure(const std::string_view str) {
            std::size_t size{};

            for (std::size_t i{}; i < str.size(); i += 2u) {
                const auto& chr = str.at(i);
                if (chr == k_wildcard)
                    ++size;
                else if (chr == k_delimiter)
                    --i;
                else {
                    if (chr == k_not)
                        ++i;

                    ++size;
                }
            }

            return size;
        }

        static constexpr bytes_t parse(const std::string_view str) {
            constexpr auto hex2int = [](const std::size_t chr) {
                if (chr >= '0'
                    && chr <= '9')
                    return chr - '0';

                if (chr >= 'A'
                    && chr <= 'F')
                    return chr - 'A' + 10u;

                return chr - 'a' + 10u;
            };

            bytes_t bytes{};

            for (std::size_t i{}, j{}; i < str.size(); i += 2u) {
                const auto& chr = str.at(i);
                if (chr == k_wildcard)
                    bytes.at(j++).m_type = byte_t::e_type::wildcard;
                else if (chr == k_delimiter)
                    --i;
                else {
                    auto& byte = bytes.at(j++);

                    if (chr != k_not)
                        byte.m_type = byte_t::e_type::equal;
                    else {
                        byte.m_type = byte_t::e_type::not_equal;

                        ++i;
                    }

                    byte.m_value = static_cast<std::uint8_t>(
                        hex2int(str.at(i)) * 0x10u + hex2int(str.at(i + 1u))
                        );
                }
            }

            return bytes;
        }

        ALWAYS_INLINE constexpr byte_seq_t() = default;

        ALWAYS_INLINE consteval byte_seq_t(const bytes_t& bytes) : m_bytes{ bytes } {}

        template < typename _lambda_t, std::size_t... _indices >
            requires std::is_invocable_v< _lambda_t >
        ALWAYS_INLINE byte_seq_t(const _lambda_t lambda, std::index_sequence< _indices... >) {
            if constexpr (std::is_same_v< const char*, std::decay_t< std::invoke_result_t< _lambda_t > > >) {
                constexpr auto seq = parse(lambda());

                m_bytes = { load_from_reg(seq[_indices])... };

                return;
            }

            m_bytes = {
                byte_t{
                    byte_t::e_type::equal,
                    reinterpret_cast<const std::uint8_t*>(lambda())[_indices]
                }...
            };
        }

        ALWAYS_INLINE address_t search(const address_t start, const address_t end) const {
            const auto seq_end = m_bytes.end();

            for (auto i = start.as< std::uint8_t* >(); ; ++i) {
                auto j = i;
                for (auto k = m_bytes.begin(); ; ++j, k = std::next(k)) {
                    if (k == seq_end)
                        return i;

                    if (j == end.as< std::uint8_t* >())
                        return end;

                    if (!k->valid(*j))
                        break;
                }
            }

            return end;
        }

        bytes_t m_bytes{};
    };
}



using hash_t = std::size_t;
using ulong_t = unsigned long;


template < typename _type >
inline constexpr auto is_char_v = std::is_same_v< _type, char > || std::is_same_v< _type, char16_t >
|| std::is_same_v< _type, char32_t > || std::is_same_v< _type, wchar_t >;

template < typename _char_t >
    requires is_char_v< _char_t >
ALWAYS_INLINE constexpr hash_t hash(const _char_t* const str, const std::size_t len);

template < typename _char_t >
    requires is_char_v< _char_t >
ALWAYS_INLINE constexpr hash_t hash(const _char_t* const str);


class c_main
{
private:

    std::uint32_t m_fps_unlock_addr{};
    using modules_t = std::unordered_map< hash_t, detail::x86_pe_image_t* >;

    bool wait_for_all_modules(modules_t& modules) const;
    bool is_samp_loaded() const;

public:

    void init();
    void uninit();

    void* mem_cpy(void* dest, const void* src, size_t len);
    int mem_set(void* _dest, int c, size_t len);

};

inline const auto g_main = std::make_unique< c_main >();

