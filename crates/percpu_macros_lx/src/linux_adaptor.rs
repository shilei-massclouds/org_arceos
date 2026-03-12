use quote::{format_ident, quote};
use syn::{Ident, Type};

#[allow(unused)]
/// Generate a code block that reads the value of the per-CPU variable on the current CPU, based on the inner symbol
/// name and the type of the variable.
///
/// The type of the variable must be one of the following: `bool`, `u8`, `u16`, `u32`, `u64`, or `usize`.
pub fn gen_read_current_raw(symbol: &Ident, ty: &Type) -> proc_macro2::TokenStream {
    let ty_str = quote!(#ty).to_string();
    let ty_size;
    let mut real_ty = quote! { #ty };
    let mut ret = quote! { *ptr };
    match ty_str.as_str() {
        "u8" | "bool" => {
            ty_size = 1;
            real_ty = quote! { u8 };
            ret = quote! { *ptr != 0 };
        },
        "u16" => {
            ty_size = 2;
        },
        "u32" => {
            ty_size = 4;
        },
        "u64" | "usize" => {
            ty_size = 8;
        },
        _ => unreachable!(),
    };

    {
        quote! {
            extern "C" {
                fn cl_this_cpu_ptr(pcp: *const #ty, size: i32) -> *const #real_ty;
            }
            let ptr = cl_this_cpu_ptr(core::ptr::addr_of!(#symbol), #ty_size);
            #ret
        }
    }
}

#[allow(unused)]
/// Generate a code block that writes the value of the per-CPU variable on the current CPU, based on the inner symbol
/// name, the identifier of the value to write, and the type of the variable.
///
/// The type of the variable must be one of the following: `bool`, `u8`, `u16`, `u32`, `u64`, or `usize`.
pub fn gen_write_current_raw(symbol: &Ident, val: &Ident, ty: &Type) -> proc_macro2::TokenStream {
    let ty_str = quote!(#ty).to_string();
    let ty_fixup = if ty_str.as_str() == "bool" {
        format_ident!("u8")
    } else {
        format_ident!("{}", ty_str)
    };
    let ty_size;
    match ty_str.as_str() {
        "u8" | "bool" => {
            ty_size = 1;
        },
        "u16" => {
            ty_size = 2;
        },
        "u32" => {
            ty_size = 4;
        },
        "u64" | "usize" => {
            ty_size = 8;
        },
        _ => unreachable!(),
    };

    {
        quote! {
            extern "C" {
                fn cl_this_cpu_ptr(pcp: *mut #ty, size: i32) -> *mut #ty_fixup;
            }
            let ptr = cl_this_cpu_ptr(core::ptr::addr_of_mut!(#symbol), #ty_size);
            *ptr = #val as #ty_fixup;
        }
    }
    /*

    let rv64_op = match ty_str.as_str() {
        "u8" | "bool" => "sb",
        "u16" => "sh",
        "u32" => "sw",
        "u64" | "usize" => "sd",
        _ => unreachable!(),
    };
    let rv64_code = quote! {
        ::core::arch::asm!(
            "lui {0}, %hi({VAR})",
            "add {0}, {0}, gp",
            concat!(#rv64_op, " {1}, %lo({VAR})({0})"),
            out(reg) _,
            in(reg) #val as #ty_fixup,
            VAR = sym #symbol,
        );
    };

    quote! {
        { #rv64_code }
    }
    */
}
