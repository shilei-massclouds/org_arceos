//! Macros to define and access a per-CPU data structure for Linux Adaptor.
//! **DO NOT** use this crate directly. Use the [percpu_lx] crate instead.
//!

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::{format_ident, quote};
use syn::{Error, ItemStatic};

mod linux_adaptor;

/// Defines a per-CPU static variable.
///
/// It should be used on a `static` variable definition.
///
/// See the documentation of the [percpu](https://docs.rs/percpu) crate for more details.
#[proc_macro_attribute]
pub fn def_percpu(attr: TokenStream, item: TokenStream) -> TokenStream {
    let code = def_percpu_impl(attr, item);
    //eprintln!("{}", code);
    code
}

fn compiler_error(err: Error) -> TokenStream {
    err.to_compile_error().into()
}

fn def_percpu_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    if !attr.is_empty() {
        return compiler_error(Error::new(
            Span::call_site(),
            "expect an empty attribute: `#[def_percpu]`",
        ));
    }

    let ast = syn::parse_macro_input!(item as ItemStatic);

    let attrs = &ast.attrs;
    let vis = &ast.vis;
    let name = &ast.ident;
    let ty = &ast.ty;
    let init_expr = &ast.expr;

    let inner_symbol_name = &format_ident!("__PERCPU_{}", name);
    let struct_name = &format_ident!("{}_WRAPPER", name);

    let ty_str = quote!(#ty).to_string();
    let is_primitive_int = ["bool", "u8", "u16", "u32", "u64", "usize"].contains(&ty_str.as_str());

    // Do not generate `fn read_current()`, `fn write_current()`, etc for non primitive types.
    let read_write_methods = if is_primitive_int {
        let read_current_raw = linux_adaptor::gen_read_current_raw(inner_symbol_name, ty);
        let write_current_raw =
            linux_adaptor::gen_write_current_raw(inner_symbol_name, &format_ident!("val"), ty);

        quote! {
            /// Returns the value of the per-CPU static variable on the current CPU.
            ///
            /// # Safety
            ///
            /// Caller must ensure that preemption is disabled on the current CPU.
            #[inline]
            pub unsafe fn read_current_raw(&self) -> #ty {
                #read_current_raw
            }

            /// Set the value of the per-CPU static variable on the current CPU.
            ///
            /// # Safety
            ///
            /// Caller must ensure that preemption is disabled on the current CPU.
            #[inline]
            pub unsafe fn write_current_raw(&self, val: #ty) {
                #write_current_raw
            }

            /// Returns the value of the per-CPU static variable on the current CPU. Preemption will be disabled during
            /// the call.
            pub fn read_current(&self) -> #ty {
                unsafe { self.read_current_raw() }
            }

            /// Set the value of the per-CPU static variable on the current CPU. Preemption will be disabled during the
            /// call.
            pub fn write_current(&self, val: #ty) {
                unsafe { self.write_current_raw(val) }
            }
        }
    } else {
        quote! {}
    };

    quote! {
        #[link_section = ".data..percpu"]
        #(#attrs)*
        static mut #inner_symbol_name: #ty = #init_expr;

        #[doc = concat!("Wrapper struct for the per-CPU data [`", stringify!(#name), "`]")]
        #[allow(non_camel_case_types)]
        #vis struct #struct_name {}

        #(#attrs)*
        #vis static #name: #struct_name = #struct_name {};

        impl #struct_name {
            #read_write_methods
        }

    }.into()
}

/*
#[cfg_attr(feature = "sp-naive", path = "naive.rs")]
mod arch;

#[cfg(any(feature = "sp-naive", not(feature = "custom-base")))]
fn def_percpu_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    if !attr.is_empty() {
        return compiler_error(Error::new(
            Span::call_site(),
            "expect an empty attribute: `#[def_percpu]`",
        ));
    }

    let ast = syn::parse_macro_input!(item as ItemStatic);

    let attrs = &ast.attrs;
    let vis = &ast.vis;
    let name = &ast.ident;
    let ty = &ast.ty;
    let init_expr = &ast.expr;

    let inner_symbol_name = &format_ident!("__PERCPU_{}", name);
    let struct_name = &format_ident!("{}_WRAPPER", name);

    let ty_str = quote!(#ty).to_string();
    let is_primitive_int = ["bool", "u8", "u16", "u32", "u64", "usize"].contains(&ty_str.as_str());

    let no_preempt_guard = if cfg!(feature = "preempt") {
        quote! { let _guard = percpu::__priv::NoPreemptGuard::new(); }
    } else {
        quote! {}
    };

    // Do not generate `fn read_current()`, `fn write_current()`, etc for non primitive types.
    let read_write_methods = if is_primitive_int {
        let read_current_raw = arch::gen_read_current_raw(inner_symbol_name, ty);
        let write_current_raw =
            arch::gen_write_current_raw(inner_symbol_name, &format_ident!("val"), ty);

        quote! {
            /// Returns the value of the per-CPU static variable on the current CPU.
            ///
            /// # Safety
            ///
            /// Caller must ensure that preemption is disabled on the current CPU.
            #[inline]
            pub unsafe fn read_current_raw(&self) -> #ty {
                #read_current_raw
            }

            /// Set the value of the per-CPU static variable on the current CPU.
            ///
            /// # Safety
            ///
            /// Caller must ensure that preemption is disabled on the current CPU.
            #[inline]
            pub unsafe fn write_current_raw(&self, val: #ty) {
                #write_current_raw
            }

            /// Returns the value of the per-CPU static variable on the current CPU. Preemption will be disabled during
            /// the call.
            pub fn read_current(&self) -> #ty {
                #no_preempt_guard
                unsafe { self.read_current_raw() }
            }

            /// Set the value of the per-CPU static variable on the current CPU. Preemption will be disabled during the
            /// call.
            pub fn write_current(&self, val: #ty) {
                #no_preempt_guard
                unsafe { self.write_current_raw(val) }
            }
        }

        // Todo: maybe add `(read|write)_remote(_raw)?` here?
    } else {
        quote! {}
    };

    let symbol_vma = arch::gen_symbol_vma(inner_symbol_name);
    let offset = arch::gen_offset(inner_symbol_name);
    let current_ptr = arch::gen_current_ptr(inner_symbol_name, ty);
    quote! {
        #[cfg_attr(not(target_os = "macos"), link_section = ".percpu")] // unimplemented on macos
        #(#attrs)*
        static mut #inner_symbol_name: #ty = #init_expr;

        #[doc = concat!("Wrapper struct for the per-CPU data [`", stringify!(#name), "`]")]
        #[allow(non_camel_case_types)]
        #vis struct #struct_name {}

        #(#attrs)*
        #vis static #name: #struct_name = #struct_name {};

        impl #struct_name {
            /// Returns the virtual memory address of this per-CPU static
            /// variable in the `.percpu` section.
            ///
            /// It's same across all CPUs, and also the same as `offset` if the
            /// "non-zero-vma" feature is not enabled.
            #[inline]
            pub fn symbol_vma(&self) -> usize {
                #symbol_vma
            }

            /// Returns the offset relative to the per-CPU data area base.
            #[inline]
            pub fn offset(&self) -> usize {
                #offset
            }

            /// Returns the raw pointer of this per-CPU static variable on the current CPU.
            ///
            /// # Safety
            ///
            /// Caller must ensure that preemption is disabled on the current CPU.
            #[inline]
            pub unsafe fn current_ptr(&self) -> *const #ty {
                #current_ptr
            }

            /// Returns the reference of the per-CPU static variable on the current CPU.
            ///
            /// # Safety
            ///
            /// Caller must ensure that preemption is disabled on the current CPU.
            #[inline]
            pub unsafe fn current_ref_raw(&self) -> &#ty {
                &*self.current_ptr()
            }

            /// Returns the mutable reference of the per-CPU static variable on the current CPU.
            ///
            /// # Safety
            ///
            /// Caller must ensure that preemption is disabled on the current CPU.
            #[inline]
            #[allow(clippy::mut_from_ref)]
            pub unsafe fn current_ref_mut_raw(&self) -> &mut #ty {
                &mut *(self.current_ptr() as *mut #ty)
            }

            /// Manipulate the per-CPU data on the current CPU in the given closure.
            /// Preemption will be disabled during the call.
            pub fn with_current<F, T>(&self, f: F) -> T
            where
                F: FnOnce(&mut #ty) -> T,
            {
                #no_preempt_guard
                f(unsafe { self.current_ref_mut_raw() })
            }

            /// Returns the raw pointer of this per-CPU static variable on the given CPU.
            ///
            /// # Safety
            ///
            /// Caller must ensure that
            /// - the CPU ID is valid, and
            /// - data races will not happen.
            #[inline]
            pub unsafe fn remote_ptr(&self, cpu_id: usize) -> *const #ty {
                let base = percpu::percpu_area_base(cpu_id);
                let offset = #offset;
                (base + offset) as *const #ty
            }

            /// Returns the reference of the per-CPU static variable on the given CPU.
            ///
            /// # Safety
            ///
            /// Caller must ensure that
            /// - the CPU ID is valid, and
            /// - data races will not happen.
            #[inline]
            pub unsafe fn remote_ref_raw(&self, cpu_id: usize) -> &#ty {
                &*self.remote_ptr(cpu_id)
            }

            /// Returns the mutable reference of the per-CPU static variable on the given CPU.
            ///
            /// # Safety
            ///
            /// Caller must ensure that
            /// - the CPU ID is valid, and
            /// - data races will not happen.
            #[inline]
            #[allow(clippy::mut_from_ref)]
            pub unsafe fn remote_ref_mut_raw(&self, cpu_id: usize) -> &mut #ty {
                &mut *(self.remote_ptr(cpu_id) as *mut #ty)
            }

            #read_write_methods
        }
    }
    .into()
}

#[doc(hidden)]
#[cfg(not(feature = "sp-naive"))]
#[proc_macro]
pub fn percpu_symbol_vma(item: TokenStream) -> TokenStream {
    let symbol = &format_ident!("{}", item.to_string());
    let offset = arch::gen_symbol_vma(symbol);
    quote!({ #offset }).into()
}

#[cfg(all(feature = "custom-base", not(feature = "sp-naive")))]
fn def_percpu_impl(attr: TokenStream, input: TokenStream) -> TokenStream {
    if !attr.is_empty() {
        return compiler_error(Error::new(
            Span::call_site(),
            "expect an empty attribute: `#[def_percpu]`",
        ));
    }

    use syn::parse_macro_input;

    let ItemStatic {
        attrs,
        vis,
        static_token,
        mutability,
        ident,
        ty,
        expr,
        ..
    } = parse_macro_input!(input as ItemStatic);

    quote! {
        #[unsafe(link_section = ".percpu")]
        #(#attrs)*
        #vis #static_token #mutability #ident : percpu::PerCpuData<#ty> = percpu::PerCpuData::new(#expr);
    }
    .into()
}
*/
