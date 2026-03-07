//! Macros for LinuxAdaptor

extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput, Data, DataEnum, Ident};

#[proc_macro_attribute]
pub fn generate_state_callbacks(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let enum_name = &input.ident;

    // parse enum items
    let variants = match input.data {
        Data::Enum(DataEnum { ref variants, .. }) => variants,
        _ => panic!("This macro only works on enums"),
    };

    let mut variant_names = variants.iter()
        .map(|v| v.ident.clone())
        .collect::<Vec<_>>();

    // make sure that the last item is `NumberOfStates`
    let last_variant = variant_names.pop().expect("Enum must have at least one variant");
    if last_variant != "NumberOfStates" {
        panic!("Last variant must be named 'NumberOfStates'");
    }

    // construct callback declarations
    let callback_names = variant_names.iter()
        .map(|v| Ident::new(&format!("{}CB", v), v.span()))
        .collect::<Vec<_>>();

    // construct callback array
    let expanded = quote! {
        #input

        static StateCallbacks: [fn(); #enum_name::NumberOfStates as usize] = [
            #(#callback_names),*
        ];
    };

    TokenStream::from(expanded)
}
