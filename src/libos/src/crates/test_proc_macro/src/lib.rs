extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

#[proc_macro_attribute]
pub fn occlum_test(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let func = parse_macro_input!(input as ItemFn);
    let func_ident = &func.sig.ident;
    let func_attrs = &func.attrs;
    let should_panic = func_attrs
        .iter()
        .find(|&attr| attr.path.is_ident("should_panic"))
        .is_some();

    let quote = quote!(
        #[cfg(feature = "unit_test")]
        #func

        #[cfg(feature = "unit_test")]
        inventory::submit!(
            unit_test::TestCase::new(
                module_path!().replace("occlum_libos_core_rs::", "").to_string() +
                     "::" + stringify!(#func_ident),
                #func_ident, #should_panic,
            )
        );
    );

    quote.into()
}
