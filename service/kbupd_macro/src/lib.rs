//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::parse::{Parse, ParseStream, Result};
use syn::punctuated::Punctuated;
use syn::token;
use syn::{braced, parenthesized, parse_macro_input};
use syn::{Expr, Ident, Token, Type, Visibility};

struct LazyGroup {
    visibility:    Visibility,
    function_name: Ident,
    items:         Punctuated<LazyItem, Token![;]>,
}

impl Parse for LazyGroup {
    fn parse(input: ParseStream) -> Result<Self> {
        let visibility = input.parse()?;
        input.parse::<token::Fn>()?;
        let function_name = input.parse()?;
        let _unused1;
        let _ = parenthesized!(_unused1 in input);
        let content;
        let _ = braced!(content in input);
        let items = content.parse_terminated(LazyItem::parse)?;
        Ok(LazyGroup {
            visibility,
            function_name,
            items,
        })
    }
}

struct LazyItem {
    visibility: Visibility,
    name:       Ident,
    ty:         Type,
    expr:       Expr,
}

impl Parse for LazyItem {
    fn parse(input: ParseStream) -> Result<Self> {
        let visibility = input.parse()?;
        input.parse::<Token![static]>()?;
        input.parse::<Token![ref]>()?;
        let name = input.parse()?;
        input.parse::<Token![:]>()?;
        let ty = input.parse()?;
        input.parse::<Token![=]>()?;
        let expr = input.parse()?;
        Ok(LazyItem {
            visibility,
            name,
            ty,
            expr,
        })
    }
}

/// Create a number of lazy_static! objects, collect the variable
/// names into a vector, and derive an initialization function that
/// calls 'lazy_static::initialize(&variable)' on each lazy_static!
/// object.
///
/// This macro parses the following syntax:
/// ```ignore
/// lazy_init! {
///     $INIT_FUNC_VISIBILITY fn $INIT_FUNC_NAME {
///         $ITEM_VISIBILITY static ref $ITEM_NAME: $ITEM_TYPE = $ITEM_EXPR;
///         ...
///     }
/// }
/// ```
///
/// Where:
///
/// INIT_FUNC_VISIBILITY - the visibility of the init function.
/// INIT_FUNC_NAME - the name of the init function.
/// ITEM_VISIBILITY - the visibility of the lazy_static! variable.
/// ITEM_NAME - the name of the lazy_static! variable.
/// ITEM_TYPE - the type of the lazy_static! variable.
/// ITEM_EXPR - an expression used to initialized the lazy_static! variable.
///
/// For example:
/// ```ignore
/// use kbupd_macro::lazy_init;
///
/// lazy_init! {
///     pub fn init_strings() {
///         pub static ref HELLO: String = String::from("Hello");
///         pub static ref WORLD: String = String::from("World");
///     }
/// }
/// ```
///
/// The example above is expanded as:
/// ```
/// use lazy_static;
///
/// lazy_static::lazy_static! {
///     pub static ref HELLO: String = String::from("Hello");
///     pub static ref WORLD: String = String::from("World");
/// }
/// pub fn init_strings() {
///     lazy_static::initialize(&HELLO);
///     lazy_static::initialize(&WORLD);
/// }
/// ```
#[proc_macro]
pub fn lazy_init(input: TokenStream) -> TokenStream {
    let lazy_group = parse_macro_input!(input as LazyGroup);

    let mut expanded = proc_macro2::TokenStream::new();

    let lazy_visibilities: Vec<_> = lazy_group.items.iter().map(|item| &item.visibility).collect();
    let lazy_names: Vec<_> = lazy_group.items.iter().map(|item| &item.name).collect();
    let lazy_types: Vec<_> = lazy_group.items.iter().map(|item| &item.ty).collect();
    let lazy_exprs: Vec<_> = lazy_group.items.iter().map(|item| &item.expr).collect();

    if lazy_names.len() > 0 {
        let visibility = lazy_group.visibility.clone();
        let function_name = lazy_group.function_name.clone();
        expanded.extend(quote! {
            lazy_static::lazy_static! {
                #(
                    #lazy_visibilities static ref #lazy_names : #lazy_types = #lazy_exprs ;
                )*
            }

            #visibility fn #function_name() {
                #(
                    lazy_static::initialize(&#lazy_names);
                )*
            }
        });
    }

    TokenStream::from(expanded)
}
