use std::boxed::Box;
use libc::{c_void};

use sgx_types::{
    sgx_report_data_t, sgx_ql_qv_result_t
};

mod dcap_quote;
pub use crate::dcap_quote::*;

#[no_mangle]
pub extern "C" fn dcap_quote_open() -> *mut c_void {
    Box::into_raw(Box::new(DcapQuote::new())) as *mut c_void
}

#[no_mangle]
pub extern "C" fn dcap_get_quote_size(handle: *mut c_void) -> u32 {
    if handle.is_null() {
        return 0
    }

    let dcap = unsafe {
        &mut *(handle as *mut DcapQuote)
    };

    dcap.get_quote_size()
}

#[no_mangle]
pub extern "C" fn dcap_generate_quote(
    handle: *mut c_void, 
    quote_buf: *mut u8,
    report_data: *const sgx_report_data_t) -> i32 
{
    if handle.is_null() {
        return -1
    }

    let dcap = unsafe {
        &mut *(handle as *mut DcapQuote)
    };

    dcap.generate_quote(quote_buf, report_data).unwrap();

    0
}

#[no_mangle]
pub extern "C" fn dcap_get_supplemental_data_size(handle: *mut c_void) -> u32 {
    if handle.is_null() {
        return 0
    }

    let dcap = unsafe {
        &mut *(handle as *mut DcapQuote)
    };

    dcap.get_supplemental_data_size()
}

#[no_mangle]
pub extern "C" fn dcap_verify_quote(
    handle: *mut c_void, 
    quote_buf: *const u8,
    quote_size: u32,
    collateral_expiration_status: *mut u32,
    quote_verification_result: *mut sgx_ql_qv_result_t,
    supplemental_data_size: u32,
    supplemental_data: *mut u8) -> i32 
{
    if handle.is_null() {
        return -1
    }

    let dcap = unsafe {
        &mut *(handle as *mut DcapQuote)
    };

    let mut verify_arg = IoctlVerDCAPQuoteArg {
        quote_buf: quote_buf,
        quote_size: quote_size,
        collateral_expiration_status: collateral_expiration_status,
        quote_verification_result: quote_verification_result,
        supplemental_data_size: supplemental_data_size,
        supplemental_data: supplemental_data,
    };

    dcap.verify_quote(&mut verify_arg).unwrap();

    0
}


#[no_mangle]
pub extern "C" fn dcap_quote_close(handle: *mut c_void) {
    if handle.is_null() {
        return
    }

    let dcap = unsafe {
        &mut *(handle as *mut DcapQuote)
    };

    dcap.close();

    unsafe {
        Box::from_raw(handle);
    }
}
