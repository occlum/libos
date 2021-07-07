use libc::*;
use std::ffi::CString;

use sgx_types::{
    sgx_report_data_t, sgx_ql_qv_result_t
};

const SGXIOC_GET_DCAP_QUOTE_SIZE: c_ulong = 0x80047307;
const SGXIOC_GEN_DCAP_QUOTE: c_ulong = 0xc0187308;
const SGXIOC_GET_DCAP_SUPPLEMENTAL_SIZE: c_ulong = 0x80047309;
const SGXIOC_VER_DCAP_QUOTE: c_ulong = 0xc030730a;


// Copy from occlum/src/libos/src/fs/dev_fs/dev_sgx/mod.rs
//#[allow(dead_code)]
#[repr(C)]
pub struct IoctlGenDCAPQuoteArg {
    pub report_data: *const sgx_report_data_t, // Input
    pub quote_size: *mut u32,                  // Input/output
    pub quote_buf: *mut u8,                    // Output
}

// Copy from occlum/src/libos/src/fs/dev_fs/dev_sgx/mod.rs
//#[allow(dead_code)]
#[repr(C)]
pub struct IoctlVerDCAPQuoteArg {
    pub quote_buf: *const u8,                               // Input
    pub quote_size: u32,                                    // Input
    pub collateral_expiration_status: *mut u32,             // Output
    pub quote_verification_result: *mut sgx_ql_qv_result_t, // Output
    pub supplemental_data_size: u32,                        // Input (optional)
    pub supplemental_data: *mut u8,                         // Output (optional)
}

pub struct DcapQuote {
    fd: c_int,
    quote_size: u32,
    supplemental_size: u32,
}

impl DcapQuote {
    pub fn new() -> Self {
        println!("DcapQuote: new");

        let path =  CString::new("/dev/sgx").unwrap();
        let fd = unsafe { libc::open(path.as_ptr(), O_RDONLY) };
        if fd > 0 {
            Self {
                fd: fd,
                quote_size: 0,
                supplemental_size: 0,
            }
        } else {
            panic!("Open /dev/sgx failed")
        }
    }

    pub fn get_quote_size(&mut self) -> u32 {
        println!("DcapQuote: get_quote_size");

        let size: u32 = 0;
        let ret = unsafe { libc::ioctl(self.fd, SGXIOC_GET_DCAP_QUOTE_SIZE, &size) };
        if ret < 0 {
            panic!("IOCTRL SGXIOC_GET_DCAP_QUOTE_SIZE failed");
        } else {
            self.quote_size = size;
            size
        }
    }

    pub fn generate_quote(&mut self, quote_buf: *mut u8,  report_data: *const sgx_report_data_t) -> Result<i32, &'static str> {
        println!("DcapQuote: generate_quote");

        let quote_arg: IoctlGenDCAPQuoteArg = IoctlGenDCAPQuoteArg {
            report_data: report_data,
            quote_size: &mut self.quote_size,
            quote_buf: quote_buf,
        };

        let ret = unsafe { libc::ioctl(self.fd, SGXIOC_GEN_DCAP_QUOTE, &quote_arg) };
        if ret < 0 {
            Err("IOCTRL SGXIOC_GEN_DCAP_QUOTE failed")
        } else {
            Ok( 0 )
        }
    }

    pub fn get_supplemental_data_size(&mut self) -> u32 {
        println!("DcapQuote: get_supplemental_data_size");

        let size: u32 = 0;
        let ret = unsafe { libc::ioctl(self.fd, SGXIOC_GET_DCAP_SUPPLEMENTAL_SIZE, &size) };
        if ret < 0 {
            panic!("IOCTRL SGXIOC_GET_DCAP_SUPPLEMENTAL_SIZE failed");
        } else {
            self.supplemental_size = size;
            size
        }
    }

    pub fn verify_quote(&mut self, verify_arg: *mut IoctlVerDCAPQuoteArg) -> Result<i32, &'static str> {
        println!("DcapQuote: verify_quote");

        let ret = unsafe { libc::ioctl(self.fd, SGXIOC_VER_DCAP_QUOTE, verify_arg) };
        if ret < 0 {
            println!("ret = {}", ret);
            Err("IOCTRL SGXIOC_VER_DCAP_QUOTE failed")
        } else {
            Ok( 0 )
        }        
    }

    pub fn close(&mut self) {
        println!("DcapQuote: close");
        unsafe { libc::close(self.fd) };
    }
}

