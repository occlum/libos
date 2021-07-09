extern crate dcap_quote;
use std::str;
use dcap_quote::*;
use sgx_types::{
    sgx_report_data_t, sgx_ql_qv_result_t, sgx_report_body_t, sgx_quote3_t
};

struct DcapDemo {
    dcap_quote: DcapQuote,
    quote_size: u32,
    quote_buf_ptr: *mut u8,
    req_data: sgx_report_data_t,
    supplemental_size: u32,
    suppl_buf_ptr: *mut u8,
}

impl DcapDemo {
    pub fn new(report_data: &str) -> Self {
        let mut dcap = DcapQuote::new();
        let quote_size = dcap.get_quote_size();
        let supplemental_size = dcap.get_supplemental_data_size();
        let mut quote_buf: Vec<u8> = vec![0; quote_size as usize];
        let quote_ptr = quote_buf.as_mut_ptr();
        let mut suppl_buf: Vec<u8> = vec![0; supplemental_size as usize];
        let suppl_ptr = suppl_buf.as_mut_ptr();
        let mut req_data = sgx_report_data_t::default();

        //fill in the report data array
        for (pos, val) in report_data.as_bytes().iter().enumerate() {
            req_data.d[pos] = *val;
        }

        Self {
            dcap_quote: dcap,
            quote_size: quote_size,
            quote_buf_ptr: quote_ptr,
            req_data: req_data,
            supplemental_size: supplemental_size,
            suppl_buf_ptr: suppl_ptr
        }
    }

    fn dcap_quote_gen(&mut self) -> Result<i32, &'static str> {
        self.dcap_quote.generate_quote(self.quote_buf_ptr, &mut self.req_data).unwrap();

        println!("DCAP generate quote successfully");

        Ok( 0 )
    }

    fn dcap_quote_get_report_body(&mut self) -> Result<*const sgx_report_body_t, &'static str> {
        let quote3: *mut sgx_quote3_t = self.quote_buf_ptr as *mut sgx_quote3_t;
        let report_body = unsafe { &((*quote3).report_body) };

        Ok(report_body)
    }

    fn dcap_quote_get_report_data(&mut self) -> Result<*const sgx_report_data_t, &'static str> {
        let report_body_ptr = self.dcap_quote_get_report_body().unwrap();
        let report_data_ptr = unsafe { &(*report_body_ptr).report_data };

        Ok(report_data_ptr)
    }

    fn dcap_quote_ver(&mut self) -> Result<sgx_ql_qv_result_t, &'static str> {
        let mut quote_verification_result = sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED;
        let mut status = 1;
    
        let mut verify_arg = IoctlVerDCAPQuoteArg {
            quote_buf: self.quote_buf_ptr,
            quote_size: self.quote_size,
            collateral_expiration_status: &mut status,
            quote_verification_result: &mut quote_verification_result,
            supplemental_data_size: self.supplemental_size,
            supplemental_data: self.suppl_buf_ptr,
        };

        self.dcap_quote.verify_quote(&mut verify_arg).unwrap();
        println!("DCAP verify quote successfully");

        Ok( quote_verification_result )
    }
}

impl Drop for DcapDemo {
    fn drop(&mut self) {
        self.dcap_quote.close();
    }
}

fn main() {
    let report_str = "Dcap demo sample";
    let mut dcap_demo = DcapDemo::new(report_str);

    println!("Generate quote with report data : {}", report_str);
    dcap_demo.dcap_quote_gen().unwrap();

    // compare the report data in quote buffer
    let report_data_ptr = dcap_demo.dcap_quote_get_report_data().unwrap();
    let string = str::from_utf8( unsafe { &(*report_data_ptr).d } ).unwrap();

    if report_str == &string[..report_str.len()] {
        println!("Report data from Quote: '{}' exactly matches.", string);
    } else {
        println!("Report data from Quote: '{}' doesn't match !!!", string);
    }

    let result = dcap_demo.dcap_quote_ver().unwrap();
    match result {
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK => {
            println!("Succeed to verify the quote!");
        },
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_NEEDED |
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE |
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED |
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_SW_HARDENING_NEEDED |
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED => {
            println!("WARN: App: Verification completed with Non-terminal result: {}", result);
        },
        _ => println!("Error: App: Verification completed with Terminal result: {}", result),
    }

}
