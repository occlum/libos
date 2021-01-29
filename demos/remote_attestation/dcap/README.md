# SGX DCAP Remote Attestation Demo

This project demonstrates how to do Intel SGX DCAP (Datacenter Attestation
Primitives) remote attestation on Occlum. Occlum provides SGX capabilities to
applications through ioctls on device `/dev/sgx`.

## Prerequisites

- Platform: Intel SGX enabled platform with DCAP installed. Follow [DCAP
  Quick Install
  Guide](https://software.intel.com/content/www/us/en/develop/articles/intel-software-guard-extensions-data-center-attestation-primitives-quick-install-guide.html)
  for the detailed installation procedure.

- Occlum: Compile Occlum on a DCAP-installed platform by invoking `make`. The
  compilation will look for the needed DCAP libraries. The needed libraries
  include `libsgx_quote_ex, libsgx_quote_ex_sim, libsgx_dcap_tvl,
  libsgx_dcap_ql and libsgx_dcap_quoteverify`.

## Run this demo on Occlum

You can run the DCAP quote generation and verification demo on Occlum via
```
./run_dcap_demo_on_Occlum.sh
```

## Preinstalled DCAP package in Ubuntu 18.04 and CentOS 8.1
The DCAP package has been preinstalled in the Occlum official docker images
including Ubuntu 18.04 and CentOS 8.1 since Occlum 0.19.0. The versions of DCAP
package and PCCS should keep the same to avoid incompatibility. The installed
DCAP version is 1.8, so PCCS should also be version 1.8 to work with the
preinstalled DCAP package. Remember to configure `/etc/sgx_default_qcnl.conf`
in the container according to your PCCS setting after running the docker image.

As DCAP 1.8 is not the latest, the demo application running in the container of
the official image will output a warning: `WARN: App: Verification completed
with Non-terminal result: a002`. The `a002` of type `sgx_ql_qv_result_t` in the
warning indicates the quote is good but TCB level of the platform is out of
date.
