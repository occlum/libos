# SGX EPID Remote Attestation Demo

This project demonstrates how to do Intel SGX EPID (Enhanced Privacy ID) remote attestation on Occlum.

In a nutshell, Occlum provides SGX capabilities to user apps through ioctls on a special device (`/dev/sgx`).
To hide the low-level details of ioctls from user apps, a user-friendly, remote attestation library is provided in this demo.

**Prerequisites.** This demo needs to access Intel Attestation Service (IAS). To do this,
a developer needs to contact Intel to obtain a Service Provider ID (SPID) and the associated
Access Key from [here](https://api.portal.trustedservices.intel.com/EPID-attestation).
After obtaining the SPID and Access Key, fill them in the config file `conf/ra_config.json` as shown below:

```
{
      "ias_url": "https://api.trustedservices.intel.com/sgx/dev/attestation/v4",
      "ias_access_key": "<YourAccessKey>",
      "enclave_spid": "<YourSPID>"
}
```

**NOTE:** The URL, SPID and Access Key above vary depending whether it is for development or production

**Step 1.** Build this demo

Build the code in debug mode with "--debug", otherwise it's in Relese mode by default.
```
./download_and_build.sh [--debug]
```

**Step 2.** Run this demo on Occlum

Build the occlum image and run the RA test application. Log level is "off" by default.
```
./run_on_occlum.sh [off|trace]
```

