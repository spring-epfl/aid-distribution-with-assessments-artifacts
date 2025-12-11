# Humanitarian Aid Distribution with Privacy-Preserving Assessment Capabilities

## HbC-2PC
Follow MP-SPDZ's installation manual: [](https://github.com/data61/MP-SPDZ)

Compile MP-SPDZ's semi protocol:
```bash
make -j 8 semi-party.x 
```

Export the configuration for the experiment, and change to the MP-SPDZ directory: 
```bash
export NUM_RECIPIENTS=10000
export SHOW_UP=9000
export THRESHOLD=2000
cd MP-SPDZ
```

### Simple f1

In order to benchmark runtimes for the distribution station and helper, use the following bash snippet:

```bash
./create_inputs_1.sh
./compile.py assessment_thresholded_stats
Scripts/compile-run.py -E semi assessment_thresholded_stats
```

- Recipient TODO
- Distribution
- Helper

### Full f2

In order to benchmark runtimes for the distribution station and helper, use the following bash snippet:

```bash
cd MP-SPDZ
./create_inputs_2.sh
./compile.py assessment_conditional_disclosure
Scripts/semi.sh -v assessment_conditional_disclosure
```

- Recipient TODO
- Distribution
- Helper
- Auditor TODO

## HbC-thHE

### Simple f1

- Recipient
- Distribution
- Helper

In order to benchmark runtimes for the distribution station and helper, run the following snippet on a laptop, and look for the outputs for `hbc_thhe_1_distribution` and `hbc_thhe_1_helper`.

```bash
cargo bench --bench hbc_thhe_1
```

To benchmark runtimes for the recipient, use [cargo-dinghy](https://crates.io/crates/cargo-dinghy) as follows. 

Setup: 
```bash
cargo install cargo-dinghy --force
```

Install [adb](https://developer.android.com/tools/adb) and make sure it is in your $PATH.
Connect your phone to your machine and make sure to enable USB debugging on your phone.  
Use `adb devices -l` to list connected devices. Check that cargo-dinghy sees the device using `cargo dinghy all-devices`.

You can run the recipient benchmark by calling

```bash
cargo dinghy -d android bench
```

on your machine, which will compile the code for Android, load it onto the phone, and run the benchmarks on the phone. Look for the output for `hbc_thhe_1_recipient`.

### Full f2

```bash
cargo bench --bench hbc_thhe_2
```

- Auditor: TODO: consistency

## Mal-thHE

### Simple f1

- Recipient: TODO: dummy 1FE encryptions, PKE encryptions towards auditor + threshold decryption
- Distribution: TODO: final decryption
- Helper: TODO: decrypt + check signature + 1FE eval + Sign
- Auditor: TODO: consistency check + Signature

### Full f2

- Recipient: TODO: threshold decryption
- Distribution: TODO: final decryption
- Helper: TODO: BGN eval + check sig predicate
- Auditor: TODO: consistency + Sign