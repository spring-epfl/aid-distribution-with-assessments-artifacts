# Artifact Appendix (Required for all badges)

Paper title: **Humanitarian Aid Distribution with Privacy-Preserving Assessment Capabilities**

Requested Badge(s):
  - [X] **Available**
  - [X] **Functional**
  - [X] **Reproduced**

## Description 

This repository contains artifacts for the paper "Humanitarian Aid Distribution with Privacy-Preserving Assessment Capabilities" by Christian Knabenhans, Lucy Qin, Justinas Sukaitis, Vincent Graf Narbel, and Carmela Troncoso, to appear at PETS 2026. 

These artifacts are implementation of protocols for assessments (e.g., statistics) for humanitarian aid distribution, which are presented in the paper.

### Security/Privacy Issues and Ethical Concerns 

When benchmarking code on a phone, the reviewer will need to plug in the phone to the machine running this code and enable USB debugging, which will allow our code to run on the phone. Our code only does benign experiments, and we do not believe that is causes any security or privacy issues. 

No ethical concerns.

## Basic Requirements 

### Hardware Requirements 

1. Minimal hardware requirement: All code can run on a laptop. Some code should be run on a phone to reproduce benchmarks.
2. Hardware specification for reproducibilty: 
   - Laptop: 2018 Thinkpad T480 with an 8-core Intel i5 CPU @ 1.6 GHz and 16 GB of RAM
   - Phone: 2016 Doogee X5 with a 4-core ARM Cortex-A7 CPU @ 1.3 GHz and 1 GB of RAM

### Software Requirements 

1. OS: tested on MacOS Tahoe 26.1, Fedora Linux 41
2. OS packages: automake build-essential clang cmake git libboost-dev libboost-filesystem-dev libboost-iostreams-dev libboost-thread-dev libgmp-dev libntl-dev libsodium-dev libssl-dev libtool python3 (all recent versions should work)
3. Artifact packaging: N/A
4. Programming language and compiler: Rust, cargo 1.80.0-nightly (7a6fad098 2024-05-31)
5. Packages: see Cargo.toml and Cargo.lock
6. Machine learning models: N/A
7. Datasets: N/A

### Estimated Time and Storage Consumption 

Time estimate: 1h human-time + 1h compute-time

## Environment 

### Accessibility 

The artifacts are available at [https://github.com/spring-epfl/aid-distribution-with-assessments-artifacts](). 

### Set up the environment 

```bash
git clone https://github.com/spring-epfl/aid-distribution-with-assessments-artifacts
cd aid-distribution-with-assessments-artifacts
git submodule init && git submodule update --recursive

# Install MP-SPDZ dependencies (see https://github.com/data61/MP-SPDZ)
sudo apt-get install automake build-essential clang cmake git libboost-dev libboost-filesystem-dev libboost-iostreams-dev libboost-thread-dev libgmp-dev libntl-dev libsodium-dev libssl-dev libtool python3
cd MP-SPDZ
make -j 8 semi-party.x 
cd -

# Install Rust
curl https://sh.rustup.rs -sSf | sh

# Compile code
cargo build --release

# Install cargo-dinghy
cargo install cargo-dinghy
```

### Testing the Environment 

Run 

```bash
cargo test
```

All tests should be passing. 

## Artifact Evaluation 

### Main Results and Claims

Our paper claims that for the setting specified in Section 6.2/lib.rs (total number of recipients, number of present recipients, maximum entitlement per recipient, etc.), our protocols are efficient enough to be practical and to not hinder humanitarian aid distribution processes. 
We show benchmarked runtimes in Table 2. 

We present six protocols, which are a combination of a base protocol (HbC-2PC, HbC-thHE, Mal-thHE) applied to an assessment function (f1, f2). 
Runtimes for P_i (recipients) are measured on a phone; runtimes for D (distribution station). H (helper), A (auditor) are measured on a laptop. 

Our claims are qualitative rather than quantitative: we claim that (i) the runtime of recipients P_i is short, i.e., sub-second, and (ii) the runtimes of distribution station D, helper H, and auditor A is acceptable, i.e., under a few minutes. We refer the interested reader to Section 6 and Appendix A of our paper for additional context (not required for the artifact evaluation). 

We do not expect the timings of Table 2 to be reproducible within a 5% margin due to discrepancies between the hardware we use for our benchmarks and the hardware used by artifact reviewers, but we expect that artifact reviewers can replicate our qualitative claims above. We describe our experiments below. 

### Experiments

#### Experiment 1: HbC-2PC-f1

Expected time: 10 minutes human-time + 10 minutes compute-time

##### Recipient P

Connect a phone to your machine and enable USB debugging (run `adb devices -l` to check if the phone is connected and available). Run

```bash
cargo dinghy -d android bench --bench hbc_2pc_1 -- hbc_2pc_1_recipient     
```   

and read off the timings for "hbc_2pc_1_recipient". 

##### Distribution station D, Helper H

Export the configuration for the experiment, and change to the MP-SPDZ directory:

```bash
export NUM_RECIPIENTS=10000
export SHOW_UP=9000
export THRESHOLD=2000
cd MP-SPDZ
```

In order to benchmark runtimes for the distribution station and helper, use the following bash snippet:

```bash
./create_inputs_1.sh
./compile.py assessment_thresholded_stats
Scripts/semi.sh assessment_thresholded_stats -v
```

This will output the computation time (same for D and H), as well as the total amount of communication. In addition to this communication, there is a base communication cost stemming from the distribution station D sending inputs to the helper, which is 1 MB of data (not shown in benchmark output). The additional communication of the 2PC protocol is negligible compared to this base cost. 


#### Experiment 2: HbC-2PC-f2

Expected time: 10 minutes human-time + 10 minutes compute-time

##### Auditor A

Run

```bash
cargo bench --bench hbc_2pc_2 
```   

and read off the timings for "hbc_2pc_2_auditor". 

##### Distribution station D, Helper H

Export the configuration for the experiment, and change to the MP-SPDZ directory:

```bash
export NUM_RECIPIENTS=10000
export SHOW_UP=9000
export THRESHOLD=2000
cd MP-SPDZ
```

In order to benchmark runtimes for the distribution station and helper, use the following bash snippet:

```bash
cd MP-SPDZ
./create_inputs_2.sh
./compile.py assessment_conditional_disclosure
Scripts//semi.sh assessment_conditional_disclosure -v
```

This will output the computation time (same for D and H), as well as the total amount of communication. In this setting, there is no base communication happening, and the communication sizes correspond directly to the entries in the table. 


#### Experiment 3: HbC-thHE-f1

Expected time: 10 minutes human-time + 10 minutes compute-time

##### Recipient P

Connect a phone to your machine and enable USB debugging (run `adb devices -l` to check if the phone is connected and available). Run

```bash
cargo dinghy -d android bench --bench hbc_thhe_1 -- hbc_thhe_1_recipient     
```   

and read off the timings for "hbc_thhe_1_recipient". 

##### Distribution station D, Helper H

Run

```bash
cargo bench --bench hbc_thhe_1 -- --nocapture 
```

and read off the timings for  "hbc_thhe_1_helper" and "hbc_thhe_1_distribution". 

#### Experiment 4: HbC-thHE-f2

Expected time: 10 minutes human-time + 10 minutes compute-time

##### Recipient P

Connect a phone to your machine and enable USB debugging (run `adb devices -l` to check if the phone is connected and available). Run

```bash
cargo dinghy -d android bench --bench hbc_thhe_2  
```   

and read off the timings for "hbc_thhe_2_recipient". 

##### Distribution station D, Helper H, Auditor A

Run

```bash
cargo bench --bench hbc_thhe_2 -- --nocapture 
```

and read off the timings for  "hbc_thhe_2_helper", "hbc_thhe_2_distribution" and "hbc_thhe_2_auditor". 


#### Experiment 5: Mal-thHE-f1

Expected time: 10 minutes human-time + 10 minutes compute-time

##### Recipient P

Connect a phone to your machine and enable USB debugging (run `adb devices -l` to check if the phone is connected and available). Run

```bash
cargo dinghy -d android bench --bench mal_thhe_1
```   

and read off the timings for "mal_thhe_1_recipient". 

##### Distribution station D, Helper H, Auditor A

Run

```bash
cargo bench --bench mal_thhe_1 -- --nocapture 
```

and read off the timings for  "mal_thhe_1_helper" and "mal_thhe_1_distribution". 

#### Experiment 6: Mal-thHE-f2

Expected time: 10 minutes human-time + 10 minutes compute-time

##### Recipient P

Connect a phone to your machine and enable USB debugging (run `adb devices -l` to check if the phone is connected and available). Run

```bash
cargo dinghy -d android bench --bench mal_thhe_2
```   

and read off the timings for "mal_thhe_1_recipient". 

##### Distribution station D, Helper H, Auditor A

Run

```bash
cargo bench --bench mal_thhe_2 -- --nocapture 
```

and read off the timings for  "mal_thhe_2_helper" and "mal_thhe_2_distribution". 

## Limitations

The sizes in Table 1 of the paper are concrete communication sizes and computed by hand, and thus not derivable from this artifact. 
Communication sizes between the distribution station D and the helper H for the HbC-thHE protocol in Table 2 *are* benchmarked using this artifact; all other communication sizes in Table 2 are derived from the terms in Table 1, and thus also not derivable from this artifact. 