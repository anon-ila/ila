# Intermediate Language for Arithmetic Circuits (ILA)


### Artifact Evaluation Summary for Reproducing Figures and Experiments

| **Component**                           | **Script(s)**                            | **Expected Output**                         | **Notes**                                                                                    |
| --------------------------------------- | ---------------------------------------- | ------------------------------------------- | -------------------------------------------------------------------------------------------- |
| **Fig. 13 (BFV)**                       | `fig_13.py`, `fig_13b.py`                | Multiplicative depth (ILA + Max)            | Generates `ILA_bfv` and `MAX` curves; minor variation expected due to platform differences.  |
| **Fig. 14 (BGV)**                       | `fig_14.py`                              | Multiplicative depth (ILA + OpenFHE + Max)  | Baseline comparison of OpenFHE vs. ILA vs. theoretical bounds.                               |
| **Fig. 15**                             | `fig_15.py`, `fig_15b.py`                | Plain-Cipher multiplicative depth           | Same as Fig. 14 but for Cipher-Plain multiplications                                                 |
| **Fig. 16 (Runtime)**                   | `fig_16a.py`, `tfhe-example/src/main.rs` | Overflow detection run-time for ILA vs. TFHE-rs             | Requires manual edits to Rust code to vary `FheUint<i>`; tested for `i ∈ {2, 4, ..., 2048}`. |
| **Image Filter**                        | `image_filter.py`                        | Decrypted filtered image region             | Validates encrypted image processing and linear filtering.                                   |
| **Private Set Intersection**            | `psi_pass.py`, `psi_fail.py`             | 0 on match, random non-zero on mismatch     | Tests correctness and masking of encrypted equality.                                         |
| **Private Information Retrieval (PIR)** | `pir_1000.py`, `pir_8000.py`             | Sparse decrypted result matching query mask | Requires manual flag changes in `ila_seal.py`. `pir_8000.py` requires >200GB disk.           |



## System Requirements

* [Docker](https://docs.docker.com/desktop/)
* 16 GB RAM minimum
* 20 GB free disk space (≥ 200 GB recommended for full experiments)


## Build Docker Image

1. Start Docker.
2. In **Docker > Settings > Resources > Advanced**, allocate max available CPU/RAM to match system requirements.
3. Build the image from the `docker/` directory:

   ```
   cd docker
   docker build -t ila-dev .
   ```


## Run Container

```
docker run -it ila-dev:latest /bin/bash
```

## Artifact Evaluation

* Artifact tests are located in `/ila/artifact_tests/`.
* To run a test:

  ```
  cd /ila
  python3 ./artifact_tests/<test_name>.py
  ```
* Example:

  ```
  python3 ./artifact_tests/fig_13.py
  ```

# Reproducibility: Main Results (Figures 13–16)

This section details how to reproduce the main results presented in **Figures 13–16** of the paper. All necessary scripts and benchmarks are provided in the `artifact_tests/` directory and related submodules.

> **Expected Behavior:**
> The system is probabilistic and hardware dependent, results can change with every run and with every machine.
> In any case, the type checker's estimate should always be less than or equal to the theoretical max.
> Any gap should be less than 2.

## Figure 14 – BGV Scheme: ILA vs Theoretical Max Depth

This is the simplest result to reproduce.

### Steps:

```
cd /ila
python3 ./artifact_tests/fig_14.py
```

### Output:

* **Columns include:**

  * Coefficient modulus bit-length
  * Multiplicative depth computed by:
    * OpenFHE
    * ILA's type checker
    * BGV Theoretical maximum `MAX_(bgv)`

* These values correspond to the `ILA_(bgv)` curve in **Fig. 14**.

---

## Figure 13: ILA_(bfv), ILA_(bgv) vs Max Depth

`fig_13.py` and `fig_13b.py` generates data for `ILA_(bfv)` and `MAX_(bfv)` curves.

### Steps:

```
cd /ila
python3 ./artifact_tests/fig_13.py
python3 ./artifact_tests/fig_13b.py
```

### Notes:

* Output includes ILA-estimated and maximum achievable multiplicative depths for **BFV**.
* The **`ILA_(bfv)`** curve is based on ILA's type checker values.
* The **`MAX`** curve is maximum of `MAX_(bgv)` generated from `fig_14.py` and `MAX_(bfv)` generated using `fig_13.py` and `fig_13b.py` 


## Figure 15 – Cipher - Plain: ILA vs Max Depth

### Steps:

```
cd /ila
python3 ./artifact_tests/fig_15.py
python3 ./artifact_tests/fig_15b.py
```

These scripts generate the full data set for Fig. 15.



## Figure 16 – Value Overflow Runtime Comparison (ILA vs. TFHE-rs)

This figure involves run time comparisons between ILA type checking and [TFHE-rs](https://github.com/zama-ai/tfhe-rs) run-time.


### Step 1: ILA Runtime

```
cd /ila
python3 ./artifact_tests/fig_16a.py
```


### Step 2: TFHE-rs Runtime (Rust)

```
cd tfhe-rs-tests/tfhe-example/src
cargo run
```

* Outputs runtime for a 2-bit overflow-detecting computation using `FheUint2`.


### Step 3: Scaling to Wider Bit-Widths

To benchmark other widths `{4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048}`:

1. Edit `main.rs`, lines 20–21:

   ```rust
   let ct_1 = FheUint<i>::encrypt(msg1, &client_key);
   let ct_2 = FheUint<i>::encrypt(msg2, &client_key);
   ```

   **Example – 32 bits:**

   ```rust
   let ct_1 = FheUint32::encrypt(msg1, &client_key);
   let ct_2 = FheUint32::encrypt(msg2, &client_key);
   ```

   **Example – 512 bits:**

   ```rust
   let ct_1 = FheUint512::encrypt(msg1, &client_key);
   let ct_2 = FheUint512::encrypt(msg2, &client_key);
   ```

2. Save and exit the editor.

3. Run the benchmark:

   ```
   cargo run
   ```

> The program will **panic on overflow**, printing the elapsed time — this is the runtime measurement used for TFHE-rs.
> The program run-time increases as i increases. For FheUint2048 run-time might be more than 10 hours.


## Additional Experiments

This section describes three additional experiments that demonstrate the expressiveness and correctness of the ILA type system for secure computation. Each experiment is implemented under `artifact_tests/`.


### Encrypted Image Filtering

**File:** `artifact_tests/image_filter.py`
**Description:**
Applies a basic filter to a region of an encrypted image (`image.png`). The image is partially encrypted, filtered in the encrypted domain, and then decrypted to an array. This experiment can take up to an hour to produce output.

#### Run:

```
cd /ila
python3 artifact_tests/image_filter.py
```

**Expected Behavior:**

* Demonstrates homomorphic evaluation of linear filters over ciphertexts.
* Final output should match the filtered result applied in plaintext.


### Private Set Intersection (PSI)

**Files:**

* `artifact_tests/psi_pass.py`
* `artifact_tests/psi_fail.py`

**Description:**
Simulates a private set intersection protocol for two encrypted sets.

* If corresponding encrypted values are equal, the result is `0`.
* If not equal, the result is a non-zero randomized value (to avoid leakage).

#### Run:

```
python3 artifact_tests/psi_pass.py  # Returns 0 (match)
python3 artifact_tests/psi_fail.py  # Returns non-zero (mismatch)
```

**Expected Behavior:**

* Correctness of equality check over encrypted data.
* Non-leakage via randomized masking on inequality.


### Private Information Retrieval (PIR)

**Files:**

* `artifact_tests/pir_1000.py`
* `artifact_tests/pir_8000.py`

**Description:**
Implements PIR using encrypted queries over a list-modeled database.

* The client encrypts a binary selection vector (query) of the same length as the database.
* The server performs homomorphic multiplication between the encrypted query and plaintext database values.
* The client decrypts the result to retrieve the selected entries.

> This experiment is **HDD-intensive**. Expect >200 GB usage for the full 8000-element test.
> This experiment might take an hour or two.

### Setup Instructions

1. Open `ila_seal.py` in a text editor:

   ```
   emacs ila_seal.py
   ```
2. Modify runtime flags:

   * **Line 118:** Set `psi=False`
   * **Line 308:** Set `psi=False`

> These flags disable PSI-specific optimizations and enable PIR logic.


### Run:

```
python3 artifact_tests/pir_1000.py    # ~1000 elements
python3 artifact_tests/pir_8000.py    # ~8000 elements, high disk usage
```

**Expected Behavior:**

* The decrypted output vector should be all 0s, except for positions selected in the query, which contain the corresponding database values.


## ILA usage

```
Usage: ila <backend> <scheme_type> <filename> <mul depth>
	 where backend = {1=seal, 2=openfhe, 3=tfhe-rs}
	 where scheme_type = {1=bgv, 2=bfv, 3=tfhe}
```

## Dependencies

1. [SEAL-Python] (https://github.com/Huelse/SEAL-Python/tree/main)
2. [OpenFHE-Python (https://github.com/openfheorg/openfhe-python)
3. [TFHE-rs] (https://github.com/zama-ai/tfhe-rs)


## References

### Acknowledgements

The lexer and parser portions of the ILA interpreter are based on https://www.jayconrod.com/posts/37/a-simple-interpreter-from-scratch-in-python-part-1.
