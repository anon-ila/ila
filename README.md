# Intermediate Language for Arithmetic Circuits (ILA)

## Build from Docker
1. `git clone https://github.com/UML-PLow/ila.git`
2. `cd docker`
3. `docker build -t ila-dev .`


## Dependencies

1. [SEAL-Python] (https://github.com/Huelse/SEAL-Python/tree/main)
2. [OpenFHE-Python (https://github.com/openfheorg/openfhe-python)
3. [TFHE-rs] (https://github.com/zama-ai/tfhe-rs)

## Run Docker

`docker run -it ila-dev:latest /bin/bash`

## Run ILA

1. `git clone https://github.com/UML-PLow/ila.git`
2. `cd ila`
3. Example: `python3 ila.py tfhe-rs tfhe tests/type_infer/cipher_add_mult_1.ila`

## ILA usage

```
Usage: ila <backend> <scheme_type> <filename>
	 where backend = {seal, openfhe, tfhe-rs}
	 where scheme_type = {bgv, bfv, tfhe}
```




## References

### Acknowledgements

The lexer and parser portions of the ILA interpreter are based on https://www.jayconrod.com/posts/37/a-simple-interpreter-from-scratch-in-python-part-1.
