FROM ubuntu:22.04

# define the folder where our src should exist/ be deposited
ARG SRC=/SEAL-Python

# prevents update and install asking for tz
ENV DEBIAN_FRONTEND=noninteractive

# install dependencies
RUN apt update && \
    apt install -y git build-essential curl cmake python3 python3-dev python3-pip sudo emacs && \
    mkdir -p ${SRC}

# copy into container requirements and install them before rest of code
RUN pip3 install numpy pybind11

RUN pip3 install scikit-image

# clone repo
RUN git clone https://github.com/anon-ila/ila.git 

# copy everything into container now that requirements stage is complete
RUN cd / && git clone https://github.com/Huelse/SEAL-Python.git

# setting our default directory to the one specified above
WORKDIR ${SRC}

# update submodules
RUN cd ${SRC} && \
    git submodule update --init --recursive
    # git submodule update --remote

# build and install seal + bindings
RUN cd ${SRC}/SEAL && \
    cmake -S . -B build -DSEAL_USE_MSGSL=OFF -DSEAL_USE_ZLIB=OFF -DSEAL_USE_ZSTD=OFF && \
    cmake --build build && \
    cd ${SRC} && \
    python3 setup.py build_ext -i

CMD ["/usr/bin/python3"]


# OpenFHE setup #
#################


RUN pip3 install "pybind11[global]"

# Clone and build OpenFHE-development
RUN cd / && git clone https://github.com/openfheorg/openfhe-development.git \
    && cd openfhe-development \
    && mkdir build \
    && cd build \
    && cmake -DBUILD_UNITTESTS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_BENCHMARKS=OFF .. \
    && make -j$(nproc) \
    && make install

# Assume that OpenFHE installs libraries into /usr/local/lib
# Update LD_LIBRARY_PATH to include this directory
ENV LD_LIBRARY_PATH=/usr/local/lib:${LD_LIBRARY_PATH}


# Clone and build OpenFHE-Python
RUN cd / && git clone https://github.com/openfheorg/openfhe-python.git \
    && cd openfhe-python \
    && mkdir build \
    && cd build \
    && cmake .. \
    && make -j$(nproc) \
    && make install


# Rust Setup
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y



# Install openfhe as a pip package
RUN cd /ila

ENV PYTHONPATH=/SEAL-Python:/usr:$PYTHONPATH

#RUN git clone https://github.com/UML-PLow/ila.git