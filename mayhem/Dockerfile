# Build Stage
FROM python:3.11-slim

# Install system dependencies for opencv, pyzbar, and zbar
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        libzbar0 \
        libgl1 \
        libglib2.0-0 \
        libsndfile1 && \
    rm -rf /var/lib/apt/lists/*

# Install atheris fuzzing library
RUN pip install --no-cache-dir atheris

ADD . /src
WORKDIR /src
RUN pip install --no-cache-dir -r requirements.txt

CMD ["/src/mayhem/fuzz_extract.py", "/src/mayhem/testsuite"]
