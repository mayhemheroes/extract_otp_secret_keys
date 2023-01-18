# Build Stage
FROM fuzzers/atheris:2.0.7-python3.9

# Install dependencies
RUN apt-get update && \
        DEBIAN_FRONTEND=noninteractive apt-get install -y libsndfile1

ADD . /src
WORKDIR /src
RUN pip install -r requirements.txt

CMD ["/src/mayhem/fuzz_extract.py", "/src/mayhem/testsuite"]
