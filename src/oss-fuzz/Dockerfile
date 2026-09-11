# Draft OSS-Fuzz integration. Not submitted.
FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y libpcre2-dev libjson-c-dev python3
COPY . $SRC/libsigma
WORKDIR $SRC/libsigma
COPY src/oss-fuzz/build.sh $SRC/
