FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends clang llvm git ca-certificates \
    && ln -sf "$(ls /usr/lib/llvm-*/bin/llvm-symbolizer /usr/bin/llvm-symbolizer-* 2>/dev/null | head -1)" /usr/bin/llvm-symbolizer \
    && rm -rf /var/lib/apt/lists/*
# ASan symbolizes the crash at runtime so frames name the faulting function.
ENV ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer
ENV ASAN_OPTIONS=symbolize=1:abort_on_error=1
WORKDIR /src
# Pin the EXACT commit for v1.7.17 and VERIFY it: a git tag is mutable, so a moved
# tag or a compromised upstream could otherwise change the code under the same image
# tag / sign-off. The build fails closed if the resolved commit does not match.
ARG CJSON_COMMIT=87d8f0961a01bf09bef98ff89bae9fdec42181ee
RUN git clone --depth 1 --branch v1.7.17 https://github.com/DaveGamble/cJSON.git \
    && test "$(git -C cJSON rev-parse HEAD)" = "$CJSON_COMMIT"
COPY harness.c /src/harness.c
COPY runner.c /src/runner.c
COPY trigger /seeds/trigger
RUN clang -g -O1 -fsanitize=address,fuzzer -I/src/cJSON /src/harness.c /src/cJSON/cJSON.c -o /harness
# The trusted authenticity wrapper (no sanitizer): it forks the harness and turns
# the OS-observed wait status into a code the target cannot forge.
RUN clang -O2 /src/runner.c -o /runner
ENTRYPOINT ["/runner", "/harness"]
