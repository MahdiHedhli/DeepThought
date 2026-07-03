FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends clang llvm git ca-certificates \
    && ln -sf "$(ls /usr/lib/llvm-*/bin/llvm-symbolizer /usr/bin/llvm-symbolizer-* 2>/dev/null | head -1)" /usr/bin/llvm-symbolizer \
    && rm -rf /var/lib/apt/lists/*
# ASan symbolizes the crash at runtime so frames name the faulting function.
ENV ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer
ENV ASAN_OPTIONS=symbolize=1:abort_on_error=1
WORKDIR /src
RUN git clone --depth 1 --branch v1.7.17 https://github.com/DaveGamble/cJSON.git
COPY harness.c /src/harness.c
COPY trigger /seeds/trigger
RUN clang -g -O1 -fsanitize=address,fuzzer -I/src/cJSON /src/harness.c /src/cJSON/cJSON.c -o /harness
ENTRYPOINT ["/harness"]
