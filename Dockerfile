# Build the verum binary, then ship it on a small runtime image.
FROM rust:1-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p verum

FROM debian:stable-slim
LABEL org.opencontainers.image.source="https://github.com/IBMark/verum"
LABEL org.opencontainers.image.description="Deterministic, whole-program, multi-language code analyzer"
LABEL org.opencontainers.image.licenses="MIT OR Apache-2.0"
COPY --from=build /src/target/release/verum /usr/local/bin/verum
WORKDIR /work
ENTRYPOINT ["verum"]
CMD ["--help"]
