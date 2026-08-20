FROM rust:1.83-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN useradd -r app
USER app
HEALTHCHECK CMD ["/app", "--health"]
ENTRYPOINT ["/app"]
