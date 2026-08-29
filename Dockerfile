FROM rust:1.85 as builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY config ./config
RUN cargo build --release

FROM gcr.io/distroless/cc-debian12
COPY --from=builder /build/target/release/heimdallr /usr/local/bin/heimdallr
COPY config/heimdallr.toml /etc/heimdallr/heimdallr.toml
EXPOSE 53/udp 53/tcp 853/tcp 853/udp 443/tcp 5380/tcp
ENTRYPOINT ["/usr/local/bin/heimdallr"]
CMD ["--config", "/etc/heimdallr/heimdallr.toml"]
