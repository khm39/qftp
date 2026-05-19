# syntax=docker/dockerfile:1.7

# ---------- builder ----------
FROM rust:1-bookworm AS build
WORKDIR /src
# Cache the dependency build by copying just the manifests first.
COPY Cargo.toml Cargo.lock ./
COPY crates/qftp-common/Cargo.toml crates/qftp-common/Cargo.toml
COPY crates/qftp-server/Cargo.toml crates/qftp-server/Cargo.toml
COPY crates/qftp-client/Cargo.toml crates/qftp-client/Cargo.toml
RUN mkdir -p crates/qftp-common/src crates/qftp-server/src crates/qftp-client/src \
    && echo "fn main(){}" > crates/qftp-server/src/main.rs \
    && echo "fn main(){}" > crates/qftp-client/src/main.rs \
    && echo "" > crates/qftp-common/src/lib.rs \
    && cargo build --release --workspace --bins \
    && rm -rf crates/qftp-server/src crates/qftp-client/src crates/qftp-common/src target/release/.fingerprint/qftp-*

# Now the real source.
COPY . .
RUN cargo build --release --workspace --bins

# ---------- runtime ----------
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/qftp-server /usr/local/bin/qftp-server
COPY --from=build /src/target/release/qftp-client /usr/local/bin/qftp-client
EXPOSE 4433/udp 9090/tcp
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/qftp-server"]
CMD ["--bind", "0.0.0.0:4433", "--root", "/srv"]
