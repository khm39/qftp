# syntax=docker/dockerfile:1.7

# ---------- builder ----------
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
# BuildKit cache mounts keep the cargo registry and the target
# directory warm across builds. Cache-mount contents do not persist
# into the image, so the finished binaries are copied out to /out.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release \
        --bin qftp-server --bin qftp-client --bin qftp-web-bridge \
    && mkdir -p /out \
    && cp target/release/qftp-server \
          target/release/qftp-client \
          target/release/qftp-web-bridge /out/

# ---------- runtime ----------
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /out/qftp-server /usr/local/bin/qftp-server
COPY --from=build /out/qftp-client /usr/local/bin/qftp-client
COPY --from=build /out/qftp-web-bridge /usr/local/bin/qftp-web-bridge
# 4433/udp qftp or WebTransport, 8080/tcp the bridge SPA listener,
# 9090/tcp the qftp-server metrics endpoint.
EXPOSE 4433/udp 8080/tcp 9090/tcp
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/qftp-server"]
CMD ["--bind", "0.0.0.0:4433", "--root", "/srv"]
