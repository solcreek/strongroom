FROM rust:1.98.1-bookworm AS crypto
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
# The CLI must match the wasm-bindgen crate in Cargo.lock exactly.
RUN rustup target add wasm32-unknown-unknown && \
    cargo install wasm-bindgen-cli --locked --version "$(awk '/^name = "wasm-bindgen"$/ { getline; gsub(/[^0-9.]/, ""); print }' Cargo.lock)"
COPY crates/core crates/core
RUN cargo build --locked --release --target wasm32-unknown-unknown -p strongroom-core && \
    wasm-bindgen target/wasm32-unknown-unknown/release/strongroom_core.wasm --target web --out-dir crates/core/pkg

FROM node:24-bookworm-slim AS build
WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
COPY --from=crypto /build/crates/core/pkg crates/core/pkg
RUN node scripts/build-service.mjs

FROM node:24-bookworm-slim AS runtime
ENV NODE_ENV=production HOST=0.0.0.0 PORT=8080
WORKDIR /app
COPY --from=build --chown=node:node /build/dist/server.js /build/dist/strongroom_core_bg.wasm ./
COPY --chown=node:node deploy/runtime-package.json ./package.json
USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s CMD node -e "fetch('http://127.0.0.1:'+process.env.PORT+'/readyz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "server.js"]
