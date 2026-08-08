ARG CADDY_VERSION=2.11.4
ARG CORAZA_CADDY_VERSION=latest
ARG CRS_VERSION=4.28.0
ARG ALPINE_VERSION=3.24

# Use the latest builder image regardless of target Caddy version — xcaddy can
# build any Caddy version, and the builder gets us Go + xcaddy.
FROM caddy:builder-alpine AS builder

ARG CADDY_VERSION
ARG CORAZA_CADDY_VERSION

# Let Go fetch a newer toolchain on demand — coraza-caddy may require a Go
# version newer than the one shipped with the matching Caddy builder image.
ENV GOTOOLCHAIN=auto

# xcaddy compiles Caddy + the Coraza WAF module. The positional version arg
# pins Caddy; coraza-caddy "latest" omits the @version suffix so the newest
# tag wins.
# No transitive-dep overrides needed: Caddy 2.11.4 already requires
# go-jose/v3 v3.0.5 and v4 v4.1.4, both of which carry the CVE-2026-34986 fix.
RUN if [ "$CORAZA_CADDY_VERSION" = "latest" ]; then \
      xcaddy build "v${CADDY_VERSION}" \
        --with github.com/corazawaf/coraza-caddy/v2 ; \
    else \
      xcaddy build "v${CADDY_VERSION}" \
        --with "github.com/corazawaf/coraza-caddy/v2@${CORAZA_CADDY_VERSION}" ; \
    fi

FROM alpine:${ALPINE_VERSION}

ARG CRS_VERSION

RUN apk upgrade --no-cache \
    && apk add --no-cache su-exec ca-certificates curl busybox-extras tini \
    && addgroup -S -g 1000 caddy \
    && adduser -S -G caddy -H -s /sbin/nologin -u 1000 caddy \
    && mkdir -p /etc/caddy/conf.d /etc/caddy/tls /data /config \
    && chown -R caddy:caddy /etc/caddy /data /config

# OWASP CRS — bundled at build time so behavior is reproducible.
# The .example files are renamed in place; the result is a self-contained ruleset.
RUN mkdir -p /etc/caddy/crs \
    && curl -fsSL "https://github.com/coreruleset/coreruleset/archive/refs/tags/v${CRS_VERSION}.tar.gz" \
        | tar -xz --strip-components=1 -C /etc/caddy/crs \
    && cp /etc/caddy/crs/crs-setup.conf.example /etc/caddy/crs/crs-setup.conf \
    && cp /etc/caddy/crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example \
          /etc/caddy/crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf \
    && cp /etc/caddy/crs/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf.example \
          /etc/caddy/crs/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf \
    && chown -R caddy:caddy /etc/caddy/crs

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY --chmod=555 entrypoint.sh /entrypoint.sh

# Caddy reads these to locate its data and config dirs; matches the
# convention used by the upstream caddy:* images so volume layouts stay
# interchangeable.
ENV XDG_DATA_HOME=/data \
    XDG_CONFIG_HOME=/config

VOLUME ["/data", "/config"]

EXPOSE 80 443 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/cgi-bin/health 2>/dev/null || exit 1

ENTRYPOINT ["/sbin/tini", "--", "/entrypoint.sh"]

ARG CADDY_VERSION
ARG CORAZA_CADDY_VERSION
ARG ALPINE_VERSION
ARG BUILD_DATE
ARG VCS_REF

LABEL org.opencontainers.image.title="caddy-waf" \
    org.opencontainers.image.description="Hardened Caddy + Coraza + OWASP CRS for self-hosted edge with automatic HTTPS and WAF" \
    org.opencontainers.image.version="${CADDY_VERSION}" \
    org.opencontainers.image.created="${BUILD_DATE}" \
    org.opencontainers.image.revision="${VCS_REF}" \
    org.opencontainers.image.vendor="QuirkQ" \
    org.opencontainers.image.licenses="Apache-2.0" \
    org.opencontainers.image.base.name="alpine:${ALPINE_VERSION}"
