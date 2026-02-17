# =============================================================================
# Wazuh OpenClaw Autopilot - Production Dockerfile
# =============================================================================
# Multi-stage build for minimal production image
# Base: Node.js 18 Alpine
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Dependencies
# -----------------------------------------------------------------------------
FROM node:18-alpine AS deps

WORKDIR /app

# Install dependencies for native modules
RUN apk add --no-cache python3 make g++

# Copy package files
COPY package.json package-lock.json ./

# Install production dependencies only
RUN npm ci --only=production && npm cache clean --force

# -----------------------------------------------------------------------------
# Stage 2: Production
# -----------------------------------------------------------------------------
FROM node:18-alpine AS production

# Security: Run as non-root user
RUN addgroup -g 1001 -S autopilot && \
    adduser -S autopilot -u 1001 -G autopilot

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache \
    curl \
    tini \
    && rm -rf /var/cache/apk/*

# Copy dependencies from deps stage
COPY --from=deps /app/node_modules ./node_modules

# Copy application code
COPY --chown=autopilot:autopilot . .

# Create data directories
RUN mkdir -p /var/lib/wazuh-autopilot/cases \
             /var/lib/wazuh-autopilot/reports \
             /var/lib/wazuh-autopilot/state \
             /etc/wazuh-autopilot/policies && \
    chown -R autopilot:autopilot /var/lib/wazuh-autopilot /etc/wazuh-autopilot

# Configurable runtime port (change via --build-arg or env)
ARG RUNTIME_PORT=9090

# Environment defaults
ENV NODE_ENV=production \
    AUTOPILOT_MODE=production \
    AUTOPILOT_DATA_DIR=/var/lib/wazuh-autopilot \
    AUTOPILOT_CONFIG_DIR=/etc/wazuh-autopilot \
    METRICS_PORT=${RUNTIME_PORT} \
    # 0.0.0.0 required inside container for Docker port forwarding;
    # host access restricted to localhost via docker-compose ports mapping
    METRICS_HOST=0.0.0.0 \
    LOG_FORMAT=json \
    LOG_LEVEL=info

# Expose runtime port
EXPOSE ${RUNTIME_PORT}

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${METRICS_PORT}/health || exit 1

# Switch to non-root user
USER autopilot

# Use tini for proper signal handling
ENTRYPOINT ["/sbin/tini", "--"]

# Start the service
CMD ["node", "index.js"]

# Labels for container metadata
LABEL org.opencontainers.image.title="Wazuh OpenClaw Autopilot" \
      org.opencontainers.image.description="Autonomous SOC layer for Wazuh using OpenClaw agents" \
      org.opencontainers.image.vendor="GenSecAI" \
      org.opencontainers.image.source="https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot" \
      org.opencontainers.image.licenses="MIT"
