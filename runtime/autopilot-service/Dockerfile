# =============================================================================
# Wazuh OpenClaw Autopilot - Production Dockerfile
# =============================================================================
# Multi-stage build for minimal production image
# Base: Node.js 22 Alpine (LTS until April 2027)
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Dependencies
# -----------------------------------------------------------------------------
FROM node:22-alpine AS deps

WORKDIR /app

# Install dependencies for native modules
RUN apk add --no-cache python3 make g++

# Copy package files
COPY package.json package-lock.json ./

# Install production dependencies only
RUN npm ci --omit=dev && npm cache clean --force

# -----------------------------------------------------------------------------
# Stage 2: Production
# -----------------------------------------------------------------------------
FROM node:22-alpine AS production

# Security: Run as non-root user
RUN addgroup -g 1001 -S autopilot && \
    adduser -S autopilot -u 1001 -G autopilot

WORKDIR /app

# Install runtime dependencies (curl removed - healthcheck uses node)
RUN apk add --no-cache \
    tini \
    && rm -rf /var/cache/apk/*

# Copy dependencies from deps stage
COPY --from=deps --chown=autopilot:autopilot /app/node_modules ./node_modules

# Copy application code
COPY --chown=autopilot:autopilot . .

# Create data directories
RUN mkdir -p /var/lib/wazuh-autopilot/cases \
             /var/lib/wazuh-autopilot/reports \
             /var/lib/wazuh-autopilot/state \
             /etc/wazuh-autopilot/policies && \
    chown -R autopilot:autopilot /var/lib/wazuh-autopilot /etc/wazuh-autopilot

# Environment defaults
ENV NODE_ENV=production \
    AUTOPILOT_MODE=production \
    AUTOPILOT_DATA_DIR=/var/lib/wazuh-autopilot \
    AUTOPILOT_CONFIG_DIR=/etc/wazuh-autopilot \
    RUNTIME_PORT=9090 \
    # 0.0.0.0 required inside container for Docker port forwarding;
    # host access restricted to localhost via docker-compose ports mapping
    METRICS_HOST=0.0.0.0 \
    LOG_FORMAT=json \
    LOG_LEVEL=info

# Expose runtime port
EXPOSE 9090

# Health check using node (works on read-only filesystem, respects runtime RUNTIME_PORT)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD node -e "const h=require('http');h.get('http://localhost:'+(process.env.RUNTIME_PORT||9090)+'/health',r=>{process.exit(r.statusCode===200?0:1)}).on('error',()=>process.exit(1))"

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
