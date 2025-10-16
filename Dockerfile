# Use official Node.js runtime as base image
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install ALL dependencies first (this will create package-lock.json)
RUN npm install

# Copy application source
COPY . .

# Create apps directory for generated APKs
RUN mkdir -p apps

# Install curl for health checks
RUN apk add --no-cache curl

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs
RUN adduser -S applify -u 1001

# Change ownership of the /app directory
RUN chown -R applify:nodejs /app

# Switch to non-root user
USER applify

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:5000/api/health || exit 1

# Start the application
CMD ["node", "server.js"]
