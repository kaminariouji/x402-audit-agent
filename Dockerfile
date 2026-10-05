FROM node:22-slim
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY scripts ./scripts
# wallet/ is deliberately NOT copied. This image gets pushed to registries, and a baked-in layer stays
# readable via `docker history` even if a later step deletes the file. What src/agents/x402-mcp-server.mjs
# reads from there is wallet-address.json — a PUBLIC payout address, not a key — and it already prefers
# X402_PAY_TO, so set that env var (or mount the directory at run time) instead of building it in.
COPY src ./src
ENV NODE_ENV=production
# Set the port the platform routes to (Render/Fly inject $PORT); default 4022.
ENV X402_MCP_PORT=4022
EXPOSE 4022
CMD ["node", "src/agents/x402-mcp-server.mjs"]
