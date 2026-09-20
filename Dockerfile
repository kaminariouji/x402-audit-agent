FROM node:22-slim
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY scripts ./scripts
COPY wallet ./wallet
COPY src ./src
ENV NODE_ENV=production
# Set the port the platform routes to (Render/Fly inject $PORT); default 4022.
ENV X402_MCP_PORT=4022
EXPOSE 4022
CMD ["node", "src/agents/x402-mcp-server.mjs"]
