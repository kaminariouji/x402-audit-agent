FROM node:22-slim
WORKDIR /app
ENV NODE_ENV=production
# Install deps as root into /app, then drop to the unprivileged built-in `node` user.
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund && npm cache clean --force
COPY --chown=node:node server.mjs audit-bot-honesty.cjs ./
USER node
ENV PORT=10000
EXPOSE 10000
CMD ["node", "server.mjs"]
