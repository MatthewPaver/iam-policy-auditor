# PolicyLens: small image, no npm install (Node standard library only).
# HOSTED=1 turns on shared-demo mode (POST throttle and privacy banner).
FROM node:22-alpine
WORKDIR /app
COPY . .
ENV HOST=0.0.0.0
ENV HOSTED=1
ENV PORT=4177
EXPOSE 4177
CMD ["node", "server.js"]
