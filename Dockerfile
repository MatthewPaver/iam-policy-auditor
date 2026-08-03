# PolicyLens — tiny local image (no npm install; Node stdlib only)
FROM node:20-alpine
WORKDIR /app
COPY . .
ENV HOST=0.0.0.0
ENV HOSTED=1
ENV PORT=4177
EXPOSE 4177
CMD ["node", "server.js"]
