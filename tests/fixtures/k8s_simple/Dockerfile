FROM node:latest
WORKDIR /app
COPY . .
RUN npm install
ENV API_KEY=sk-1234567890abcdef
USER root
CMD ["node", "server.js"]
