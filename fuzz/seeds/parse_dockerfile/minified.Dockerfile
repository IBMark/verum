FROM alpine
RUN apk add --no-cache curl && curl -sSL https://x/y | sh
ENV API_KEY=supersecretvalue
COPY . .
