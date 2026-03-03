FROM node:20-bookworm-slim

WORKDIR /app

ENV NODE_ENV=production

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    dnsutils \
    iputils-ping \
    iproute2 \
    python3 \
    snmp \
    traceroute \
  && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm install --omit=dev

COPY . .

EXPOSE 4000 5514/tcp 5514/udp 2055/udp

CMD ["npm", "start"]

