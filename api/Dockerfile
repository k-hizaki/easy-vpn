# api/Dockerfile
FROM node:23.9.0-bookworm-slim

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get install -y certbot cron easy-rsa p7zip-full && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app
COPY package*.json ./
RUN npm i --omit=dev && npm install pm2 -g
RUN mkdir -p /secret

# Application main
COPY backend.js ./
COPY entrypoint.sh ./
RUN chmod +x entrypoint.sh
RUN chmod 600 /secret/

EXPOSE 80/tcp
EXPOSE 443/tcp

ENTRYPOINT ["./entrypoint.sh"]