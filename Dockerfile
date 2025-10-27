FROM node:22-slim

WORKDIR /usr/src/mockpass

COPY package* ./

RUN npm ci

COPY . ./

CMD ["node", "index.js"]
