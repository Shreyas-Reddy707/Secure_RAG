FROM node:20-alpine

WORKDIR /app

# 1. Install dependencies
COPY package.json ./
RUN npm install --legacy-peer-deps

# 2. Copy all frontend source and config files
COPY . .

# 3. Build production Next.js bundle
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

EXPOSE 3000

CMD ["npm", "run", "start"]

