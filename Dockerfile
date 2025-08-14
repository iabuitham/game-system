# Use official Node LTS image
FROM node:20-alpine AS build

WORKDIR /usr/src/app
# Install dependencies
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

# copy source
COPY . .
# expose port
EXPOSE 3001
CMD ["node", "server.js"]
