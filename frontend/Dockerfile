FROM node:20-alpine

WORKDIR /app

COPY frontend/package*.json ./
RUN npm install

COPY frontend/ ./

ENV HOST=0.0.0.0
CMD ["npm", "start"]
