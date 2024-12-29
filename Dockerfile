FROM node:18.16.0-alpine as base

WORKDIR /app

COPY package*.json ./

RUN npm install

COPY src ./src

COPY tsconfig.json ./tsconfig.json

EXPOSE 3000

CMD ["npm", "run", "start"]