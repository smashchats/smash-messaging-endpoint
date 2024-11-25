FROM node:20-alpine

ARG PORT=3210
ARG HOST=host.docker.internal

WORKDIR /app

COPY package*.json .

RUN npm install

COPY . .

RUN npm run build

ENV HOST=$HOST
ENV PORT=$PORT

EXPOSE $PORT

CMD ["npm", "start"]
