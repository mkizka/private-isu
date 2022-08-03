FROM node:16.16-buster

RUN mkdir -p /home/webapp
WORKDIR /home/webapp
COPY package.json .
COPY package-lock.json .
RUN npm ci
COPY . .
CMD npm run start
