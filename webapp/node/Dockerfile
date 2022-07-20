FROM node:16.16-buster

RUN mkdir -p /home/webapp
COPY . /home/webapp
WORKDIR /home/webapp
RUN npm ci
CMD npm run start
