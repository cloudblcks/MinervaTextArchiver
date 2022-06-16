# pull official base image
FROM node:18.2.0-alpine3.15

WORKDIR /app

#ENV PATH ./node_modules/.bin:$PATH

# install app dependencies
COPY package.json package-lock.json /app/
RUN npm install
# add app

COPY . /app

# start app
EXPOSE 3000

CMD ["npm", "start"]