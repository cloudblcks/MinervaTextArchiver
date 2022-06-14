# set the base image
# n/b: for production, node is only used for building the static Html and javascript files
# as react creates static html and js files after build these are what will be served by nginx
# use alias build to be easier to refer this container elsewhere
## e.g inside nginx container
#FROM node:alpine as build
#
#WORKDIR /app
#
#COPY . /app
#
#ENV PATH /app/node_modules/.bin:$PATH
#
#RUN yarn
#
#RUN yarn build


FROM nginx:alpine

#COPY --from=build /app/build /usr/share/nginx/html

RUN rm /etc/nginx/conf.d/default.conf
COPY ./minerva.conf /etc/nginx/conf.d

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]