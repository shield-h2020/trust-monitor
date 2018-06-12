FROM nginx:1.12-alpine

LABEL maintainer="Marco De Benedictis <marco.debenedictis@polito.it>"

RUN apk --update --no-cache add tzdata \
    && rm -fr /var/cache/apk/*

ENV TZ=Europe/Rome

VOLUME ["/etc/ssl"]

COPY ./conf/ /etc/nginx/

RUN rm -fr /usr/share/nginx/html/*.html
COPY ./html/ /usr/share/nginx/html/

EXPOSE 80
EXPOSE 443
