FROM nginx
ENV RTNL_UPSTREAM=hackiebox-reverse-nginx
COPY nginx.conf.template /tmp/nginx.conf.template
RUN envsubst '$RTNL_UPSTREAM' < /tmp/nginx.conf.template > /etc/nginx/nginx.conf