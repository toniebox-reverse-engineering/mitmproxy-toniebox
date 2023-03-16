FROM nginx
#TODO RTNL_UPSTREAM
ENV RTNL_UPSTREAM=hackiebox-reverse 
COPY nginx.conf.template /tmp/nginx.conf.template
RUN envsubst '$RTNL_UPSTREAM' < /tmp/nginx.conf.template > /etc/nginx/nginx.conf