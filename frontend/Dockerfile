FROM nginx:alpine

WORKDIR /usr/share/nginx/html

# Copy HTML file
COPY websocket-test.html index.html

# Expose port
EXPOSE 5500

# Custom nginx config to run on port 5500
RUN echo 'server { \
    listen 5500; \
    location / { \
        root /usr/share/nginx/html; \
        index index.html; \
    } \
}' > /etc/nginx/conf.d/default.conf

CMD ["nginx", "-g", "daemon off;"]
