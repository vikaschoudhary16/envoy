FROM node:23.3-bullseye-slim@sha256:26127e770e05b5f702b52402c3a3e875aeb66aa59d7dda29ebc50f8ce6c92576 as node-base


FROM node-base as node-http-auth
ARG NODE_APP=.
ARG NODE_APP_NAME=http-service/server
# Add an env to save ARG
ENV NODE_APP_PATH "/app/${NODE_APP_NAME}"
COPY "$NODE_APP" /app
# Dont use exec form to interpolate correctly
CMD node $NODE_APP_PATH
