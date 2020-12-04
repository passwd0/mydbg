FROM alpine
RUN apk update && \
    apk add capstone && \
    apk add capstone-dev && \
    apk add make && \
    apk add musl-dev && \
    apk add gcc