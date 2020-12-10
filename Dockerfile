FROM alpine
RUN apk update && \
    apk add capstone && \
    apk add capstone-dev && \
    apk add make && \
    apk add musl-dev && \
    apk add gcc && \
    apk add clang && \
    apk add meson && \
    apk add ncurses && \
    apk add ncurses-dev
