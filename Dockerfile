ARG ALPINE_VERSION=3.22
ARG PYTHON_VERSION=3.13

FROM python:${PYTHON_VERSION}-alpine${ALPINE_VERSION} AS builder
RUN apk update && apk upgrade && \
    apk add --no-cache git gcc
RUN pip install --no-cache-dir pyinstaller && \
    pip install --no-cache-dir git+https://github.com/AaronGrillot98/sarif-merge
WORKDIR /build
RUN pyinstaller --onefile --strip --name sarif-merge $(which sarif-merge)

FROM alpine:${ALPINE_VERSION}
RUN apk update && apk upgrade
COPY --from=builder /build/dist/sarif-merge /usr/local/bin/sarif-merge
RUN chmod +x /usr/local/bin/sarif-merge && \
    adduser -D -u 1000 merger
USER merger

ENTRYPOINT [ "/usr/local/bin/sarif-merge" ]
