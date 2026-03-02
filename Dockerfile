FROM gcr.io/distroless/static-debian12

ARG TARGETPLATFORM
COPY gqls /usr/local/bin/gqls

ENTRYPOINT ["/usr/local/bin/gqls"]