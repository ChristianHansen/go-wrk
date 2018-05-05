FROM alpine:3.6

COPY go-wrk /gobin/go-wrk 

ENTRYPOINT ["/gobin/go-wrk"]
