FROM golang:1.9.7-alpine as builder
WORKDIR /go/src/app
RUN apk update && \
	apk add glide git
COPY . .
RUN glide up 
RUN go build

FROM alpine
WORKDIR /
COPY --from=builder /go/src/app/app .
RUN chmod +x /app
ENTRYPOINT ["./app"]
