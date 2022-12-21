# syntax=docker/dockerfile:1

## Build
FROM golang:1.19-buster AS build

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY *.go ./

RUN go build -o /gamo

## Deploy
FROM gcr.io/distroless/cc-debian11

WORKDIR /

COPY --from=build /gamo /gamo

EXPOSE 8080

USER nonroot:nonroot

ENTRYPOINT [ "/gamo", "--bind=0.0.0.0:8080" ]
