ARG GO_VERSION=1.26

FROM golang:${GO_VERSION} AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/jackproof ./cmd/jackproof

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/jackproof /usr/local/bin/jackproof
USER nonroot:nonroot
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/jackproof"]
