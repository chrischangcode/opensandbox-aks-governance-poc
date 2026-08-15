FROM mcr.microsoft.com/oss/go/microsoft/golang:1.26-bookworm@sha256:6617edd08296ac9f66719ae5ee239ca1018951b9a25af3efa6f084ba0186ca30 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOEXPERIMENT=nosystemcrypto go build -trimpath -ldflags='-s -w' \
    -o /out/aks-sandbox-dashboard ./cmd/aks-sandbox-dashboard

FROM mcr.microsoft.com/azurelinux/distroless/base:3.0@sha256:178f25fadf466549d31e234b3091bf815161159f2f2bc98720bbf39f7368aff4
COPY --from=build /out/aks-sandbox-dashboard /usr/local/bin/aks-sandbox-dashboard
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/aks-sandbox-dashboard"]
