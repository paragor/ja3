FROM golang:1.18

RUN apt update && apt install -y libpcap-dev

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download
COPY cli/ cli/
COPY pkg/ pkg/

RUN go build -o ja3exporter cli/ja3exporter.go && mv ja3exporter /usr/bin

CMD ["ja3exporter"]
