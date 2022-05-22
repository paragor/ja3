

.PHONY: build
build:
	docker stop ja3_tmp || true
	docker rm ja3_tmp || true
	docker build -t ja3_tmp .
	docker run --name ja3_tmp ja3_tmp echo make tmp
	docker cp ja3_tmp:/usr/bin/ja3exporter ja3exporter
