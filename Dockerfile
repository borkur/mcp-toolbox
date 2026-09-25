# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM golang:1 AS build

WORKDIR /go/src/mcp-toolbox
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG BUILD_TYPE="container.dev"
ARG COMMIT_SHA=""

RUN CGO_ENABLED=1 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -buildmode=pie \
    -ldflags "-s -w -X github.com/googleapis/mcp-toolbox/cmd.buildType=${BUILD_TYPE} -X github.com/googleapis/mcp-toolbox/cmd.commitSha=${COMMIT_SHA}" \
    -o /app/toolbox .

# Final Stage
FROM debian:stable-slim

RUN apt-get -qq update && apt-get -qq install -y --no-install-recommends \
    curl \
    procps \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash appuser
WORKDIR /app
COPY --from=build /app/toolbox /app/toolbox
RUN ln -s /app/toolbox /toolbox && chmod +x /app/toolbox && chown -R appuser:appuser /app
USER appuser

EXPOSE 8080

ENTRYPOINT ["/app/toolbox"]
