# ===========================================================================
# wist-cred — Runtime Docker Image (Multi-arch)
#
# 采用「预编译二进制 + 最小运行时」的方式（与 wist-gateway 一致）：
# 二进制由 release 流水线按架构交叉编译，build context 下按 amd64/ arm64/
# 分目录提供，Dockerfile 只负责打包成运行镜像。
#
# 配置 / PKI / store 都是环境相关的，通过卷挂载，不烘焙进镜像。
# 启动时用 WIST_CRED_CONFIG 指向配置文件（缺省读工作目录下的 cred.toml）。
# ===========================================================================

FROM ubuntu:24.04

ARG TARGETARCH

LABEL org.opencontainers.image.source="https://github.com/dayu-sec/wist-cred"
LABEL org.opencontainers.image.description="Credential service for the wist platform (issue / revoke / deliver program tokens)"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# 运行时依赖：只用到根证书（TLS 走 rustls，不依赖系统 openssl）。
# uid 固定 999：wist-cred-stack 的 compose 以 999:999 运行，宿主侧由 `gops sys perms` 对齐。
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 999 -s /bin/false wist

# 预编译二进制（build context 按架构提供：amd64/wist-cred、arm64/wist-cred）
COPY ${TARGETARCH}/wist-cred /usr/local/bin/wist-cred

# 运行期目录：配置、PKI（只读）与 state（可写）由卷挂载到 /wist-cred
RUN mkdir -p /wist-cred/state && chown -R wist:wist /wist-cred

USER wist
WORKDIR /wist-cred

# API 端口（TLS 由入口 nginx 终止，本服务只说 plain HTTP）
EXPOSE 8443

ENTRYPOINT ["wist-cred"]
CMD []
