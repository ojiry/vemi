# Supply a verified Node base digest and an exact Claude Code version at build time.
ARG NODE_BASE
FROM ${NODE_BASE}
ARG CLAUDE_VERSION
RUN test -n "$CLAUDE_VERSION" && npm install --global "@anthropic-ai/claude-code@$CLAUDE_VERSION"
COPY bridge.cjs /opt/vemi/bridge.cjs
USER 1000:1000
WORKDIR /review
ENTRYPOINT ["node", "/opt/vemi/bridge.cjs"]
