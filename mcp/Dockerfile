# The MCP server alone, for MCP directories that build and inspect servers in a
# container (Glama). The `nokk` wheel it depends on carries the engine binary,
# so the image needs nothing else. The CDP server image is the root Dockerfile.
FROM python:3.12-slim
RUN pip install --no-cache-dir --root-user-action=ignore --pre nokk-mcp
ENTRYPOINT ["nokk-mcp"]
