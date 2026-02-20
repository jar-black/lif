import os
import uuid

import docker
from jose import JWTError, jwt
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send

JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = "HS256"

ANTHROPIC_API_KEY = os.environ["ANTHROPIC_API_KEY"]
GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
RUNNER_IMAGE = os.environ.get("RUNNER_IMAGE", "lif-claude-runner")
CLAUDE_SETTINGS_PATH = os.environ.get("CLAUDE_SETTINGS_PATH", "")

# --- MCP server ---

_security = TransportSecuritySettings(allowed_hosts=["localhost"])
mcp = FastMCP("mcp-claude-runner", stateless_http=True, transport_security=_security)


# --- JWT auth middleware ---


class JWTAuthMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            response = Response(status_code=401)
            await response(scope, receive, send)
            return

        token = auth_header[7:]
        try:
            jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except JWTError:
            response = Response(status_code=401)
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)


# --- Tools ---


@mcp.tool()
def run_task(repo_url: str, prompt: str, base_branch: str = "main") -> dict:
    """Run Claude Code in a Docker container to autonomously execute a coding task and produce a PR.

    Args:
        repo_url: GitHub repository URL (e.g. https://github.com/owner/repo)
        prompt: The task description / prompt for Claude Code
        base_branch: Branch to base the work on (default: main)
    """
    short_id = uuid.uuid4().hex[:8]
    branch_name = f"claude/{short_id}"

    # Build the shell script that runs inside the container
    script = f"""set -e
# Configure git auth
git config --global url."https://x-access-token:$GITHUB_TOKEN@github.com/".insteadOf "https://github.com/"
git clone --branch {base_branch} {repo_url} /work/repo
cd /work/repo
git checkout -b {branch_name}

# Configure git identity
git config user.name "Claude Code"
git config user.email "claude@anthropic.com"

# Copy Claude settings if available
if [ -d /claude-settings/.claude ]; then
    cp -r /claude-settings/.claude /root/.claude
fi

# Run Claude Code with the prompt + PR instruction
claude -p "{prompt}

When you are done with the task, commit all changes and create a pull request using:
  gh pr create --title 'Claude: {prompt[:60]}' --body 'Automated PR by Claude Code' --base {base_branch}
Print the PR URL as the last line of output." --dangerously-skip-permissions
"""

    client = docker.from_env()

    # Environment for the runner container
    env = {
        "ANTHROPIC_API_KEY": ANTHROPIC_API_KEY,
        "GITHUB_TOKEN": GITHUB_TOKEN,
        "GH_TOKEN": GITHUB_TOKEN,
    }

    # Volumes
    volumes = {}
    if CLAUDE_SETTINGS_PATH:
        volumes[CLAUDE_SETTINGS_PATH] = {"bind": "/claude-settings", "mode": "ro"}

    try:
        container = client.containers.run(
            RUNNER_IMAGE,
            command=["bash", "-c", script],
            environment=env,
            volumes=volumes,
            detach=False,
            remove=True,
            stdout=True,
            stderr=True,
            network_mode="host",
        )

        output = container.decode("utf-8", errors="replace")

        # Try to extract PR URL from output
        pr_url = None
        for line in reversed(output.strip().splitlines()):
            line = line.strip()
            if "github.com" in line and "/pull/" in line:
                # Extract URL from the line
                for word in line.split():
                    if "github.com" in word and "/pull/" in word:
                        pr_url = word
                        break
                if pr_url:
                    break

        if pr_url:
            return {"status": "success", "pr_url": pr_url, "branch": branch_name}
        else:
            return {
                "status": "completed",
                "branch": branch_name,
                "note": "Task completed but no PR URL detected in output",
                "output_tail": output[-2000:] if len(output) > 2000 else output,
            }

    except docker.errors.ContainerError as e:
        output = e.stderr.decode("utf-8", errors="replace") if e.stderr else str(e)
        return {
            "status": "error",
            "error": f"Container exited with code {e.exit_status}",
            "output_tail": output[-2000:] if len(output) > 2000 else output,
        }
    except docker.errors.ImageNotFound:
        return {
            "status": "error",
            "error": f"Runner image '{RUNNER_IMAGE}' not found. Build it with: docker build -f runner.Dockerfile -t {RUNNER_IMAGE} .",
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


# --- App setup ---

_inner = mcp.streamable_http_app()
app = JWTAuthMiddleware(_inner)
