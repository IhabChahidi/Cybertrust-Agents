"""Static structural validation of docker-compose.yml and Dockerfile (spec
section 9: "Docker may not be available in the current sandbox. Still run
all possible static checks... otherwise inspect and test the Compose file
structurally.").

`docker compose config` is the preferred check and IS run when the Docker
CLI is available (test_docker_compose_config_validates_when_docker_available
below, auto-skipped otherwise -- confirmed unavailable in this sandbox:
`docker`/`docker-compose` are both absent from PATH here). Every other test
in this file parses the YAML/Dockerfile directly with PyYAML and asserts the
structural properties spec section 9 lists, so the properties that CAN be
checked without a Docker daemon still have real, executable test coverage
rather than being asserted only in prose.
"""

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
COMPOSE_PATH = REPO_ROOT / "docker-compose.yml"
DOCKERFILE_PATH = REPO_ROOT / "Dockerfile"

pytestmark = pytest.mark.unit


@pytest.fixture(scope="module")
def compose() -> dict:
    return yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def dockerfile_text() -> str:
    return DOCKERFILE_PATH.read_text(encoding="utf-8")


def test_docker_compose_config_validates_when_docker_available():
    if shutil.which("docker") is None:
        pytest.skip("docker CLI not available in this environment -- see other tests in this file for static checks")
    result = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_PATH), "config", "--quiet"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr


def test_three_expected_services_are_defined(compose):
    assert set(compose["services"].keys()) == {"chromadb", "llama-generator", "generator-api"}


def test_model_path_matches_env_default_and_is_never_downloaded(compose, dockerfile_text):
    llama = compose["services"]["llama-generator"]
    command = llama["command"]
    assert "--model" in command
    model_path = command[command.index("--model") + 1]
    # llama-generator's own --model arg and generator-api's GENERATOR_MODEL_PATH
    # env default must reference the identical GGUF file: whichever model the
    # server actually loads is the one the API's llamacpp_client points at (see
    # mcp_server/llamacpp_config.py). Both are ${VAR:-default} shell syntax --
    # this test parses that default rather than hardcoding a specific model name,
    # so a model swap only needs to be made consistently in this one file.
    assert model_path.startswith("${GENERATOR_MODEL_PATH:-") and model_path.endswith("}")
    command_default = model_path[len("${GENERATOR_MODEL_PATH:-"):-1]
    api_env = compose["services"]["generator-api"]["environment"]["GENERATOR_MODEL_PATH"]
    assert api_env.startswith("${GENERATOR_MODEL_PATH:-") and api_env.endswith("}")
    api_default = api_env[len("${GENERATOR_MODEL_PATH:-"):-1]
    assert command_default == api_default
    assert command_default.startswith("/models/") and command_default.endswith(".gguf")
    # No RUN/CMD/ENTRYPOINT anywhere in either file may fetch the model --
    # only a read-only bind mount supplies it (see next test).
    for forbidden in ("wget ", "curl ", "huggingface-cli", "hf_hub_download", "snapshot_download"):
        assert forbidden not in dockerfile_text
        assert forbidden not in yaml.safe_dump(compose)


def test_model_volume_is_read_only(compose):
    llama = compose["services"]["llama-generator"]
    mounts = llama["volumes"]
    assert any(m.endswith(":ro") and "/models" in m for m in mounts), mounts


def test_chroma_volume_is_persistent_and_named(compose):
    chromadb = compose["services"]["chromadb"]
    assert any("chroma-data" in m for m in chromadb["volumes"])
    assert "chroma-data" in compose["volumes"]


def test_service_dns_names_match_generator_env_defaults(compose):
    generator_api_env = compose["services"]["generator-api"]["environment"]
    assert generator_api_env["CHROMA_HOST"] == "chromadb"
    assert generator_api_env["GENERATOR_BASE_URL"] == "http://llama-generator:8080/v1"
    assert "llama-generator" in compose["services"]
    assert "chromadb" in compose["services"]


def test_every_service_has_a_healthcheck(compose):
    for name, service in compose["services"].items():
        assert "healthcheck" in service, f"{name} has no healthcheck"
        assert service["healthcheck"].get("test"), f"{name}'s healthcheck has no test command"


def test_generator_api_depends_on_health_conditions(compose):
    depends_on = compose["services"]["generator-api"]["depends_on"]
    assert depends_on["chromadb"]["condition"] == "service_healthy"
    assert depends_on["llama-generator"]["condition"] == "service_healthy"


def test_internal_network_has_no_external_egress(compose):
    assert compose["networks"]["internal"].get("internal") is True


def test_only_generator_api_publishes_a_port(compose):
    for name, service in compose["services"].items():
        has_ports = bool(service.get("ports"))
        if name == "generator-api":
            assert has_ports, "generator-api should publish its port"
        else:
            assert not has_ports, f"{name} should not publish any port"


def test_chromadb_and_llama_generator_are_not_on_the_public_network(compose):
    assert compose["services"]["chromadb"]["networks"] == ["internal"]
    assert compose["services"]["llama-generator"]["networks"] == ["internal"]
    assert set(compose["services"]["generator-api"]["networks"]) == {"internal", "public"}


def test_cpu_is_the_default_gpu_layers_zero(compose):
    llama_command = compose["services"]["llama-generator"]["command"]
    gpu_layers_index = llama_command.index("--n-gpu-layers") + 1
    assert llama_command[gpu_layers_index] == "${LLAMA_GPU_LAYERS:-0}"


def test_dockerfile_creates_and_uses_a_non_root_user(dockerfile_text):
    assert "useradd" in dockerfile_text
    assert "USER app" in dockerfile_text
    # USER must appear after the useradd line and before CMD, so the
    # container process actually runs as the unprivileged user.
    assert dockerfile_text.index("USER app") > dockerfile_text.index("useradd")
    assert dockerfile_text.index("USER app") < dockerfile_text.index("CMD")


def test_dockerfile_has_a_healthcheck(dockerfile_text):
    assert "HEALTHCHECK" in dockerfile_text


def test_dockerfile_never_downloads_a_model(dockerfile_text):
    for forbidden in ("wget ", "curl ", "huggingface-cli", ".gguf"):
        assert forbidden not in dockerfile_text
