# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The configuration: one declaration per option, one ladder, one spelling.

What these tests hold are the promises an operator reads the README for:
that a key, its variable and its flag are the same statement, that the
layers are ordered the way the document says, that a spelling this
server used to have is refused by name rather than ignored, and that the
table in the README is the declaration and not a copy of it that drifted.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from mcuhome.workbench import api

from mcuhome.buildserver import options, server
from mcuhome.buildserver.backend import SessionBackend
from mcuhome.buildserver.config import FROM_STDIN, Config, load_config

README = Path(__file__).resolve().parents[2] / "README.md"

#: A token that is not the point of the test that passes it.
TOKEN = "x" * 32


@pytest.fixture
def host(tmp_path: Path) -> dict[str, str]:
    """An environment with a system and a user layer of its own.

    Every test here states one, so that none of them reads the
    configuration of the machine it happens to run on.
    """
    (tmp_path / "etc" / "mcuhome").mkdir(parents=True)
    (tmp_path / "home" / "mcuhome").mkdir(parents=True)
    return {
        "XDG_CONFIG_DIRS": str(tmp_path / "etc"),
        "XDG_CONFIG_HOME": str(tmp_path / "home"),
    }


def write(file: Path, text: str) -> Path:
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(text, encoding="utf-8")
    return file


# --------------------------------------------------------------------------
# The declaration
# --------------------------------------------------------------------------


@pytest.mark.parametrize("option", options.SERVER_OPTIONS, ids=lambda one: one.name)
def test_every_option_derives_its_own_spellings(option: api.Option) -> None:
    """The key is the flag is the variable — nothing is written down twice."""
    assert option.area == "server"
    assert option.flag == "--" + option.name.replace(".", "-").replace("_", "-")
    if option.environment:
        assert option.env_var == "MCUHOME_" + option.name.upper().replace(".", "_")
    else:
        assert option.env_var == ""
    assert option.help, f"{option.name} says nothing about what it controls"


def test_the_declared_registry_is_the_platform_s_plus_this_server_s() -> None:
    """The whole platform registry, because the files are shared.

    A system or user ``configuration.yaml`` is read by every MCUHome
    program on the host, so a key another one owns is not an error here.
    """
    assert options.DECLARED_OPTIONS == api.OPTIONS + options.SERVER_OPTIONS


def test_no_option_of_this_server_collides_with_a_workbench_option() -> None:
    declared = {option.name for option in api.OPTIONS}
    assert declared.isdisjoint({option.name for option in options.SERVER_OPTIONS})


# --------------------------------------------------------------------------
# The ladder
# --------------------------------------------------------------------------


def test_this_program_states_its_memory_budget_in_the_program_layer(host) -> None:
    """A build server bounds memory where a workstation does not."""
    config = load_config([], env=host)
    assert config.build.memory == options.DEFAULT_MEMORY
    setting = config.settings.setting("build.memory")
    assert (setting.origin, setting.source) == ("program", "mcuhome-buildserver")


def test_a_file_wins_over_the_program_layer(tmp_path: Path, host) -> None:
    """An operator's configuration is above what this program defaults to."""
    write(tmp_path / "home" / "mcuhome" / "configuration.yaml", "build:\n  memory: 12g\n")
    config = load_config([], env=host)
    assert config.build.memory == "12g"
    assert config.settings.origin("build.memory") == "user"


def test_the_layers_run_file_then_environment_then_flag(tmp_path: Path, host) -> None:
    """Three layers on one key, each one winning over the one below it."""
    write(tmp_path / "etc" / "mcuhome" / "configuration.yaml", "server:\n  max_sessions: 2\n")
    system = load_config([], env=host)
    assert (system.max_sessions, system.settings.origin("server.max_sessions")) == (2, "system")

    write(tmp_path / "home" / "mcuhome" / "configuration.yaml", "server:\n  max_sessions: 3\n")
    user = load_config([], env=host)
    assert (user.max_sessions, user.settings.origin("server.max_sessions")) == (3, "user")

    variable = load_config([], env={**host, "MCUHOME_SERVER_MAX_SESSIONS": "4"})
    assert variable.max_sessions == 4
    assert variable.settings.setting("server.max_sessions").source == "MCUHOME_SERVER_MAX_SESSIONS"

    flag = load_config(
        ["--server-max-sessions", "5"], env={**host, "MCUHOME_SERVER_MAX_SESSIONS": "4"}
    )
    assert flag.max_sessions == 5
    assert flag.settings.setting("server.max_sessions").source == "--server-max-sessions"


def test_the_server_s_own_file_stands_where_a_project_s_file_stands(tmp_path: Path, host) -> None:
    """Above the two shared files, below the environment and the flags."""
    write(tmp_path / "home" / "mcuhome" / "configuration.yaml", "server:\n  max_seats: 10\n")
    file = write(tmp_path / "server" / "mcuhome.yaml", "server:\n  max_seats: 20\n")
    config = load_config(["--server-config", str(file)], env=host)
    assert config.max_seats == 20
    assert config.settings.origin("server.max_seats") == "project"
    assert config.settings.setting("server.max_seats").source == str(file)
    beaten = load_config(
        ["--server-config", str(file)], env={**host, "MCUHOME_SERVER_MAX_SEATS": "30"}
    )
    assert beaten.max_seats == 30


def test_the_server_s_own_file_is_where_trust_anchors_are_looked_for(tmp_path: Path, host) -> None:
    file = write(tmp_path / "server" / "mcuhome.yaml", "server:\n  max_seats: 20\n")
    assert load_config(["--server-config", str(file)], env=host).project_root == file.parent


def test_a_configuration_file_that_is_not_there_is_refused(tmp_path: Path, host) -> None:
    """A person who names a file meant it."""
    with pytest.raises(api.ConfigError) as refusal:
        load_config(["--server-config", str(tmp_path / "gone" / "mcuhome.yaml")], env=host)
    assert "not there" in refusal.value.message


def test_the_configuration_file_carries_the_name_a_project_s_file_carries(
    tmp_path: Path, host
) -> None:
    file = write(tmp_path / "server" / "buildserver.yaml", "server:\n  max_seats: 20\n")
    with pytest.raises(api.ConfigError) as refusal:
        load_config(["--server-config", str(file)], env=host)
    assert api.PROJECT_CONFIG_FILE in refusal.value.message


def test_a_value_that_does_not_fit_its_declaration_is_refused(tmp_path: Path, host) -> None:
    write(tmp_path / "home" / "mcuhome" / "configuration.yaml", "server:\n  max_sessions: 0\n")
    with pytest.raises(api.ConfigError):
        load_config([], env=host)
    with pytest.raises(api.ConfigError):
        load_config(["--server-max-sessions", "0"], env=host)
    with pytest.raises(api.ConfigError):
        load_config([], env={**host, "MCUHOME_SERVER_MAX_SESSIONS": "many"})


def test_a_list_of_paths_in_a_variable_uses_the_platform_s_separator(tmp_path: Path, host) -> None:
    """A path may hold a comma; the separator a path cannot hold is the one."""
    import os

    value = os.pathsep.join([str(tmp_path / "a"), str(tmp_path / "b")])
    config = load_config([], env={**host, "MCUHOME_BUILD_SDK_SOURCES": value})
    assert config.build.sdk_sources == (tmp_path / "a", tmp_path / "b")


def test_a_list_flag_is_repeatable_and_each_use_appends(tmp_path: Path, host) -> None:
    config = load_config(
        [
            "--build-sdk-sources",
            str(tmp_path / "a"),
            "--build-sdk-sources",
            str(tmp_path / "b"),
        ],
        env=host,
    )
    assert config.build.sdk_sources == (tmp_path / "a", tmp_path / "b")


def test_the_three_package_kinds_keep_their_own_keys(tmp_path: Path, host) -> None:
    """A kind is never looked for under another kind's key."""
    config = load_config(["--build-sdk-sources", str(tmp_path / "a")], env=host)
    assert config.build.sdk_sources == (tmp_path / "a",)
    assert config.build.workspace_sources == ()
    assert config.build.tools_sources == ()


def test_a_boolean_has_both_spellings(host) -> None:
    assert load_config([], env=host).auto_pull is True
    assert load_config(["--no-server-auto-pull"], env=host).auto_pull is False
    assert load_config(["--server-auto-pull"], env=host).auto_pull is True


def test_the_pair_file_is_a_path_and_publishing_it_is_a_boolean(tmp_path: Path, host) -> None:
    """Where it goes and whether it goes are two statements."""
    stated = tmp_path / "pair" / "token"
    config = load_config(["--server-pair-file", str(stated)], env=host)
    assert config.pair_file == stated
    assert load_config(["--no-server-publish-pair-file"], env=host).pair_file is None


# --------------------------------------------------------------------------
# Spellings this server used to have
# --------------------------------------------------------------------------


@pytest.mark.parametrize("spelling", sorted(options.RETIRED_FLAGS))
def test_every_retired_flag_is_refused_by_name(spelling: str, host) -> None:
    with pytest.raises(api.ConfigError) as refusal:
        load_config([spelling, "whatever"], env=host)
    assert spelling in refusal.value.message
    assert refusal.value.hint


@pytest.mark.parametrize("variable", sorted(options.RETIRED_VARIABLES))
def test_every_retired_variable_is_refused_by_name(variable: str, host) -> None:
    with pytest.raises(api.ConfigError) as refusal:
        load_config([], env={**host, variable: "value"})
    assert variable in refusal.value.message
    assert refusal.value.hint


@pytest.mark.parametrize("variable", sorted(options.CLOSED_VARIABLES))
def test_every_variable_this_server_does_not_read_is_refused(variable: str, host) -> None:
    """Nothing an operator exports goes quiet.

    A ``MCUHOME_*`` name this server ignores is a policy that did not
    take effect, and nobody finds that out until a build does something
    nobody asked for.
    """
    with pytest.raises(api.ConfigError) as refusal:
        load_config([], env={**host, variable: "1"})
    assert variable in refusal.value.message
    assert refusal.value.hint


def test_every_closed_channel_has_a_refusal_behind_it() -> None:
    """An option whose variable nobody reads names the channels that work."""
    for option in options.SERVER_OPTIONS:
        if option.environment:
            continue
        derived = "MCUHOME_" + option.name.upper().replace(".", "_")
        assert derived in options.CLOSED_VARIABLES, f"{option.name}: {derived} goes quiet"
        assert option.flag in options.CLOSED_VARIABLES[derived]


def test_the_token_variable_is_refused_though_it_never_existed(host) -> None:
    """The one refusal that is not about a spelling this server retired."""
    with pytest.raises(api.ConfigError) as refusal:
        load_config([], env={**host, "MCUHOME_SERVER_TOKEN": TOKEN})
    assert "--server-token -" in refusal.value.hint
    assert "server.token_file" in refusal.value.hint


def test_a_retired_spelling_names_a_successor_that_exists() -> None:
    """A refusal that named a flag nobody has would teach the wrong thing."""
    spellings = {option.flag for option in options.DECLARED_OPTIONS if option.flag}
    spellings |= {option.name for option in options.DECLARED_OPTIONS}
    # The flags this command owns rather than derives, which a refusal
    # may just as well name.
    spellings |= {"--server-token", "--server-config", "--print-config"}
    for stated in (*options.RETIRED_FLAGS.values(), *options.RETIRED_VARIABLES.values()):
        assert any(spelling in stated for spelling in spellings), stated


def test_a_retired_flag_with_its_value_attached_is_the_same_spelling(host) -> None:
    with pytest.raises(api.ConfigError) as refusal:
        load_config(["--docker=podman"], env=host)
    assert "--docker" in refusal.value.message


# --------------------------------------------------------------------------
# The bearer token
# --------------------------------------------------------------------------


def test_the_token_comes_from_the_flag(host) -> None:
    config = load_config(["--server-token", TOKEN], env=host)
    assert (config.token, config.token_generated) == (TOKEN, False)


def test_the_token_comes_from_standard_input(host) -> None:
    """So it stands in no shell history and in no process list."""
    config = load_config(["--server-token", "-"], env=host, stdin=io.StringIO(TOKEN + "\n"))
    assert (config.token, config.token_generated) == (TOKEN, False)


def test_the_token_from_standard_input_is_refused_where_nothing_is_piped_in(host) -> None:
    class Terminal(io.StringIO):
        def isatty(self) -> bool:
            return True

    with pytest.raises(api.ConfigError) as refusal:
        load_config(["--server-token", "-"], env=host, stdin=Terminal(TOKEN))
    assert "standard input" in refusal.value.message


def test_an_empty_read_is_not_a_token(host) -> None:
    with pytest.raises(api.ConfigError):
        load_config(["--server-token", "-"], env=host, stdin=io.StringIO("\n"))


def test_the_token_comes_from_the_file_the_configuration_names(tmp_path: Path, host) -> None:
    file = write(tmp_path / "token", TOKEN + "\n")
    flagged = load_config(["--server-token-file", str(file)], env=host)
    assert (flagged.token, flagged.token_generated) == (TOKEN, False)
    from_variable = load_config([], env={**host, "MCUHOME_SERVER_TOKEN_FILE": str(file)})
    assert from_variable.token == TOKEN
    write(tmp_path / "home" / "mcuhome" / "configuration.yaml", f"server:\n  token_file: {file}\n")
    assert load_config([], env=host).token == TOKEN


def test_a_token_nobody_configured_is_generated_once(host) -> None:
    """A fresh container is usable in one step and never open."""
    config = load_config([], env=host)
    assert config.token_generated is True
    assert len(config.token) >= 32
    assert load_config([], env=host).token != config.token


def test_the_token_has_no_environment_variable_of_its_own() -> None:
    """A secret in a variable is in the environment of every child process."""
    assert all(option.name != "server.token" for option in options.SERVER_OPTIONS)
    assert (
        "MCUHOME_SERVER_TOKEN"
        in options.successor(options.RETIRED_VARIABLES["MCUHOME_BUILDSERVER_TOKEN"])
        or "no environment variable" in options.RETIRED_VARIABLES["MCUHOME_BUILDSERVER_TOKEN"]
    )


# --------------------------------------------------------------------------
# Project light: the registries and the allowlist
# --------------------------------------------------------------------------


def test_the_registry_map_is_read_the_way_a_project_reads_it(tmp_path: Path, host) -> None:
    file = write(
        tmp_path / "server" / "mcuhome.yaml",
        "registry:\n"
        "  packages.example.org:\n"
        "    untrusted: true\n"
        "    mirrors:\n"
        "      mcuhome-sdk:\n"
        f"        - {tmp_path / 'mirror'}\n",
    )
    config = load_config(["--server-config", str(file)], env=host)
    configured = {entry.base_domain: entry for entry in config.registries}
    assert configured["packages.example.org"].untrusted is True
    assert configured["packages.example.org"].mirrors["mcuhome-sdk"] == (str(tmp_path / "mirror"),)


def test_mcuhome_s_own_registry_keeps_the_anchor_the_workbench_ships(host) -> None:
    """A server that configures nothing trusts what a workstation trusts."""
    config = load_config([], env=host)
    official = next(
        entry for entry in config.registries if entry.base_domain == api.OFFICIAL_BASE_DOMAIN
    )
    assert official.anchor == api.BUNDLED_ANCHOR_DIR / f"{api.OFFICIAL_BASE_DOMAIN}.json"


def test_an_operator_who_states_an_anchor_keeps_it(tmp_path: Path, host) -> None:
    anchor = write(tmp_path / "anchor.json", "{}")
    file = write(
        tmp_path / "server" / "mcuhome.yaml",
        f"registry:\n  {api.OFFICIAL_BASE_DOMAIN}:\n    anchor: {anchor}\n",
    )
    config = load_config(["--server-config", str(file)], env=host)
    official = next(
        entry for entry in config.registries if entry.base_domain == api.OFFICIAL_BASE_DOMAIN
    )
    assert official.anchor == anchor


def test_the_configured_registries_are_what_opens_the_package_registry(
    monkeypatch, tmp_path: Path, host
) -> None:
    """Project light, at the one place it decides anything."""
    file = write(
        tmp_path / "server" / "mcuhome.yaml",
        "registry:\n"
        f"  {api.OFFICIAL_BASE_DOMAIN}:\n"
        "    mirrors:\n"
        "      mcuhome-sdk:\n"
        f"        - {tmp_path / 'mirror'}\n",
    )
    config = load_config(
        ["--server-config", str(file), "--server-context-root", str(tmp_path / "sessions")],
        env=host,
    )
    asked: dict[str, object] = {}

    def capture(base_domain, **kwargs):
        asked["base_domain"] = base_domain
        asked.update(kwargs)
        return lambda: None

    monkeypatch.setattr(api, "open_package_registry", capture)
    SessionBackend(config)._package_registry()
    assert asked["base_domain"] == api.OFFICIAL_BASE_DOMAIN
    assert asked["project_root"] == file.parent
    settings = {entry.base_domain: entry for entry in asked["settings"]}
    assert settings[api.OFFICIAL_BASE_DOMAIN].mirrors["mcuhome-sdk"] == (str(tmp_path / "mirror"),)
    assert settings[api.OFFICIAL_BASE_DOMAIN].anchor == (
        api.BUNDLED_ANCHOR_DIR / f"{api.OFFICIAL_BASE_DOMAIN}.json"
    )


def test_one_key_is_the_allowlist_and_the_search_list(tmp_path: Path, host) -> None:
    """The repositories a build may name are the repositories that are searched."""
    import time
    import types

    from mcuhome.buildserver import environments, errors, sessions

    file = write(
        tmp_path / "server" / "mcuhome.yaml",
        "server:\n  allowed_container_repositories:\n    - ghcr.io/example/environment\n",
    )
    config = load_config(["--server-config", str(file)], env=host)
    assert config.allowed_container_repositories == ("ghcr.io/example/environment",)
    environments.check_allowed(
        "ghcr.io/example/environment:tag",
        allowed=config.allowed_container_repositories,
        what="the image this build was pinned to",
    )
    with pytest.raises(errors.SessionError):
        environments.check_allowed(
            "ghcr.io/somebody/else:tag",
            allowed=config.allowed_container_repositories,
            what="the image this build was pinned to",
        )
    state = types.SimpleNamespace(
        config=config,
        started_at=time.monotonic(),
        sessions=types.SimpleNamespace(open_count=0, max_open=config.max_sessions),
    )
    announced = sessions.capabilities_payload(state, [])
    assert announced["environments"]["allowed"] == ["ghcr.io/example/environment"]


def test_an_allowlist_with_nothing_in_it_is_refused(tmp_path: Path, host) -> None:
    """A server that may run nothing would refuse every build, once per client."""
    write(
        tmp_path / "home" / "mcuhome" / "configuration.yaml",
        "server:\n  allowed_container_repositories: []\n",
    )
    with pytest.raises(api.ConfigError):
        load_config([], env=host)


# --------------------------------------------------------------------------
# What is in effect
# --------------------------------------------------------------------------


def test_printing_the_configuration_asks_for_no_token(host) -> None:
    """Otherwise `--print-config --server-token -` sits on standard input."""
    config = load_config(["--print-config", "--server-token", FROM_STDIN], env=host, stdin=None)
    assert (config.token, config.token_generated) == ("", False)


def test_print_config_answers_every_option_and_binds_nothing(capsys, host, monkeypatch) -> None:
    monkeypatch.setattr("os.environ", host)
    assert server.main(["--print-config"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["ok"] is True
    for option in options.SERVER_OPTIONS:
        entry = document["config"][option.name]
        assert set(entry) == {"value", "origin", "source"}
    assert document["config"]["build.memory"]["origin"] == "program"


def test_a_refusal_at_startup_is_exit_two(capsys, host, monkeypatch) -> None:
    monkeypatch.setattr("os.environ", host)
    assert server.main(["--docker", "podman"]) == 2
    assert "--docker" in capsys.readouterr().err


def test_a_configuration_built_in_code_answers_the_same_document() -> None:
    """A ``Config`` nobody resolved has no resolution to print."""
    assert Config().settings is None


# --------------------------------------------------------------------------
# The README is the declaration
# --------------------------------------------------------------------------


def test_the_readme_documents_every_option() -> None:
    """One table, generated from the same declaration a run resolves."""
    text = README.read_text(encoding="utf-8")
    for option in (
        *options.SERVER_OPTIONS,
        *(api.option(name, options.DECLARED_OPTIONS) for name in options.BUILD_KEYS),
    ):
        row = next(
            (line for line in text.splitlines() if line.startswith(f"| `{option.name}` |")),
            None,
        )
        assert row is not None, f"{option.name} is in no README table"
        assert f"`{option.flag}`" in row
        assert (f"`{option.env_var}`" in row) if option.env_var else ("| – |" in row)
        if option.default not in (None, ()):
            stated = (
                str(option.default).lower()
                if isinstance(option.default, bool)
                else ", ".join(f"`{item}`" for item in option.default)
                if isinstance(option.default, tuple)
                else str(option.default)
            )
            assert stated in row, f"{option.name}: the README states another default"


def test_the_readme_lists_every_refused_spelling() -> None:
    text = README.read_text(encoding="utf-8")
    for spelling in (
        *options.RETIRED_FLAGS,
        *options.RETIRED_VARIABLES,
        *options.CLOSED_VARIABLES,
    ):
        assert f"| `{spelling}` |" in text, f"{spelling} is in no README table"


def test_the_readme_names_no_spelling_this_server_retired() -> None:
    """Outside the table that retires them, they must not appear at all."""
    lines = [
        line
        for line in README.read_text(encoding="utf-8").splitlines()
        if not line.startswith("| `-") and not line.startswith("| `MCUHOME_BUILDSERVER_")
    ]
    text = "\n".join(lines)
    for spelling in options.RETIRED_FLAGS:
        assert f"`{spelling}`" not in text, f"the README still offers {spelling}"
    assert "MCUHOME_BUILDSERVER_" not in text.replace("`MCUHOME_BUILDSERVER_` family", "")
