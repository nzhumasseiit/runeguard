from runeguard.daemon import RuneGuardDaemon


def test_daemon_decide_request_allows_safe_action():
    daemon = RuneGuardDaemon()
    response = daemon.decide_request({"tool_name": "read_file", "path": "README.md"})

    assert response["type"] == "ALLOW"
    assert response["allow"] is True


def test_daemon_decide_request_blocks_unsafe_action():
    daemon = RuneGuardDaemon()
    response = daemon.decide_request({"tool_name": "read_file", "path": "repo/.env"})

    assert response["type"] == "BLOCK"
    assert response["allow"] is False


def test_daemon_decide_request_requires_tool_name():
    daemon = RuneGuardDaemon()
    response = daemon.decide_request({"path": "README.md"})

    assert response["type"] == "ERROR"
    assert response["allow"] is False
