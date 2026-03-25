import pytest
import os
import sys
from unittest.mock import patch, MagicMock
from queue import Queue

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import vt_bulk
import requests as _requests


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def reset_globals():
    """Reset module-level global state before each test."""
    vt_bulk.VERBOSE = True
    vt_bulk.NO_JSON_DUMP = True
    vt_bulk.CHECK_QUOTA = False
    vt_bulk.finished_requesting_scans = False
    vt_bulk.analysis_results_queue = Queue()
    vt_bulk.files_need_scanning_queue = Queue()
    vt_bulk.path_and_link_to_requested_analysis_queue = Queue()
    vt_bulk.headers = {"accept": "application/json", "x-apikey": "testkey123"}


@pytest.fixture
def sample_files(tmp_path):
    """Two temp files for testing."""
    f1 = tmp_path / "file1.exe"
    f1.write_bytes(b"malware sample 1")
    f2 = tmp_path / "file2.dll"
    f2.write_bytes(b"malware sample 2")
    return [str(f1), str(f2)]


def _make_file_response(status_code=200, names=None, stats=None, link=""):
    """Helper to build a mock VT file GET response."""
    resp = MagicMock()
    resp.status_code = status_code
    if status_code == 200:
        resp.json.return_value = {
            "data": {
                "attributes": {
                    "names": names or ["test"],
                    "last_analysis_stats": stats or {"malicious": 0, "suspicious": 0, "undetected": 1},
                },
                "links": {"self": link or "https://vt.test/api/v3/files/abc"},
            }
        }
    return resp


def _make_post_response(analysis_link="https://vt.test/api/v3/analyses/xyz789"):
    """Helper to build a mock VT file upload POST response."""
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"data": {"links": {"self": analysis_link}}}
    return resp


def _make_analysis_response(status="completed"):
    """Helper to build a mock VT analysis polling GET response."""
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"data": {"attributes": {"status": status}}}
    return resp


# ===================== Integration: all files cached =======================

class TestAllCachedFlow:
    """Every file already exists on VT → no uploads needed."""

    def test_all_cached(self, sample_files, capsys):
        file1, file2 = sample_files

        def fake_get(url, **kwargs):
            return _make_file_response(200, names=["cached_file"])

        with patch("vt_bulk.requests.get", side_effect=fake_get), \
             patch("vt_bulk.createAnalysisFile"):
            vt_bulk.multithread_launchProgram([file1, file2])

        output = capsys.readouterr().out
        assert "retrieved successfully" in output
        assert "file1.exe" in output
        assert "file2.dll" in output
        assert "Undetected: ['file1.exe', 'file2.dll']" in output

    def test_all_malicious(self, sample_files, capsys):
        def fake_get(url, **kwargs):
            return _make_file_response(
                200,
                names=["evil"],
                stats={"malicious": 5, "suspicious": 1, "undetected": 0},
            )

        with patch("vt_bulk.requests.get", side_effect=fake_get), \
             patch("vt_bulk.createAnalysisFile"):
            vt_bulk.multithread_launchProgram(sample_files)

        output = capsys.readouterr().out
        assert "Malicious:" in output


# ===================== Integration: all files need upload ==================

class TestAllUploadedFlow:
    """No file exists on VT → all uploaded and polled."""

    def test_all_uploaded(self, sample_files):
        file1, file2 = sample_files

        def fake_get(url, **kwargs):
            if "/files/" in url:
                return MagicMock(status_code=404)
            return _make_analysis_response("completed")

        mock_post = MagicMock(return_value=_make_post_response())

        with patch.object(_requests, "get", side_effect=fake_get), \
             patch.object(_requests, "post", mock_post), \
             patch("vt_bulk.createAnalysisFile"):
            vt_bulk.multithread_launchProgram([file1, file2])

        assert mock_post.call_count == 2


# ===================== Integration: mixed flow =============================

class TestMixedFlow:
    """Some files cached, some need upload."""

    def test_mixed(self, sample_files, capsys):
        file1, file2 = sample_files

        # file1 → cached (200), file2 → needs upload (404)
        file_responses = {
            file1: _make_file_response(200, names=["cached"]),
            file2: MagicMock(status_code=404),
        }

        def fake_get(url, **kwargs):
            if "/files/" in url:
                for fp, resp in file_responses.items():
                    if fp in url or vt_bulk.getFileHash(fp, "SHA256") in url:
                        return resp
            return _make_analysis_response("completed")

        mock_post = MagicMock(return_value=_make_post_response())

        with patch.object(_requests, "get", side_effect=fake_get), \
             patch.object(_requests, "post", mock_post), \
             patch("vt_bulk.createAnalysisFile"):
            vt_bulk.multithread_launchProgram([file1, file2])

        output = capsys.readouterr().out
        mock_post.assert_called_once()  # only file2 was uploaded
        assert "retrieved successfully" in output  # file1 was cached


# ===================== Integration: getQueuedScansResultsV2 ===============

class TestGetQueuedScansResultsV2:
    """Test the polling loop that checks analysis status."""

    def test_polls_until_completed(self, tmp_path):
        test_file = tmp_path / "uploaded.exe"
        test_file.write_bytes(b"test content")

        vt_bulk.path_and_link_to_requested_analysis_queue.put(
            (str(test_file), "https://vt.test/api/v3/analyses/poll123")
        )

        call_count = {"n": 0}

        def fake_get(url, **kwargs):
            call_count["n"] += 1
            if "analyses" in url:
                if call_count["n"] == 1:
                    return _make_analysis_response("queued")
                return _make_analysis_response("completed")
            # multithread_GetFileResults GET
            return _make_file_response(200, names=["uploaded"])

        with patch("vt_bulk.requests.get", side_effect=fake_get), \
             patch("vt_bulk.createAnalysisFile"):
            vt_bulk.getQueuedScansResultsV2()

        # The pair should have been consumed
        assert vt_bulk.path_and_link_to_requested_analysis_queue.empty()
