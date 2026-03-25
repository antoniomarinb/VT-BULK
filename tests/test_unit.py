import pytest
import os
import sys
import json
import time
from unittest.mock import patch, MagicMock
from queue import Queue

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import vt_bulk


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def reset_globals():
    """Reset module-level global state before each test."""
    vt_bulk.VERBOSE = True
    vt_bulk.NO_JSON_DUMP = False
    vt_bulk.CHECK_QUOTA = True
    vt_bulk.finished_requesting_scans = False
    vt_bulk.analysis_results_queue = Queue()
    vt_bulk.files_need_scanning_queue = Queue()
    vt_bulk.path_and_link_to_requested_analysis_queue = Queue()
    vt_bulk.headers = {"accept": "application/json", "x-apikey": "testkey123"}


@pytest.fixture
def tmp_test_file(tmp_path):
    """Create a temporary test file with known content."""
    f = tmp_path / "testfile.exe"
    f.write_bytes(b"hello world")
    return str(f)


@pytest.fixture
def tmp_dir_with_files(tmp_path):
    """Create a temp directory with files of multiple extensions."""
    (tmp_path / "a.exe").write_text("a")
    (tmp_path / "b.dll").write_text("b")
    (tmp_path / "c.txt").write_text("c")
    (tmp_path / "vt_api_key.txt").write_text("secret")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "d.exe").write_text("d")
    return tmp_path


# ===================== getFileHash =========================================

class TestGetFileHash:
    def test_sha256(self, tmp_test_file):
        result = vt_bulk.getFileHash(tmp_test_file, "SHA256")
        assert len(result) == 64
        assert result == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

    def test_sha512(self, tmp_test_file):
        result = vt_bulk.getFileHash(tmp_test_file, "SHA512")
        assert len(result) == 128

    def test_md5(self, tmp_test_file):
        result = vt_bulk.getFileHash(tmp_test_file, "MD5")
        assert len(result) == 32
        assert result == "5eb63bbbe01eeed093cb22bb8f5acdc3"

    def test_case_insensitive(self, tmp_test_file):
        r1 = vt_bulk.getFileHash(tmp_test_file, "sha256")
        r2 = vt_bulk.getFileHash(tmp_test_file, "SHA256")
        assert r1 == r2

    def test_invalid_algo_falls_back_to_sha256(self, tmp_test_file):
        vt_bulk.VERBOSE = False
        expected = vt_bulk.getFileHash(tmp_test_file, "SHA256")
        result = vt_bulk.getFileHash(tmp_test_file, "INVALID")
        assert result == expected


# ===================== filterFilesByExtension ===============================

class TestFilterFilesByExtension:
    FILES = ["/a.exe", "/b.dll", "/c.txt", "/d.exe"]

    def test_single_ext(self):
        result = vt_bulk.filterFilesByExtension(self.FILES, ".exe")
        assert result == ["/a.exe", "/d.exe"]

    def test_multiple_ext(self):
        result = vt_bulk.filterFilesByExtension(self.FILES, ".exe,.dll")
        assert sorted(result) == sorted(["/a.exe", "/b.dll", "/d.exe"])

    def test_no_dot_prefix(self):
        result = vt_bulk.filterFilesByExtension(self.FILES, "exe")
        assert result == ["/a.exe", "/d.exe"]

    def test_none_returns_all(self):
        assert vt_bulk.filterFilesByExtension(self.FILES, None) == self.FILES

    def test_empty_returns_all(self):
        assert vt_bulk.filterFilesByExtension(self.FILES, "") == self.FILES

    def test_no_match(self):
        assert vt_bulk.filterFilesByExtension(self.FILES, ".mp3") == []

    def test_whitespace_around_ext(self):
        result = vt_bulk.filterFilesByExtension(self.FILES, " .exe , .dll ")
        assert sorted(result) == sorted(["/a.exe", "/b.dll", "/d.exe"])


# ===================== getAllFilesInDirHierarchy ============================

class TestGetAllFilesInDirHierarchy:
    def test_finds_all(self, tmp_dir_with_files):
        result = vt_bulk.getAllFilesInDirHierarchy(str(tmp_dir_with_files))
        basenames = sorted(os.path.basename(f) for f in result)
        assert basenames == ["a.exe", "b.dll", "c.txt", "d.exe"]

    def test_skips_api_key(self, tmp_dir_with_files):
        result = vt_bulk.getAllFilesInDirHierarchy(str(tmp_dir_with_files))
        assert not any("vt_api_key.txt" in f for f in result)


# ===================== getFilesToScan ======================================

class TestGetFilesToScan:
    def test_with_filter(self, tmp_dir_with_files):
        result = vt_bulk.getFilesToScan(str(tmp_dir_with_files), ".exe")
        basenames = sorted(os.path.basename(f) for f in result)
        assert basenames == ["a.exe", "d.exe"]

    def test_no_filter(self, tmp_dir_with_files):
        result = vt_bulk.getFilesToScan(str(tmp_dir_with_files), None)
        assert len(result) == 4


# ===================== argumentHandler =====================================

class TestArgumentHandler:
    @patch("vt_bulk.argparse.ArgumentParser.parse_args")
    def test_valid_path(self, mock_parse):
        mock_parse.return_value = MagicMock(
            path="/tmp", extension=None, quiet=False,
            unsafe_only=False, full_report=False,
        )
        vt_bulk.argumentHandler()
        assert vt_bulk.DIRECTORY_PATH == "/tmp"
        assert vt_bulk.extension is None

    @patch("vt_bulk.argparse.ArgumentParser.parse_args")
    def test_with_extension(self, mock_parse):
        mock_parse.return_value = MagicMock(
            path="/tmp", extension=".exe", quiet=False,
            unsafe_only=False, full_report=False,
        )
        vt_bulk.argumentHandler()
        assert vt_bulk.extension == ".exe"

    @patch("vt_bulk.argparse.ArgumentParser.parse_args")
    def test_quiet_flag(self, mock_parse):
        mock_parse.return_value = MagicMock(
            path="/tmp", extension=None, quiet=True,
            unsafe_only=False, full_report=False,
        )
        vt_bulk.argumentHandler()
        assert vt_bulk.VERBOSE is False

    @patch("vt_bulk.argparse.ArgumentParser.parse_args")
    def test_invalid_path_exits(self, mock_parse):
        mock_parse.return_value = MagicMock(
            path="/nonexistent_path_abc123", extension=None, quiet=False,
            unsafe_only=False, full_report=False,
        )
        with pytest.raises(SystemExit):
            vt_bulk.argumentHandler()

    @patch("vt_bulk.LaunchSimpleTUI", return_value=("/tmp", None))
    @patch("vt_bulk.argparse.ArgumentParser.parse_args")
    def test_no_path_triggers_tui(self, mock_parse, mock_tui):
        mock_parse.return_value = MagicMock(
            path=None, extension=None, quiet=False,
            unsafe_only=False, full_report=False,
        )
        vt_bulk.argumentHandler()
        mock_tui.assert_called_once()
        assert vt_bulk.DIRECTORY_PATH == "/tmp"


# ===================== getUserVerification =================================

class TestGetUserVerification:
    @patch("vt_bulk.input2", return_value="yes")
    def test_yes_proceeds(self, mock_input):
        vt_bulk.getUserVerification(["/some/file.exe"])

    @patch("vt_bulk.input2", return_value="no")
    def test_no_exits(self, mock_input):
        with pytest.raises(SystemExit):
            vt_bulk.getUserVerification(["/some/file.exe"])

    def test_empty_list_exits(self):
        with pytest.raises(SystemExit):
            vt_bulk.getUserVerification([])


# ===================== API functions (mocked) ==============================

class TestMultithreadGetFileResults:
    def test_200_cached(self, tmp_test_file):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {"names": ["test.exe"], "last_analysis_stats": {"malicious": 0, "suspicious": 0, "undetected": 1}},
                "links": {"self": "https://vt.test/api/v3/files/abc123"},
            }
        }
        with patch("vt_bulk.requests.get", return_value=mock_resp), \
             patch("vt_bulk.createAnalysisFile"):
            vt_bulk.multithread_GetFileResults(tmp_test_file)
        assert not vt_bulk.analysis_results_queue.empty()
        result = vt_bulk.analysis_results_queue.get()
        assert result["file_path"] == tmp_test_file
        assert result["summary"]["malicious"] == 0

    def test_404_needs_upload(self, tmp_test_file):
        mock_resp = MagicMock(status_code=404)
        with patch("vt_bulk.requests.get", return_value=mock_resp):
            vt_bulk.multithread_GetFileResults(tmp_test_file)
        assert not vt_bulk.files_need_scanning_queue.empty()
        assert vt_bulk.analysis_results_queue.empty()
        assert vt_bulk.files_need_scanning_queue.get() == tmp_test_file

    def test_500_exits(self, tmp_test_file):
        mock_resp = MagicMock(status_code=500)
        with patch("vt_bulk.requests.get", return_value=mock_resp):
            with pytest.raises(SystemExit):
                vt_bulk.multithread_GetFileResults(tmp_test_file)


class TestRequestedAnalysisWorker:
    def test_posts_file_successfully(self, tmp_test_file):
        vt_bulk.files_need_scanning_queue.put(tmp_test_file)
        vt_bulk.finished_requesting_scans = True

        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {"data": {"links": {"self": "https://vt.test/api/v3/analyses/abc"}}}

        with patch("vt_bulk.requests.post", return_value=mock_resp):
            vt_bulk.requestedAnalysisWorker()

        assert not vt_bulk.path_and_link_to_requested_analysis_queue.empty()
        path, link = vt_bulk.path_and_link_to_requested_analysis_queue.get()
        assert path == tmp_test_file
        assert "analyses" in link

    def test_handles_error_response(self, tmp_test_file):
        vt_bulk.files_need_scanning_queue.put(tmp_test_file)
        vt_bulk.finished_requesting_scans = True

        mock_resp = MagicMock(status_code=403, text="Forbidden")
        mock_resp.json.return_value = {}

        with patch("vt_bulk.requests.post", return_value=mock_resp):
            vt_bulk.requestedAnalysisWorker()

        assert vt_bulk.path_and_link_to_requested_analysis_queue.empty()

    def test_empty_queue_exits_immediately(self):
        vt_bulk.finished_requesting_scans = True
        vt_bulk.requestedAnalysisWorker()
        assert vt_bulk.path_and_link_to_requested_analysis_queue.empty()


# ===================== APIRateLimiter ======================================

class TestAPIRateLimiter:
    def test_under_limit_no_sleep(self):
        rl = vt_bulk.APIRateLimiter(4)
        with patch("vt_bulk.time.sleep") as mock_sleep:
            for _ in range(4):
                rl.request()
                rl.place()
        mock_sleep.assert_not_called()

    def test_at_limit_sleeps(self):
        rl = vt_bulk.APIRateLimiter(4)
        # Pre-fill queue with timestamps from 100s ago
        old = time.time() - 100
        for _ in range(4):
            rl.queue.put(old)

        with patch("vt_bulk.time.sleep") as mock_sleep, \
             patch("vt_bulk.time.time", side_effect=[200.0, 200.0]):
            rl.request()
            rl.place()

        mock_sleep.assert_called_once()


# ===================== printAndSaveDailyAPIQuotaStats ======================

class TestPrintAndSaveDailyAPIQuotaStats:
    def test_200_shows_stats(self, capsys):
        today = __import__("datetime").datetime.today().strftime("%Y-%m-%d")
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {"data": {"daily": {today: {"uploads": 5}}}}
        vt_bulk.vt_user_id = "testuser"
        vt_bulk.NO_JSON_DUMP = True
        with patch("vt_bulk.requests.get", return_value=mock_resp):
            vt_bulk.printAndSaveDailyAPIQuotaStats()
        assert "uploads" in capsys.readouterr().out

    def test_error_prints_message(self, capsys):
        mock_resp = MagicMock(status_code=401)
        vt_bulk.vt_user_id = "testuser"
        with patch("vt_bulk.requests.get", return_value=mock_resp):
            vt_bulk.printAndSaveDailyAPIQuotaStats()
        assert "Could not fetch" in capsys.readouterr().out


# ===================== createAnalysisFile ==================================

class TestCreateAnalysisFile:
    def test_creates_json(self, tmp_test_file, tmp_path):
        scans_dir = tmp_path / "scans"
        with patch("vt_bulk.os.path.exists", return_value=False), \
             patch("vt_bulk.os.makedirs") as mock_mkdir, \
             patch("vt_bulk.os.path.basename", return_value="testfile"), \
             patch("vt_bulk.getFileHash", return_value="abc123"), \
             patch("builtins.open", MagicMock()):
            vt_bulk.createAnalysisFile({"data": {}}, tmp_test_file)
        mock_mkdir.assert_called_once()

    def test_no_dump_skips(self, tmp_test_file):
        vt_bulk.NO_JSON_DUMP = True
        with patch("builtins.open") as mock_open:
            vt_bulk.createAnalysisFile({}, tmp_test_file)
        mock_open.assert_not_called()
