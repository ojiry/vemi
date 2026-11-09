import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "review", Path(__file__).resolve().parents[1] / "scripts" / "review.py")
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)


class ReviewTest(unittest.TestCase):
    def test_render_rejects_prose_and_invalid_locations(self):
        valid = {"verdict": "findings", "findings": [{"file": 1, "line": 2, "kind": "injection"}]}
        self.assertIn("`example.py:2`", review.render(valid, ["example.py"], {"example.py": 2})[1])
        for invalid in (
            {"verdict": "clean", "findings": valid["findings"]},
            {"verdict": "clean", "findings": [], "text": "@someone"},
            {"verdict": "findings", "findings": [{"file": 1, "line": 3, "kind": "injection"}]},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(review.Blocked):
                review.render(invalid, ["example.py"], {"example.py": 2})

    def test_tree_rejects_unsafe_objects(self):
        api = review.GitHub("owner/vemi", "dummy")
        file = {"path": "a.py", "mode": "100644", "type": "blob", "size": 1, "sha": "a" * 40}
        for tree in (
            [dict(file, path="../a.py")],
            [dict(file, path=".GIT/config")],
            [dict(file, mode="120000")],
            [dict(file, mode="160000", type="commit")],
            [file, dict(file, path="A.py")],
        ):
            with self.subTest(tree=tree), patch.object(api, "call", return_value={
                "truncated": False, "tree": tree,
            }), self.assertRaises(review.Blocked):
                api.tree("b" * 40)

    def test_inference_broker_rejects_other_destinations(self):
        with patch.object(review, "request") as request:
            with self.assertRaises(review.Blocked):
                review.anthropic({"id": 1, "path": "//example.com/v1/messages",
                                  "beta": "", "body": ""}, "dummy", "model", 1)
            request.assert_not_called()

    def test_approval_only_matches_exact_pull_and_commits(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            repo, base, head = "owner/vemi", "a" * 40, "b" * 40
            self.assertFalse(review.grant(root, repo, 1, base, head))
            path = root / "approve.json"
            for number, granted in ((True, False), (1, True), (2, False)):
                path.write_text(json.dumps({"repository": repo, "pr": number, "base": base, "head": head}))
                path.chmod(0o600)
                self.assertEqual(review.grant(root, repo, 1, base, head), granted)
                self.assertFalse(review.grant(root, repo, 1, base, "c" * 40))
                self.assertFalse(review.grant(root, repo, 1, "c" * 40, head))

    def test_stop_precedes_credentials_and_requests(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "STOP").touch()
            with patch.object(review, "config") as config, patch("builtins.print"):
                review.run(root)
                config.assert_not_called()


if __name__ == "__main__":
    unittest.main()
