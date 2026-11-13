"""Tests for the self-serve dataset bucket-notification endpoints.

Covers register (auto-create + rule), idempotency, multi-prefix read-modify-write merge,
deregister (ref-free removal), the cp-* convention guard, and missing-bucket deregister.
"""

REG = "/api/buckets/{bucket}/notifications/register"


class TestRegisterNotification:
    def test_register_creates_bucket_and_rule(self, app_client, fake_minio):
        bucket = "cp-tenant-demo"
        assert not fake_minio.bucket_exists(bucket)

        resp = app_client.post(REG.format(bucket=bucket), json={"prefix": "data/sales.csv"})

        assert resp.status_code == 201
        body = resp.json()
        assert body["bucket"] == bucket
        assert body["prefix"] == "data/sales.csv"
        assert body["rules"] == 1
        # bucket auto-created on demand
        assert fake_minio.bucket_exists(bucket)
        # rule persisted, pointing at the shared ARN
        rules = fake_minio._notifications[bucket]
        assert len(rules) == 1
        assert rules[0]["arn"] == "arn:minio:sqs::cpdatasets:webhook"
        assert "s3:ObjectCreated:*" in rules[0]["events"]

    def test_register_is_idempotent_per_prefix(self, app_client, fake_minio):
        bucket = "cp-tenant-idem"
        app_client.post(REG.format(bucket=bucket), json={"prefix": "x.csv"})
        resp = app_client.post(REG.format(bucket=bucket), json={"prefix": "x.csv"})
        assert resp.status_code == 201
        assert resp.json()["rules"] == 1
        assert len(fake_minio._notifications[bucket]) == 1

    def test_register_merges_multiple_prefixes(self, app_client, fake_minio):
        bucket = "cp-tenant-multi"
        app_client.post(REG.format(bucket=bucket), json={"prefix": "a.csv"})
        resp = app_client.post(REG.format(bucket=bucket), json={"prefix": "b.csv"})
        assert resp.status_code == 201
        assert resp.json()["rules"] == 2
        assert len(fake_minio._notifications[bucket]) == 2

    def test_register_whole_bucket_empty_prefix(self, app_client, fake_minio):
        bucket = "cp-tenant-whole"
        resp = app_client.post(REG.format(bucket=bucket), json={})
        assert resp.status_code == 201
        assert resp.json()["prefix"] == ""
        assert resp.json()["rules"] == 1

    def test_register_rejects_non_cp_bucket(self, app_client):
        resp = app_client.post(REG.format(bucket="artifacts"), json={"prefix": "x.csv"})
        assert resp.status_code == 400
        assert "must start with" in resp.json()["error"]["message"]

    def test_register_rejects_traversal_prefix(self, app_client, fake_minio):
        """``body.prefix`` used to reach MinIO's PrefixFilterRule unvalidated."""
        bucket = "cp-tenant-traversal"
        resp = app_client.post(REG.format(bucket=bucket), json={"prefix": "../../etc/passwd"})
        assert resp.status_code == 400
        assert not fake_minio.bucket_exists(bucket)

    def test_register_rejects_control_char_prefix(self, app_client):
        bucket = "cp-tenant-ctrl"
        resp = app_client.post(REG.format(bucket=bucket), json={"prefix": "a\x00b"})
        assert resp.status_code == 400


class TestDeregisterNotification:
    def test_deregister_removes_only_matching_rule(self, app_client, fake_minio):
        bucket = "cp-tenant-del"
        app_client.post(REG.format(bucket=bucket), json={"prefix": "a.csv"})
        app_client.post(REG.format(bucket=bucket), json={"prefix": "b.csv"})

        resp = app_client.request("DELETE", REG.format(bucket=bucket), json={"prefix": "a.csv"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["removed"] == 1
        assert body["rules"] == 1
        remaining = fake_minio._notifications[bucket]
        assert len(remaining) == 1
        assert remaining[0]["prefix"] == "b.csv"

    def test_deregister_unknown_prefix_is_noop(self, app_client, fake_minio):
        bucket = "cp-tenant-noop"
        app_client.post(REG.format(bucket=bucket), json={"prefix": "a.csv"})
        resp = app_client.request(
            "DELETE", REG.format(bucket=bucket), json={"prefix": "missing.csv"}
        )
        assert resp.status_code == 200
        assert resp.json()["removed"] == 0
        assert resp.json()["rules"] == 1

    def test_deregister_missing_bucket_is_noop(self, app_client):
        resp = app_client.request(
            "DELETE", REG.format(bucket="cp-never-existed"), json={"prefix": "a.csv"}
        )
        assert resp.status_code == 200
        assert resp.json()["removed"] == 0

    def test_deregister_rejects_non_cp_bucket(self, app_client):
        resp = app_client.request(
            "DELETE", REG.format(bucket="artifacts"), json={"prefix": "x.csv"}
        )
        assert resp.status_code == 400

    def test_deregister_rejects_traversal_prefix(self, app_client):
        """``body.prefix`` used to reach MinIO's PrefixFilterRule unvalidated."""
        resp = app_client.request(
            "DELETE", REG.format(bucket="cp-tenant-del2"), json={"prefix": "../x"}
        )
        assert resp.status_code == 400


LIST = "/api/buckets/{bucket}/notifications"


class TestListNotifications:
    def test_list_reflects_registered_rules(self, app_client):
        bucket = "cp-tenant-list"
        app_client.post(REG.format(bucket=bucket), json={"prefix": "a.csv"})
        app_client.post(REG.format(bucket=bucket), json={"prefix": "b.csv"})

        resp = app_client.get(LIST.format(bucket=bucket))
        assert resp.status_code == 200
        body = resp.json()
        assert body["bucket"] == bucket
        prefixes = sorted(r["prefix"] for r in body["rules"])
        assert prefixes == ["a.csv", "b.csv"]
        rule = next(r for r in body["rules"] if r["prefix"] == "a.csv")
        assert rule["arn"] == "arn:minio:sqs::cpdatasets:webhook"
        assert "s3:ObjectCreated:*" in rule["events"]
        assert rule["config_id"].startswith("cp-")

    def test_list_empty_for_unprovisioned_bucket(self, app_client):
        resp = app_client.get(LIST.format(bucket="cp-never-provisioned"))
        assert resp.status_code == 200
        assert resp.json() == {"bucket": "cp-never-provisioned", "rules": []}

    def test_list_empty_after_deregister(self, app_client):
        bucket = "cp-tenant-listdel"
        app_client.post(REG.format(bucket=bucket), json={"prefix": "a.csv"})
        app_client.request("DELETE", REG.format(bucket=bucket), json={"prefix": "a.csv"})

        resp = app_client.get(LIST.format(bucket=bucket))
        assert resp.status_code == 200
        assert resp.json()["rules"] == []

    def test_list_rejects_non_cp_bucket(self, app_client):
        resp = app_client.get(LIST.format(bucket="artifacts"))
        assert resp.status_code == 400
        assert "must start with" in resp.json()["error"]["message"]
