"""Tests for the web app and database. Run: python test_app.py"""
import os
import database
from app import app, clean_url

TEST_DB = "test_phishguard.db"


def setup():
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)
    database.DB_PATH = TEST_DB
    database.init_db()
    app.config["TESTING"] = True
    return app.test_client()


def test_clean_url():
    assert clean_url("  http://a.com ") == "http://a.com"
    assert clean_url("") is None
    assert clean_url("has space.com") is None
    assert clean_url("a" * 3000) is None


def test_pages_and_scan():
    c = setup()
    assert c.get("/").status_code == 200
    r = c.post("/", data={"url": "http://paypa1-secure-login.example-bank.xyz/verify"})
    assert b"DANGEROUS" in r.data
    assert b"Please enter a valid URL" in c.post("/", data={"url": ""}).data
    assert b"paypa1" in c.get("/history").data
    assert b"Total scans" in c.get("/stats").data


def test_bulk_and_filter():
    c = setup()
    c.post("/bulk", data={"urls": "https://www.google.com\nhttp://192.168.1.1/login\n\n"})
    stats = database.get_stats()
    assert stats["total"] == 2
    assert len(database.get_history(verdict="SAFE")) == 1


def test_api():
    c = setup()
    data = c.get("/api/check?url=http://amaz0n.com/signin").get_json()
    assert data["verdict"] == "DANGEROUS"
    assert c.get("/api/check").status_code == 400


def test_clear():
    c = setup()
    c.post("/", data={"url": "https://www.google.com"})
    c.post("/clear")
    assert database.get_stats()["total"] == 0


if __name__ == "__main__":
    test_clean_url(); test_pages_and_scan(); test_bulk_and_filter(); test_api(); test_clear()
    os.remove(TEST_DB)
    print("All web app tests passed.")
