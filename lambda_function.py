"""CloudForge least-privilege demo: backend (AWS Lambda behind a Function URL).

What it does
------------
* The Lambda itself has almost no power: its execution role may only
  (a) assume LeastPrivTesterRole, (b) read that one role's policy, (c) write logs.
* For every test it calls STS AssumeRole to get TEMPORARY credentials for
  LeastPrivTesterRole (15 minutes, no stored access keys anywhere).
* It then tries real S3 / IAM calls with those credentials and reports which
  ones AWS allowed and which it denied.

Routes
------
GET  /              dashboard (index.html)
GET  /api/info      identities, bucket, list of tests
GET  /api/policy    the restricted role's actual permission policy
POST /api/run       body {"action": "<id>"}  -> run one test
POST /api/run-all   run every test

Run from a terminal instead (CloudShell):  python3 lambda_function.py
"""
import base64
import json
import os
import time
from pathlib import Path

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

TESTER_ROLE_ARN = os.environ.get("TESTER_ROLE_ARN", "")
BUCKET = os.environ.get("BUCKET", "")
REGION = (
    os.environ.get("AWS_REGION")
    or os.environ.get("AWS_DEFAULT_REGION")
    or "ap-southeast-2"
)
TEST_KEY = "hello.txt"
SESSION_SECONDS = 900  # shortest STS allows: credentials die after 15 minutes
POLICY_NAME = "ReadOneBucketOnly"

# Error codes AWS uses when an identity is not allowed to do something.
DENY_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "AuthorizationError",
    "Forbidden",
    "403",
}

_CFG = Config(retries={"max_attempts": 2, "mode": "standard"}, connect_timeout=5, read_timeout=10)


# --------------------------------------------------------------------------
# The tests. expect = "allow" (permitted task) or "deny" (administrative action)
# --------------------------------------------------------------------------
def _list_bucket(s):
    r = s.client("s3", config=_CFG).list_objects_v2(Bucket=BUCKET, MaxKeys=10)
    keys = [o["Key"] for o in r.get("Contents", [])]
    return "Listed %d object(s): %s" % (len(keys), ", ".join(keys) or "(empty)")


def _read_object(s):
    r = s.client("s3", config=_CFG).get_object(Bucket=BUCKET, Key=TEST_KEY)
    text = r["Body"].read(200).decode("utf-8", "replace")
    return "Read %s: %s" % (TEST_KEY, text.strip())


def _upload_object(s):
    s.client("s3", config=_CFG).put_object(
        Bucket=BUCKET, Key="unauthorized-upload.txt", Body=b"this should not be allowed"
    )
    return "Upload succeeded (the restricted role should NOT be able to do this)"


def _delete_object(s):
    s.client("s3", config=_CFG).delete_object(Bucket=BUCKET, Key="unauthorized-delete.txt")
    return "Delete succeeded (the restricted role should NOT be able to do this)"


def _delete_bucket(s):
    s.client("s3", config=_CFG).delete_bucket(Bucket=BUCKET)
    return "Bucket deleted (the restricted role should NOT be able to do this)"


def _create_user(s):
    s.client("iam", config=_CFG).create_user(UserName="cloudforge-should-fail")
    return "IAM user created (the restricted role should NOT be able to do this)"


ACTIONS = [
    {"id": "list_bucket", "label": "List files in the bucket", "kind": "Permitted task",
     "expect": "allow", "api": "s3:ListBucket", "fn": _list_bucket},
    {"id": "read_object", "label": "Read hello.txt", "kind": "Permitted task",
     "expect": "allow", "api": "s3:GetObject", "fn": _read_object},
    {"id": "upload_object", "label": "Upload a new file", "kind": "Write action",
     "expect": "deny", "api": "s3:PutObject", "fn": _upload_object},
    {"id": "delete_object", "label": "Delete a file", "kind": "Write action",
     "expect": "deny", "api": "s3:DeleteObject", "fn": _delete_object},
    {"id": "delete_bucket", "label": "Delete the whole bucket", "kind": "Administrative action",
     "expect": "deny", "api": "s3:DeleteBucket", "fn": _delete_bucket},
    {"id": "create_user", "label": "Create an IAM user", "kind": "Administrative action",
     "expect": "deny", "api": "iam:CreateUser", "fn": _create_user},
]
ACTIONS_BY_ID = {a["id"]: a for a in ACTIONS}


# --------------------------------------------------------------------------
# Temporary credentials via STS
# --------------------------------------------------------------------------
def restricted_session(name="dashboard"):
    """Assume the restricted role. Returns (boto3 Session, info dict)."""
    if not TESTER_ROLE_ARN or not BUCKET:
        raise RuntimeError("TESTER_ROLE_ARN and BUCKET environment variables are not set")
    resp = boto3.client("sts", config=_CFG).assume_role(
        RoleArn=TESTER_ROLE_ARN,
        RoleSessionName=name,
        DurationSeconds=SESSION_SECONDS,
    )
    c = resp["Credentials"]
    session = boto3.Session(
        aws_access_key_id=c["AccessKeyId"],
        aws_secret_access_key=c["SecretAccessKey"],
        aws_session_token=c["SessionToken"],
        region_name=REGION,
    )
    info = {
        "restricted_identity": resp["AssumedRoleUser"]["Arn"],
        "credentials_expire": c["Expiration"].isoformat(),
        "credential_type": "temporary (STS AssumeRole), expires in %d minutes" % (SESSION_SECONDS // 60),
    }
    return session, info


def run_action(session, action):
    started = time.time()
    code = None
    try:
        detail = action["fn"](session)
        outcome = "ALLOWED"
    except ClientError as e:
        err = e.response.get("Error", {})
        code = err.get("Code", "")
        detail = "%s: %s" % (code, err.get("Message", ""))
        outcome = "DENIED" if code in DENY_CODES else "ERROR"
    except Exception as e:  # network problems, bad config, ...
        code = type(e).__name__
        detail = "%s: %s" % (code, e)
        outcome = "ERROR"
    expected = "ALLOWED" if action["expect"] == "allow" else "DENIED"
    return {
        "id": action["id"],
        "label": action["label"],
        "kind": action["kind"],
        "api": action["api"],
        "expected": expected,
        "outcome": outcome,
        "as_expected": outcome == expected,
        "error_code": code,
        "detail": detail,
        "ms": int((time.time() - started) * 1000),
    }


def backend_identity():
    return boto3.client("sts", config=_CFG).get_caller_identity()["Arn"]


def role_policy():
    role_name = TESTER_ROLE_ARN.split("/")[-1]
    try:
        r = boto3.client("iam", config=_CFG).get_role_policy(RoleName=role_name, PolicyName=POLICY_NAME)
        return {"role": role_name, "policy_name": POLICY_NAME, "document": r["PolicyDocument"]}
    except ClientError as e:
        return {"role": role_name, "policy_name": POLICY_NAME, "error": str(e)}


def public_actions():
    return [{k: a[k] for k in ("id", "label", "kind", "api")} | {
        "expected": "ALLOWED" if a["expect"] == "allow" else "DENIED"} for a in ACTIONS]


# --------------------------------------------------------------------------
# HTTP layer (Lambda Function URL, payload format 2.0)
# --------------------------------------------------------------------------
_SEC = {
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
        "connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'"
    ),
}


def _json(status, payload):
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json", **_SEC},
        "body": json.dumps(payload, default=str),
    }


def _html():
    page = Path(__file__).with_name("index.html").read_text(encoding="utf-8")
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "text/html; charset=utf-8", **_SEC},
        "body": page,
    }


def _body(event):
    raw = event.get("body") or ""
    if event.get("isBase64Encoded") and raw:
        raw = base64.b64decode(raw).decode("utf-8", "replace")
    try:
        data = json.loads(raw) if raw else {}
    except ValueError:
        data = {}
    return data if isinstance(data, dict) else {}


def handler(event, context=None):
    http = (event.get("requestContext") or {}).get("http") or {}
    method = (http.get("method") or "GET").upper()
    path = event.get("rawPath") or "/"
    try:
        if method == "GET" and path in ("/", "/index.html"):
            return _html()
        if method == "GET" and path == "/api/info":
            return _json(200, {
                "backend_identity": backend_identity(),
                "tester_role": TESTER_ROLE_ARN,
                "bucket": BUCKET,
                "region": REGION,
                "actions": public_actions(),
            })
        if method == "GET" and path == "/api/policy":
            return _json(200, role_policy())
        if method == "POST" and path == "/api/run":
            action = ACTIONS_BY_ID.get(str(_body(event).get("action", "")))
            if not action:
                return _json(400, {"error": "unknown action", "valid": list(ACTIONS_BY_ID)})
            session, info = restricted_session()
            return _json(200, {**info, "result": run_action(session, action)})
        if method == "POST" and path == "/api/run-all":
            session, info = restricted_session()
            results = [run_action(session, a) for a in ACTIONS]
            return _json(200, {
                **info,
                "results": results,
                "passed": sum(1 for r in results if r["as_expected"]),
                "total": len(results),
            })
        return _json(404, {"error": "not found", "path": path})
    except ClientError as e:
        err = e.response.get("Error", {})
        return _json(500, {"error": "%s: %s" % (err.get("Code", "AWSError"), err.get("Message", str(e)))})
    except Exception as e:  # never leak a stack trace to the browser
        return _json(500, {"error": "%s: %s" % (type(e).__name__, e)})


# --------------------------------------------------------------------------
# Terminal mode:  python3 lambda_function.py
# --------------------------------------------------------------------------
if __name__ == "__main__":
    sess, meta = restricted_session("terminal")
    print("Restricted identity :", meta["restricted_identity"])
    print("Credentials         :", meta["credential_type"])
    print()
    good = 0
    for act in ACTIONS:
        r = run_action(sess, act)
        good += r["as_expected"]
        print("%-26s expected %-7s got %-7s %s" % (
            r["label"], r["expected"], r["outcome"], "OK" if r["as_expected"] else "UNEXPECTED"))
    print("\n%d/%d behaved as expected" % (good, len(ACTIONS)))
