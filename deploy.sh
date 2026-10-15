#!/usr/bin/env bash
# CloudForge least-privilege demo: one-command deploy. Run inside AWS CloudShell.
# Safe to run more than once: it creates what is missing and updates the rest.
set -u
cd "$(dirname "$0")" || exit 1

REGION="${CF_REGION:-ap-southeast-2}"
FUNC=LeastPrivDashboard
TESTER=LeastPrivTesterRole
BACKEND=LeastPrivBackendRole

aws() { command aws --region "$REGION" "$@"; }
die() { echo; echo "FAILED: $*" >&2; exit 1; }
say() { echo; echo "== $*"; }
retry() { # retry <times> <command...>  (IAM needs a few seconds to propagate)
  local n=$1 i; shift
  for i in $(seq 1 "$n"); do
    if "$@" >/dev/null 2>.retry_err; then return 0; fi
    sleep 6
  done
  cat .retry_err >&2; return 1
}

for f in lambda_function.py index.html; do
  [ -f "$f" ] || die "$f is missing. Unzip the bundle first and run this from that folder."
done

ACCT=$(aws sts get-caller-identity --query Account --output text 2>/dev/null) \
  || die "Cannot reach AWS. Run this inside CloudShell."
BUCKET="lp-demo-$ACCT"
BACKEND_ARN="arn:aws:iam::$ACCT:role/$BACKEND"
TESTER_ARN="arn:aws:iam::$ACCT:role/$TESTER"
echo "Account $ACCT | region $REGION | bucket $BUCKET"

# ---------------------------------------------------------------- 1. bucket
say "1/6 Test resource (S3 bucket)"
if aws s3api head-bucket --bucket "$BUCKET" 2>/dev/null; then
  echo "bucket already exists"
else
  aws s3api create-bucket --bucket "$BUCKET" \
    --create-bucket-configuration LocationConstraint="$REGION" >/dev/null \
    || die "could not create bucket $BUCKET"
fi
aws s3api put-public-access-block --bucket "$BUCKET" --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true \
  >/dev/null 2>&1 || true
echo "hello from the least-privilege demo" > hello.txt
aws s3 cp hello.txt "s3://$BUCKET/hello.txt" --only-show-errors || die "could not upload hello.txt"

# ------------------------------------------------- 2. backend (Lambda) role
say "2/6 Backend role (can only assume the restricted role)"
cat > trust-lambda.json <<EOF
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}
EOF
cat > backend-policy.json <<EOF
{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":"sts:AssumeRole","Resource":"$TESTER_ARN"},
 {"Effect":"Allow","Action":"iam:GetRolePolicy","Resource":"$TESTER_ARN"},
 {"Effect":"Allow","Action":["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],
  "Resource":"arn:aws:logs:$REGION:$ACCT:log-group:/aws/lambda/$FUNC*"}]}
EOF
if aws iam get-role --role-name "$BACKEND" >/dev/null 2>&1; then
  echo "role already exists"
else
  aws iam create-role --role-name "$BACKEND" \
    --assume-role-policy-document file://trust-lambda.json >/dev/null || die "could not create $BACKEND"
fi
aws iam put-role-policy --role-name "$BACKEND" --policy-name BackendMinimal \
  --policy-document file://backend-policy.json || die "could not attach backend policy"

# ----------------------------------------------- 3. restricted (tester) role
say "3/6 Restricted role (read ONE bucket, nothing else)"
ADMIN_ARN=$(aws iam get-role --role-name AccountFullAccessRole --query Role.Arn --output text 2>/dev/null || true)
python3 - "$BACKEND_ARN" "$ADMIN_ARN" <<'PY'
import json, sys
who = [a for a in sys.argv[1:] if a.startswith("arn:")]
doc = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": {"AWS": who}, "Action": "sts:AssumeRole"}]}
json.dump(doc, open("trust-tester.json", "w"))
PY
cat > perm.json <<EOF
{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::$BUCKET"},
 {"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::$BUCKET/*"}]}
EOF
if aws iam get-role --role-name "$TESTER" >/dev/null 2>&1; then
  retry 8 aws iam update-assume-role-policy --role-name "$TESTER" \
    --policy-document file://trust-tester.json || die "could not update trust of $TESTER"
else
  retry 8 aws iam create-role --role-name "$TESTER" \
    --assume-role-policy-document file://trust-tester.json || die "could not create $TESTER"
fi
aws iam put-role-policy --role-name "$TESTER" --policy-name ReadOneBucketOnly \
  --policy-document file://perm.json || die "could not attach the restricted policy"
echo "restricted role ready"

# --------------------------------------------------------- 4. package + lambda
say "4/6 Backend (Lambda function)"
rm -f function.zip
python3 -m zipfile -c function.zip lambda_function.py index.html || die "could not build function.zip"
ENVV="Variables={TESTER_ROLE_ARN=$TESTER_ARN,BUCKET=$BUCKET}"
if aws lambda get-function --function-name "$FUNC" >/dev/null 2>&1; then
  aws lambda update-function-code --function-name "$FUNC" --zip-file fileb://function.zip >/dev/null \
    || die "could not update function code"
  aws lambda wait function-updated --function-name "$FUNC" 2>/dev/null || sleep 5
  aws lambda update-function-configuration --function-name "$FUNC" --environment "$ENVV" >/dev/null \
    || die "could not update function configuration"
  aws lambda wait function-updated --function-name "$FUNC" 2>/dev/null || sleep 5
else
  retry 10 aws lambda create-function --function-name "$FUNC" --runtime python3.12 \
    --handler lambda_function.handler --role "$BACKEND_ARN" --zip-file fileb://function.zip \
    --timeout 30 --memory-size 256 --environment "$ENVV" \
    || die "could not create the Lambda function (is Lambda enabled for this account?)"
  aws lambda wait function-active-v2 --function-name "$FUNC" 2>/dev/null || sleep 8
fi
echo "function ready"

# ---------------------------------------------------------- 5. public web URL
say "5/6 Web address for the dashboard"
URL=$(aws lambda get-function-url-config --function-name "$FUNC" --query FunctionUrl --output text 2>/dev/null || true)
if [ -z "$URL" ] || [ "$URL" = "None" ]; then
  URL=$(aws lambda create-function-url-config --function-name "$FUNC" --auth-type NONE \
        --query FunctionUrl --output text 2>.url_err || true)
fi
if [ -n "$URL" ] && [ "$URL" != "None" ]; then
  aws lambda add-permission --function-name "$FUNC" --statement-id FunctionURLPublic \
    --action lambda:InvokeFunctionUrl --principal '*' --function-url-auth-type NONE >/dev/null 2>&1 || true
  aws lambda add-permission --function-name "$FUNC" --statement-id FunctionURLPublicInvoke \
    --action lambda:InvokeFunction --principal '*' --invoked-via-function-url >/dev/null 2>&1 || true
else
  URL=""
  echo "Could not create a public URL on this account:"; cat .url_err 2>/dev/null
  echo "The backend still works. Use the terminal demo: python3 lambda_function.py"
fi

# ----------------------------------------------------------------- 6. self-test
say "6/6 Self-test (backend calls AWS with the restricted role)"
cat > event.json <<'EOF'
{"requestContext":{"http":{"method":"POST"}},"rawPath":"/api/run-all","body":"{}","isBase64Encoded":false}
EOF
PASS=0
for attempt in 1 2 3 4 5; do
  aws lambda invoke --function-name "$FUNC" --cli-binary-format raw-in-base64-out \
    --payload file://event.json out.json >/dev/null 2>&1
  python3 - <<'PY'
import json, sys
try:
    r = json.load(open("out.json"))
    b = json.loads(r["body"])
except Exception as e:
    print("  waiting for AWS to finish setting up permissions..."); sys.exit(2)
if "results" not in b:
    print("  waiting for AWS to finish setting up permissions... (%s)" % b.get("error", r)); sys.exit(2)
print("  restricted identity:", b["restricted_identity"])
for x in b["results"]:
    print("  %-26s expected %-7s got %-7s %s" % (x["label"], x["expected"], x["outcome"],
          "OK" if x["as_expected"] else "UNEXPECTED"))
print("  %d/%d behaved as expected" % (b["passed"], b["total"]))
json.dump(b, open("selftest-evidence.json", "w"), indent=2)
sys.exit(0 if b["passed"] == b["total"] else 1)
PY
  rc=$?
  if [ "$rc" -eq 0 ]; then PASS=1; break; fi
  [ "$rc" -eq 1 ] && break   # ran fine but something was unexpected: no point retrying
  sleep 8
done

echo
echo "=============================================================="
if [ "$PASS" = 1 ]; then echo " ALL CHECKS PASSED"; else echo " Self-test did not fully pass - send this screen to Claude"; fi
[ -n "$URL" ] && echo " Dashboard: $URL"
echo " Evidence file: $(pwd)/selftest-evidence.json"
echo " When finished: bash cleanup_all.sh"
echo "=============================================================="
