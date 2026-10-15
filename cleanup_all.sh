#!/usr/bin/env bash
# Removes EVERYTHING the CloudForge demo created, including the unused test user.
# Run inside AWS CloudShell:  bash cleanup_all.sh
set -u
REGION="${CF_REGION:-ap-southeast-2}"
FUNC=LeastPrivDashboard
TESTER=LeastPrivTesterRole
BACKEND=LeastPrivBackendRole
TEST_USER=hackathon-admin

aws() { command aws --region "$REGION" "$@"; }
ACCT=$(aws sts get-caller-identity --query Account --output text 2>/dev/null) \
  || { echo "Cannot reach AWS. Run this inside CloudShell."; exit 1; }
BUCKET="lp-demo-$ACCT"

echo "This permanently deletes: Lambda $FUNC, roles $BACKEND and $TESTER,"
echo "bucket $BUCKET (and its files) and the test user $TEST_USER."
read -r -p "Type DELETE to continue: " CONFIRM
[ "$CONFIRM" = "DELETE" ] || { echo "Cancelled. Nothing was deleted."; exit 1; }

run() {
  echo "- $*"
  if "$@" >/dev/null 2>&1; then echo "    removed"; else echo "    skipped (not found / already gone)"; fi
}

echo; echo "== Removing resources"
run aws lambda delete-function-url-config --function-name "$FUNC"
run aws lambda delete-function --function-name "$FUNC"
run aws logs delete-log-group --log-group-name "/aws/lambda/$FUNC"
run aws iam delete-role-policy --role-name "$BACKEND" --policy-name BackendMinimal
run aws iam delete-role --role-name "$BACKEND"
run aws iam delete-role-policy --role-name "$TESTER" --policy-name ReadOneBucketOnly
run aws iam delete-role --role-name "$TESTER"
run aws s3 rm "s3://$BUCKET" --recursive
run aws s3api delete-bucket --bucket "$BUCKET"

echo; echo "== Removing the unused test user ($TEST_USER)"
for id in $(aws iam list-service-specific-credentials --user-name "$TEST_USER" \
            --query 'ServiceSpecificCredentials[].ServiceSpecificCredentialId' --output text 2>/dev/null); do
  run aws iam delete-service-specific-credential --user-name "$TEST_USER" --service-specific-credential-id "$id"
done
for key in $(aws iam list-access-keys --user-name "$TEST_USER" \
            --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null); do
  run aws iam delete-access-key --user-name "$TEST_USER" --access-key-id "$key"
done
run aws iam detach-user-policy --user-name "$TEST_USER" --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
run aws iam delete-user --user-name "$TEST_USER"

echo; echo "== Verifying (each line should say gone)"
chk() { if "${@:2}" >/dev/null 2>&1; then echo "  STILL EXISTS: $1"; else echo "  gone: $1"; fi; }
chk "Lambda $FUNC"        aws lambda get-function --function-name "$FUNC"
chk "Role $BACKEND"       aws iam get-role --role-name "$BACKEND"
chk "Role $TESTER"        aws iam get-role --role-name "$TESTER"
chk "Bucket $BUCKET"      aws s3api head-bucket --bucket "$BUCKET"
chk "User $TEST_USER"     aws iam get-user --user-name "$TEST_USER"
echo; echo "Cleanup finished."
