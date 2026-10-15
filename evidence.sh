#!/usr/bin/env bash
# Pulls AWS's own audit trail (CloudTrail) for the demo: who assumed the restricted
# role and which administrative calls were refused. Events appear 5-15 minutes
# after the dashboard/test run, so run this a little later.
set -u
REGION="${CF_REGION:-ap-southeast-2}"
for NAME in AssumeRole CreateUser DeleteBucket; do
  echo "== CloudTrail: $NAME"
  aws cloudtrail lookup-events --region "$REGION" --max-results 20 \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$NAME" \
    --query 'Events[].CloudTrailEvent' --output json 2>/dev/null | python3 -c '
import json, sys
try:
    events = [json.loads(e) for e in json.load(sys.stdin)]
except Exception:
    events = []
shown = 0
for e in events:
    who = (e.get("userIdentity") or {}).get("arn", "?")
    role = (e.get("requestParameters") or {}).get("roleArn", "")
    if "LeastPriv" not in who and "LeastPriv" not in role and "cloudforge" not in json.dumps(e.get("requestParameters"), default=str):
        continue
    print("  %s  %-12s by %s" % (e.get("eventTime"), e.get("eventName"), who))
    print("      result: %s" % (e.get("errorCode") or "Success"))
    if e.get("errorMessage"):
        print("      " + e["errorMessage"][:220])
    shown += 1
if not shown:
    print("  (nothing yet - CloudTrail can take up to 15 minutes)")
'
done
