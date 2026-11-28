# shellcheck shell=sh
# Sourced by scripts/acceptance-lib.sh: the stand-in for Stalwart that every
# test host runs on 127.0.0.1:8099. It uses the library's helpers.
stalwart_stand_in() {
    # A stand-in for Stalwart that knows one administrator token: subject 1, native
    # account b, role e. Any other token is invalid, as in production. With it the
    # broker authorizes a request as usual, so an action runs through polkit and
    # systemctl for real, and a sign-in's code exchange is answered with it, so
    # the web service makes a session, and notes each token whose revocation is
    # asked for in /root/stand-in-revoked. It also answers what `garrison stalwart setup` asks
    # and shows what it wrote, without the secrets: the API keys it makes with
    # their permissions in /root/stand-in-keys, refused while
    # /root/stand-in-refuses exists, its other objects in /root/stand-in-objects.
    inside_input 'cat > /root/stalwart-stub.sh' <<'STUB'
read -r method path rest
length=0
authorization=
while IFS= read -r line; do
    line=$(printf %s "$line" | tr -d '\r')
    [ -z "$line" ] && break
    case "$line" in
        [Cc]ontent-[Ll]ength:*) length=$(printf %s "${line#*:}" | tr -d ' ') ;;
        [Aa]uthorization:*) authorization=$(printf %s "${line#*:}" | sed 's/^ *//') ;;
    esac
done
body=$(head -c "$length")
answer=
status="200 OK"
# The form Stalwart 1.1.0 answers in: a list names its account, b, the
# administrator's own.
respond() {
    answer="{\"methodResponses\": [[\"$1\", {\"accountId\": \"b\", \"list\": [$2], \"notFound\": []}, \"0\"]], \"sessionState\": \"0\"}"
}
answered() { answer="{\"methodResponses\": [[\"$1\", $2, \"0\"]], \"sessionState\": \"0\"}"; }
rights() { printf %s "$body" | grep -o '"permissions":{"@type":"Replace","permissions":{[^}]*}}' || echo '"permissions":{}'; }
# The object a /set created or updated, under its kind.
keep() {
    set -- "$(printf %s "$body" | sed -n 's/.*\/set",{"[a-z]*":{"\([^"]*\)":{\(.*\)}}},"0"\]\]}$/\1 \2/p')"
    [ -n "$1" ] || return 0
    mkdir -p /root/stand-in-objects
    printf '{"id": "%s", %s}\n' "$(echo "${1%% *}" | sed "s/^new$/$kind-1/")" "${1#* }" |
        sed 's/,"signatureKey":{[^}]*}//; s/,"authSecret":{[^}]*}//' > "/root/stand-in-objects/$kind"
}
case "$method $path" in
    "GET /auth/userinfo")
        if [ "$authorization" = "Bearer acceptance-token-0123456789abcdef" ]; then
            answer='{"sub": "1", "email": "admin@example.test"}'
        else
            status="401 Unauthorized"
        fi ;;
    "POST /auth/token")
        answer='{"access_token": "acceptance-token-0123456789abcdef", "token_type": "Bearer", "expires_in": 600}' ;;
    "POST /auth/revoke")
        printf '%s\n' "$body" | sed -n 's/^token=\([^&]*\).*/\1/p' >> /root/stand-in-revoked ;;
    "GET /jmap/session")
        if [ -e /root/stand-in-refuses ]; then
            status="401 Unauthorized"
        else
            answer='{"primaryAccounts": {"urn:stalwart:jmap": "b"}}'
        fi ;;
    "POST /jmap/")
        call=$(printf %s "$body" | grep -o 'x:[A-Za-z]*/[a-z]*' | head -n 1)
        kind=${call#x:}; kind=${kind%/*}
        case "$body" in
            *x:Account/get*) respond x:Account/get '{"id": "b", "@type": "User", "memberTenantId": null,
                "roles": {"@type": "Custom", "roleIds": {"e": true}}, "permissions": {"@type": "Inherit"}}' ;;
            *x:Authentication/get*) respond x:Authentication/get \
                '{"id": "singleton", "defaultAdminRoleIds": {}, "defaultUserRoleIds": {}}' ;;
            *x:Role/get*) respond x:Role/get '{"id": "e", "roleIds": {}, "memberTenantId": null, "disabledPermissions": {},
                "enabledPermissions": {"authenticate": true, "sysActionCreate": true, "sysRoleUpdate": true}}' ;;
            *x:ApiKey/get*)
                respond "$call" "$(sed 's/^\([^ ]*\) \([^ ]*\) \(.*\)$/{"id": "\1", "description": "\3", "allowedIps": {"127.0.0.1": true, "::1": true}, "createdAt": "2026-11-24T00:00:00Z", "expiresAt": null, \2, "secret": "kept"}/' \
                    /root/stand-in-keys 2>/dev/null | paste -s -d , -)" ;;
            *x:ApiKey/set*'"create"'*)
                id=k$(date +%s%N)
                printf '%s %s %s\n' "$id" "$(rights)" "$(printf %s "$body" | sed -n 's/.*"description":"\([^"]*\)".*/\1/p')" \
                    >> /root/stand-in-keys
                answered "$call" "{\"created\": {\"new\": {\"id\": \"$id\", \"secret\": \"stand-in-$id-secret\"}}}" ;;
            *x:ApiKey/set*'"update"'*)
                id=$(printf %s "$body" | sed -n 's/.*"update":{"\([^"]*\)".*/\1/p')
                sed -i "s|^$id [^ ]* |$id $(rights) |" /root/stand-in-keys
                answered "$call" '{}' ;;
            *x:ApiKey/set*'"destroy"'*)
                for id in $(cut -d ' ' -f 1 /root/stand-in-keys); do
                    case $body in *"\"$id\""*) sed -i "/^$id /d" /root/stand-in-keys ;; esac
                done
                answered "$call" '{}' ;;
            *x:WebHook/get*) respond "$call" "$(cat /root/stand-in-objects/WebHook 2>/dev/null || echo '{"id": "w1", "httpHeaders": {"X-Garrison": "events"}}')" ;;
            # The milters a scenario puts in /root/stand-in-milters.
            *x:MtaMilter/get*) respond "$call" "$(cat /root/stand-in-milters 2>/dev/null)" ;;
            */get*) respond "$call" "$(cat "/root/stand-in-objects/$kind" 2>/dev/null)" ;;
            */set*) keep; answered "$call" '{}' ;;
        esac ;;
esac
printf 'HTTP/1.1 %s\r\nContent-Type: application/json\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' "$status" "${#answer}" "$answer"
STUB
    inside 'if command -v ncat >/dev/null 2>&1; then
            systemd-run --quiet --unit=acceptance-stalwart ncat -lk 127.0.0.1 8099 --sh-exec "sh /root/stalwart-stub.sh"
        else
            systemd-run --quiet --unit=acceptance-stalwart \
                socat TCP-LISTEN:8099,bind=127.0.0.1,reuseaddr,fork SYSTEM:"sh /root/stalwart-stub.sh"
        fi'
}
