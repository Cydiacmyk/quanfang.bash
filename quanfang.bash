#!/bin/bash
# 全防 quanfang v8.4 —— 精简版
set -u
R=$'\033[31m';G=$'\033[32m';Y=$'\033[33m';B=$'\033[34m';X=$'\033[0m'
o(){ printf '%s[+]%s %s\n' "$G" "$X" "$*"; }
w(){ printf '%s[!]%s %s\n' "$Y" "$X" "$*" >&2; }
e(){ printf '%s[拦]%s %s\n' "$R" "$X" "$*" >&2; }
g(){ printf '%s[i]%s %s\n' "$B" "$X" "$*"; }
BLACKLIST_FILE="${QUANFANG_BLOCK:-/etc/quanfang/block}"
if [[ ! -d "$(dirname "$BLACKLIST_FILE")" ]] || [[ ! -w "$(dirname "$BLACKLIST_FILE")" && ! -w "$BLACKLIST_FILE" ]]; then
BLACKLIST_FILE="${TMPDIR:-/tmp}/quanfang_block.$$"; fi
T="";FMT=plain;TRUST=0;BLK_OP="";BLK_VAL="";BLK_TAKEN=0
for a in "$@"; do
if (( BLK_TAKEN == 1 )); then BLK_TAKEN=2; BLK_VAL=$a; continue; fi
case "$a" in
--trust|-y) TRUST=1;;
--block|--block-add) BLK_OP=add;BLK_TAKEN=1;;
--block-add=*) BLK_OP=add;BLK_VAL=${a#--block-add=};;
--block-list|--block-list=*) BLK_OP=list;;
--block-del) BLK_OP=del;BLK_TAKEN=1;;
--block-del=*) BLK_OP=del;BLK_VAL=${a#--block-del=};;
--auto|--auto=plain|--auto=hex|--auto=b64) :;;
--auto=*) FMT=${a#--auto=};;
--*) w "忽略: $a";;
*) [[ -z $T && -z $BLK_OP ]] && T=$(readlink -f "$a");;
esac; done
cmd_blacklist_add(){ local p=${1:-$BLK_VAL}
[[ -z $p ]] && { w "用法: --block <路径|关键字>"; return 1; }
[[ -f $BLACKLIST_FILE ]] || printf '%s\n' '# quanfang' >"$BLACKLIST_FILE"
if grep -Fxq -- "$p" "$BLACKLIST_FILE" 2>/dev/null; then g "已存在: $p"
else printf '%s\n' "$p" >>"$BLACKLIST_FILE"; o "已加入黑名单: $p"; fi; }
cmd_blacklist_list(){ g "黑名单文件: $BLACKLIST_FILE"
if [[ -f $BLACKLIST_FILE ]]; then
local n=0; while IFS= read -r l||[[ -n $l ]]; do
[[ -z $l || $l == \#* ]] && continue; n=$((n+1)); printf '  %d  %s\n' "$n" "$l"
done <"$BLACKLIST_FILE"
(( n == 0 )) && g "(空)"; fi; }
cmd_blacklist_del(){ local p=$1
[[ -z $p ]] && { w "用法: --block-del=<关键字>"; return 1; }
[[ -f $BLACKLIST_FILE ]] || { w "黑名单为空"; return 1; }
if grep -Fxq -- "$p" "$BLACKLIST_FILE"; then
grep -Fxv -- "$p" "$BLACKLIST_FILE" >"$BLACKLIST_FILE.tmp" && mv "$BLACKLIST_FILE.tmp" "$BLACKLIST_FILE"
o "已移除: $p"; else w "未找到: $p"; fi; }
cmd_blacklist_check(){ local c=$1
[[ -f $BLACKLIST_FILE ]] || return 1
while IFS= read -r pat||[[ -n $pat ]]; do
[[ -z $pat || $pat == \#* ]] && continue
if [[ "$c" == *"$pat"* ]]; then HIT=$((HIT+1)); RISK=$((RISK+100))
w "命中黑名单: $pat"; return 0; fi
done <"$BLACKLIST_FILE"; return 1; }
match(){ local c=$1 lvl=0
local r1='rm[[:space:]]+-rf?[[:space:]]+/(etc|usr|bin|boot|root|var|dev|lib)'
local r2='rm[[:space:]]+-rf?[[:space:]]+/[[:space:]]*([*]|$)'
local r3='dd[[:space:]].*(of|if)=/dev/[a-zA-Z0-9]+'
local r4='(mkfs|wipefs|mkswap|fdisk|parted|sgdisk)'
local r5='(curl|wget|fetch)[^]|]*'
local r6='eval[[:space:]]'
local r7='\$\([^)]'
local r8='\$\([0-9a-zA-Z_$]'
local r9='`[^`]*`'
local r10='\|[[:space:]]*(base64|xxd|uudecode)[[:space:]]*-?d?[[:space:]]*[^|]*\|[[:space:]]*(bash|sh|eval|source|\.)'
local r11='/dev/(input|bus)/'
[[ $c =~ $r1 ]] && lvl=100
[[ $c =~ $r2 ]] && lvl=100
[[ $c =~ $r3 ]] && lvl=40
[[ $c =~ $r4 ]] && lvl=100
[[ $c =~ $r5 ]] && lvl=100
[[ $c =~ $r6 ]] && lvl=40
[[ $c =~ $r7 ]] && lvl=40
[[ $c =~ $r8 ]] && lvl=20
[[ $c =~ $r9 ]] && lvl=40
[[ $c =~ $r10 ]] && lvl=100
[[ $c =~ $r11 ]] && lvl=40
echo $lvl; }
scan(){ local f=$1 ln=0
while IFS= read -r line||[[ -n $line ]]; do ln=$((ln+1))
local c=${line%%#*}; [[ -z ${c//[[:space:]]/} ]] && continue
if cmd_blacklist_check "$c"; then RISK=$((RISK+100)); HIT=$((HIT+1)); continue; fi
if [[ $c =~ ^[[:print:]]+$ ]]; then
local lvl; lvl=$(match "$c")
if (( lvl > 0 )); then
RISK=$((RISK+lvl)); HIT=$((HIT+1))
[[ $lvl -eq 100 ]] && w "命中 L${ln} [c] 危险: ${c:0:60}" \
|| w "命中 L${ln} [u] 可疑: ${c:0:60}"
fi
else UNK=$((UNK+1)); w "命中 L${ln} 非文本(疑似编码)"; fi
done <"$f"
g "风险=$RISK 命中=$HIT 未知=$UNK"; }
decd(){ local s=$1 o=$2; : >"$o"
xxd -r -p "$s" >"$o" 2>/dev/null && [[ -s $o ]] && return 0
base64 -d "$s" >"$o" 2>/dev/null && [[ -s $o ]] && return 0
return 1; }
if [[ $BLK_OP == list ]]; then cmd_blacklist_list; exit 0; fi
if [[ $BLK_OP == del ]]; then
[[ -z $BLK_VAL && $BLK_TAKEN == 2 ]] && BLK_VAL=$2
cmd_blacklist_del "$BLK_VAL"; exit $?; fi
if [[ -n $BLK_OP ]]; then
[[ -z $BLK_VAL && $BLK_TAKEN == 2 ]] && BLK_VAL=$2
cmd_blacklist_add "$BLK_VAL"; exit $?; fi
[[ -n $T && -f $T ]] || { echo "用法: $0 <脚本> [--trust] [--auto=plain|hex|b64] [--block ...]"; exit 64; }
DEC="$T.decoded"; : >"$DEC"; RISK=0; HIT=0; UNK=0
case "$FMT" in
plain) cat "$T" >"$DEC";;
hex|b64) decd "$T" "$DEC" && scan "$DEC" >/dev/null || e "解码失败";;
*) cat "$T" >"$DEC";;
esac
[[ -s $DEC ]] || { e "无有效内容"; exit 1; }
scan "$DEC" >/dev/null
g "风险分=${RISK} 命中=${HIT}"
if (( HIT >= 1 )); then
e "发现拦截项, 未执行"
printf '%s[!]%s 复查: %s --auto=plain --trust %s\n' "$Y" "$X" "$0" "$T"
elif (( RISK > 0 )); then
e "风险分过高, 未执行 (需人工复核)"
else
o "扫描通过 (风险分=$RISK)"
if (( TRUST == 1 )); then bash "$T"; o "执行结束 (rc=$?)"
else g "确认执行? [y/N]"; read -r A
[[ $A == y || $A == Y ]] && bash "$T" && o "执行结束 (rc=$?)"
fi
fi
rm -f "$DEC"; exit 0
