#!/bin/bash
set -uo pipefail

TEMP_FILE="apnic_delegated_stats.txt"
SERVICE_DESCRIPTION="China_Access"
RESTRICTED_PORTS_FILE="restricted_ports.txt"
CHINA_IPS_FILE="china_ips.txt"

INTERNAL_RANGES=(
    "10.0.0.0/8"
    "172.16.0.0/12"
    "192.168.0.0/16"
    "127.0.0.0/8"
)

BACKUP_RULES_FILE="/tmp/ufw_backup_$(date +%s).rules"

cleanup_on_error() {
    echo "检测到错误，正在回滚..."
    if [[ -f "$BACKUP_RULES_FILE" ]]; then
        echo "恢复 UFW 规则..."
        sudo ufw --force disable
        sudo ufw default deny incoming
        sudo ufw default allow outgoing
    fi
    echo "回滚完成，脚本退出"
    exit 1
}

trap cleanup_on_error ERR INT TERM

validate_ip_cidr() {
    local ip=$1
    [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]
}

validate_port() {
    local port=$1
    if [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )); then
        return 0
    fi
    [[ "$port" =~ ^[0-9]+:[0-9]+$ ]]
}

is_internal_ip() {
    local ip=$1
    local ip_num
    ip_num=$(echo "$ip" | awk -F'/' '{print $1}')
    ip_num=$(printf '%d\n' "$(echo "$ip_num" | awk -F'.' '{print $1*256^3 + $2*256^2 + $3*256 + $4}')")

    for range in "${INTERNAL_RANGES[@]}"; do
        local network cidr mask start end
        network=$(echo "$range" | awk -F'/' '{print $1}')
        cidr=$(echo "$range" | awk -F'/' '{print $2}')
        mask=$((0xFFFFFFFF << (32 - cidr)) )
        start=$(printf '%d\n' "$(echo "$network" | awk -F'.' '{print $1*256^3 + $2*256^2 + $3*256 + $4}')")
        start=$((start & mask))
        end=$((start | (0xFFFFFFFF - mask)))

        (( ip_num >= start && ip_num <= end )) && return 0
    done
    return 1
}

save_ufw_policy() {
    echo "备份当前 UFW 规则..."
    sudo ufw status numbered > "$BACKUP_RULES_FILE" 2>&1 || true
    sudo ufw status > ufw.policy 2>&1

    [[ -f "ufw.policy" ]] || { echo "备份失败"; exit 1; }

    echo "提取 UFW 规则端口..."
    grep -i "allow" ufw.policy | awk -F' ' '{print $1}' | grep -v "^$" | sort -u > restricted_ports.tmp
    mv restricted_ports.tmp restricted_ports.txt
    echo "规则备份完成"
}

validate_port_file() {
    echo "验证端口文件..."

    [[ -f "$RESTRICTED_PORTS_FILE" ]] || { echo "错误: 缺少 $RESTRICTED_PORTS_FILE"; exit 1; }
    [[ -s "$RESTRICTED_PORTS_FILE" ]] || { echo "错误: $RESTRICTED_PORTS_FILE 文件为空"; exit 1; }

    sort -u -o "$RESTRICTED_PORTS_FILE" "$RESTRICTED_PORTS_FILE"
    echo "端口文件验证成功 (已去重)"
}

parse_port_entry() {
    local entry=$1 protocol port_range
    IFS='/' read -r port_range protocol <<< "$entry"
    protocol=${protocol:-tcp}

    [[ "$protocol" == "tcp" || "$protocol" == "udp" ]] || { echo "错误: $entry 使用无效协议: $protocol" >&2; return 1; }
    validate_port "$port_range" || { echo "错误: $entry 端口格式无效" >&2; return 1; }

    echo "$port_range/$protocol"
}

load_ports() {
    local ports=()
    while IFS= read -r line || [[ -n "$line" ]]; do
        local trimmed=$(echo "$line" | xargs)
        [[ -z "$trimmed" || "$trimmed" == \#* ]] && continue

        if parsed=$(parse_port_entry "$trimmed"); then
            ports+=("$parsed")
        else
            exit 1
        fi
    done < "$RESTRICTED_PORTS_FILE"

    (( ${#ports[@]} == 0 )) && { echo "错误: 没有找到有效端口配置" >&2; exit 1; }
    echo "${ports[@]}"
}

detect_internal_ports() {
    echo "检测已绑定内网的端口..."

    local internal_ports=()
    local ufw_output
    ufw_output=$(sudo ufw status numbered 2>/dev/null) || return

    for range in "${INTERNAL_RANGES[@]}"; do
        local network
        network=$(echo "$range" | awk -F'/' '{print $1}')
        local found_ports
        found_ports=$(echo "$ufw_output" | grep -i "allow" | grep "$network" | awk '{print $8}' | grep -oE '[0-9]+' | sort -u)

        if [[ -n "$found_ports" ]]; then
            while read -r port; do
                internal_ports+=("$port/tcp")
            done <<< "$found_ports"
        fi
    done

    if (( ${#internal_ports[@]} > 0 )); then
        echo "以下端口已限制内网，将跳过中国IP限制:"
        printf '   %s\n' "${internal_ports[@]}"
    else
        echo "未检测到内网限制端口"
    fi

    printf '%s\n' "${internal_ports[*]}"
}

get_china_ips() {
    echo "正在从 APNIC 下载并解析中国IP段..."

    local max_retries=3
    local retry=0

    while (( retry < max_retries )); do
        if wget --timeout=30 --tries=2 -qO - "https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest" 2>/dev/null | \
            awk -F'|' '/CN.*ipv4/ {print $4 "/" 32-log($5)/log(2)}' > "$CHINA_IPS_FILE" 2>/dev/null; then
            break
        fi
        ((retry++))
        echo "下载失败，尝试重试 ($retry/$max_retries)..."
        sleep 2
    done

    (( retry == max_retries )) && { echo "错误: 无法下载 APNIC 数据"; exit 1; }

    local count
    count=$(wc -l < "$CHINA_IPS_FILE")
    echo "获取到 $count 个中国IP段"
}

rule_exists() {
    local ip=$1 port=$2 protocol=$3
    local check_output
    check_output=$(sudo ufw status numbered 2>/dev/null) || return 1
    echo "$check_output" | grep -qi "allow.*from.*$ip.*port.*$port.*$protocol"
}

apply_single_rule() {
    local ip=$1 port_spec=$2 protocol=$3
    local port_num=${port_spec%%/*}

    if rule_exists "$ip" "$port_num" "$protocol"; then
        echo "   规则已存在，跳过"
        return 0
    fi

    echo "   添加规则: $ip -> port $port_num/$protocol"
    sudo ufw allow proto "$protocol" from "$ip" to any port "$port_num" comment "$SERVICE_DESCRIPTION" >/dev/null 2>&1
}

apply_rules_for_ip_and_ports() {
    local internal_ports
    internal_ports=$(detect_internal_ports)

    local internal_arr=()
    if [[ -n "$internal_ports" ]]; then
        IFS=' ' read -ra internal_arr <<< "$internal_ports"
    fi

    local ip_ranges
    mapfile -t ip_ranges < <(get_china_ips)

    local port_specs
    IFS=' ' read -ra port_specs <<< "$(load_ports)"

    local total_ips=${#ip_ranges[@]}
    local total_ports=${#port_specs[@]}
    local total_rules=$((total_ips * total_ports))
    local current_rule=0

    echo "将添加约 $total_rules 条规则 (IP段: $total_ips x 端口: $total_ports)"

    for ip in "${ip_ranges[@]}"; do
        validate_ip_cidr "$ip" || { echo "   跳过无效IP: $ip"; continue; }
        is_internal_ip "$ip" && { echo "   跳过内网IP: $ip"; continue; }

        for port_spec in "${port_specs[@]}"; do
            ((current_rule++))

            local port=${port_spec%%/*}
            local protocol=${port_spec##*/}
            local port_with_proto="$port/$protocol"

            local skip=false
            for internal in "${internal_arr[@]}"; do
                [[ "$internal" == "$port_with_proto" ]] && { skip=true; break; }
            done
            [[ "$skip" == "true" ]] && continue

            (( current_rule % 100 == 0 )) && echo "   进度: $current_rule / $total_rules"

            apply_single_rule "$ip" "$port" "$protocol"
        done
    done

    echo "完成 $current_rule 条规则添加"
}

apply_rule() {
    local port=$1 action=$2 from=$3
    local protocol=${port##*/}
    local port_spec=${port%%/*}

    if [[ "$from" == *"Anywhere"* ]]; then
        if [[ "$port" != *"(v6)"* ]]; then
            sudo ufw "$action" "$port_spec/$protocol" comment "$SERVICE_DESCRIPTION" >/dev/null 2>&1 || true
        fi
        if [[ "$port" == *"(v6)"* ]]; then
            sudo ufw "$action" "$port_spec/$protocol" comment "$SERVICE_DESCRIPTION" v6 >/dev/null 2>&1 || true
        fi
    else
        echo "   跳过复杂规则 (仅支持 Anywhere): $port $action $from"
    fi
}

restore_ufw_rules() {
    local POLICY_FILE="ufw.policy"
    SERVICE_DESCRIPTION="Custom_Rules"

    [[ -f "$POLICY_FILE" ]] || { echo "错误: 文件 $POLICY_FILE 不存在"; exit 1; }

    echo "恢复 UFW 规则..."

    awk 'NR>2 {print}' "$POLICY_FILE" | while read -r line; do
        to=$(echo "$line" | awk '{print $1}')
        action=$(echo "$line" | awk '{print tolower($2)}')
        from=$(echo "$line" | awk '{$1=$2=""; print substr($0,3)}')
        apply_rule "$to" "$action" "$from"
    done

    sudo ufw reload
    echo "规则恢复完成"
}

main() {
    echo "======================================"
    echo "   UFW 防火墙优化脚本 V1.1.0"
    echo "======================================"
    echo ""
    echo "1. 禁止所有非中国IP连接"
    echo "2. 恢复 UFW 规则为默认初始值"
    echo "======================================"
    echo ""

    read -p "请输入数字选项 1 或 2: " XUANXIANG

    case ${XUANXIANG} in
        1)
            echo ""
            echo "开始执行选项 1..."
            save_ufw_policy
            validate_port_file

            echo ""
            echo "配置 UFW 默认策略..."
            sudo ufw default deny incoming
            sudo ufw default allow outgoing

            echo ""
            apply_rules_for_ip_and_ports

            echo ""
            echo "启用 UFW..."
            sudo ufw --force enable
            sudo ufw status verbose

            rm -f "$TEMP_FILE"

            echo ""
            echo "======================================"
            echo "配置完成！"
            echo "======================================"
            ;;
        2)
            echo ""
            echo "开始执行选项 2..."
            restore_ufw_rules

            echo ""
            echo "======================================"
            echo "规则恢复完成！"
            echo "======================================"
            ;;
        *)
            echo "无效选项，请输入 1 或 2"
            exit 1
            ;;
    esac
}

main "$@"