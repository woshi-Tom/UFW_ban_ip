#!/bin/bash
set -uo pipefail

export LC_ALL=C.UTF-8
export LANG=C.UTF-8

RESTRICTED_PORTS_FILE="restricted_ports.txt"
CHINA_IPS_FILE="china_ips.txt"

REGION_CODE="CN"
REGION_NAME="中国"

INTERNAL_RANGES=(
    "10.0.0.0/8"
    "172.16.0.0/12"
    "192.168.0.0/16"
    "127.0.0.0/8"
)

declare -A REGIONS=(
    [CN]="中国"
    [IN]="印度"
    [RU]="俄罗斯"
    [US]="美国"
    [JP]="日本"
    [KR]="韩国"
    [BR]="巴西"
    [ID]="印度尼西亚"
)

ADDED_RULES_FILE="/tmp/ufw_added_rules_$$.txt"
POLICY_BACKUP="ufw.policy"
DRY_RUN="false"

check_whiptail() {
    if ! command -v whiptail &>/dev/null; then
        echo "错误: 未找到 whiptail，请安装: apt-get install whiptail"
        exit 1
    fi
}

cleanup_on_error() {
    echo ""
    echo "检测到错误，开始回滚..."

    if [[ -f "$ADDED_RULES_FILE" && -s "$ADDED_RULES_FILE" ]]; then
        echo "删除添加的规则..."

        while IFS= read -r rule_num; do
            if [[ -n "$rule_num" ]]; then
                echo "   删除规则 #$rule_num"
                sudo ufw delete "$rule_num" >/dev/null 2>&1 || true
            fi
        done < "$ADDED_RULES_FILE"

        rm -f "$ADDED_RULES_FILE"
    fi

    if [[ -f "$POLICY_BACKUP" ]]; then
        echo "尝试恢复原始规则..."
        restore_ufw_rules
    fi

    whiptail --title "回滚完成" --msgbox "错误已处理\n\n已删除新添加的规则\n并尝试恢复到原始状态\n\n建议检查 UFW 状态: sudo ufw status" 12 45

    exit 1
}

cleanup_exit() {
    rm -f "$ADDED_RULES_FILE" "/tmp/ufw_added_count_$$.txt"
    exit 0
}

trap cleanup_exit INT TERM

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

    if sudo ufw export > "$POLICY_BACKUP" 2>/dev/null; then
        echo "备份完成 (ufw export 格式)"
    else
        sudo ufw status > "$POLICY_BACKUP" 2>&1
        echo "备份完成 (ufw status 格式)"
    fi

    [[ -f "$POLICY_BACKUP" ]] || { whiptail --title "错误" --msgbox "备份失败!" 8 20; exit 1; }

    grep -i "allow" "$POLICY_BACKUP" | grep -v "^Status:" | awk -F' ' '{print $1}' | grep -v "^$" | sort -u > restricted_ports.tmp
    mv restricted_ports.tmp restricted_ports.txt
    echo "端口提取完成"
}

validate_port_file() {
    [[ -f "$RESTRICTED_PORTS_FILE" ]] || { whiptail --title "错误" --msgbox "错误: 缺少 $RESTRICTED_PORTS_FILE" 8 30; exit 1; }
    [[ -s "$RESTRICTED_PORTS_FILE" ]] || { whiptail --title "错误" --msgbox "错误: 端口文件为空\n\n请先配置 UFW 允许规则" 8 35; exit 1; }
    sort -u -o "$RESTRICTED_PORTS_FILE" "$RESTRICTED_PORTS_FILE"
}

parse_port_entry() {
    local entry=$1 protocol port_range
    IFS='/' read -r port_range protocol <<< "$entry"
    protocol=${protocol:-tcp}
    [[ "$protocol" == "tcp" || "$protocol" == "udp" ]] || return 1
    validate_port "$port_range" || return 1
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
    (( ${#ports[@]} == 0 )) && { whiptail --title "错误" --msgbox "错误: 没有有效端口配置" 8 30; exit 1; }
    echo "${ports[@]}"
}

detect_internal_ports() {
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
    printf '%s\n' "${internal_ports[@]}"
}

is_internal_network() {
    local ip_or_range=$1
    local ip_network
    ip_network=$(echo "$ip_or_range" | awk -F'/' '{print $1}')

    for range in "${INTERNAL_RANGES[@]}"; do
        local network cidr
        network=$(echo "$range" | awk -F'/' '{print $1}')
        cidr=$(echo "$range" | awk -F'/' '{print $2}')

        local network_num ip_num mask start end
        network_num=$(printf '%d\n' "$(echo "$network" | awk -F'.' '{print $1*256^3 + $2*256^2 + $3*256 + $4}')")
        ip_num=$(printf '%d\n' "$(echo "$ip_network" | awk -F'.' '{print $1*256^3 + $2*256^2 + $3*256 + $4}')")
        mask=$((0xFFFFFFFF << (32 - cidr)))
        start=$((network_num & mask))
        end=$((start | (0xFFFFFFFF - mask)))

        if (( ip_num >= start && ip_num <= end )); then
            return 0
        fi
    done
    return 1
}

detect_specific_ip_rules() {
    local ufw_output
    ufw_output=$(sudo ufw status numbered 2>/dev/null) || return

    local skip_ports=()
    local ask_ports=()

    while IFS= read -r line; do
        if echo "$line" | grep -qi "allow"; then
            local from_field port_field
            from_field=$(echo "$line" | awk '{print $6}')
            port_field=$(echo "$line" | awk '{print $8}')

            if [[ "$from_field" != "Anywhere" && -n "$port_field" ]]; then
                local port_num
                port_num=$(echo "$port_field" | grep -oE '^[0-9]+')
                [[ -z "$port_num" ]] && continue

                if is_internal_network "$from_field"; then
                    skip_ports+=("$port_num/tcp (内网)")
                else
                    ask_ports+=("$port_num/tcp from $from_field")
                fi
            fi
        fi
    done <<< "$ufw_output"

    if (( ${#skip_ports[@]} > 0 )); then
        echo "以下端口已有内网规则，自动跳过:"
        printf '   %s\n' "${skip_ports[@]}"
    fi

    if (( ${#ask_ports[@]} > 0 )); then
        echo "以下端口已有特定IP规则:"
        printf '   %s\n' "${ask_ports[@]}"
        echo ""
        whiptail --title "特定IP规则" --msgbox "检测到以下端口已有特定IP来源规则:\n\n$(printf '%s\n' "${ask_ports[@]}")\n\n这些端口将跳过区域限制" 15 50
    fi

    local all_skip=("${skip_ports[@]}" "${ask_ports[@]}")
    printf '%s\n' "${all_skip[@]}"
}

cleanup_universal_rules() {
    whiptail --title "清理规则" --infobox "正在清理旧的 '允许任意访问' 规则...\n\n这些规则将被新的区域限制规则替代" 8 40

    local ufw_output
    ufw_output=$(sudo ufw status numbered 2>/dev/null) || return

    local rule_nums=()
    while IFS= read -r line; do
        local rule_num from_field
        rule_num=$(echo "$line" | grep -oE '^\[[0-9]+\]' | grep -oE '[0-9]+')
        from_field=$(echo "$line" | awk '{print $6}')

        if [[ -n "$rule_num" && "$from_field" == "Anywhere" ]]; then
            local comment
            comment=$(echo "$line" | grep -oE '\[.*\]' | tail -1)
            if [[ -z "$comment" || ! "$comment" =~ \[.*\] ]]; then
                rule_nums+=("$rule_num")
            fi
        fi
    done <<< "$ufw_output"

    local deleted_count=0
    if (( ${#rule_nums[@]} > 0 )); then
        for (( i=${#rule_nums[@]}-1; i>=0; i-- )); do
            if [[ "$DRY_RUN" == "true" ]]; then
                echo "[DRY-RUN] ufw delete #${rule_nums[i]} (Anywhere)" >&2
            else
                sudo ufw delete "${rule_nums[i]}" >/dev/null 2>&1 || true
            fi
            ((deleted_count++))
        done

        if (( deleted_count > 0 )); then
            whiptail --title "清理完成" --msgbox "✓ 已清理 $deleted_count 条旧规则\n\n这些规则已被新的区域限制规则替代" 8 25
        fi
    fi
}

get_region_ips() {
    local cache_file="/tmp/ufw_ip_cache_${REGION_CODE}.txt"
    local cache_ttl=604800  # 7天 (秒)

    # 检查缓存是否有效
    if [[ -f "$cache_file" && -s "$cache_file" ]]; then
        local cache_age
        cache_age=$(( $(date +%s) - $(stat -c %Y "$cache_file" 2>/dev/null || stat -f %m "$cache_file" 2>/dev/null || echo 0) ))
        if (( cache_age < cache_ttl )); then
            cat "$cache_file"
            return 0
        fi
    fi

    # 缓存过期或不存在，重新下载
    whiptail --title "下载数据" --infobox "正在下载 $REGION_NAME IP 数据...\n\n首次或缓存过期需要联网获取" 8 40

    local max_retries=3
    local retry=0
    while (( retry < max_retries )); do
        if wget --timeout=30 --tries=2 -qO - "https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest" 2>/dev/null | \
            awk -F'|' "/${REGION_CODE}.*ipv4/ {print \$4 \"/\" 32-log(\$5)/log(2)}" > "$cache_file" 2>/dev/null; then
            # 同时写入工作目录供后续参考
            cp "$cache_file" "$CHINA_IPS_FILE" 2>/dev/null || true
            cat "$cache_file"
            return 0
        fi
        ((retry++))
    done
    (( retry == max_retries )) && { whiptail --title "错误" --msgbox "错误: 无法下载 APNIC 数据\n\n请检查网络连接" 8 40; exit 1; }
}

rule_exists() {
    local ip=$1 port=$2 protocol=$3
    local check_output
    check_output=$(sudo ufw status numbered 2>/dev/null) || return 1
    local ip_escaped
    ip_escaped=$(echo "$ip" | sed 's/\./\\./g; s/\//\\\//g')
    echo "$check_output" | grep -qi "allow.*from.*${ip_escaped}[^0-9]*port[^0-9]*${port}[^0-9].*${protocol}"
}

get_last_rule_number() {
    sudo ufw status numbered 2>/dev/null | tail -1 | grep -oE '^\[[0-9]+\]' | grep -oE '[0-9]+'
}

apply_single_rule() {
    local ip=$1 port_spec=$2 protocol=$3
    local port_num=${port_spec%%/*}

    if rule_exists "$ip" "$port_num" "$protocol"; then
        return 0
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        echo "[DRY-RUN] ufw allow proto $protocol from $ip to any port $port_num comment $REGION_NAME" >&2
        return 0
    fi

    local before_count
    before_count=$(get_last_rule_number || echo "0")

    sudo ufw allow proto "$protocol" from "$ip" to any port "$port_num" comment "$REGION_NAME" >/dev/null 2>&1

    local after_count
    after_count=$(get_last_rule_number || echo "0")

    if (( after_count > before_count )); then
        echo "$after_count" >> "$ADDED_RULES_FILE"
    fi
}

apply_rules_for_ip_and_ports() {
    local internal_arr=()
    mapfile -t internal_arr < <(detect_internal_ports)
    [[ ${#internal_arr[@]} -eq 1 && -z "${internal_arr[0]}" ]] && internal_arr=()

    local specific_arr=()
    mapfile -t specific_arr < <(detect_specific_ip_rules)
    [[ ${#specific_arr[@]} -eq 1 && -z "${specific_arr[0]}" ]] && specific_arr=()

    local ip_ranges
    mapfile -t ip_ranges < <(get_region_ips)

    local port_specs
    IFS=' ' read -ra port_specs <<< "$(load_ports)"

    local total_ips=${#ip_ranges[@]}
    local total_ports=${#port_specs[@]}
    local added_count_file="/tmp/ufw_added_count_$$.txt"
    echo "0" > "$added_count_file"

    # 预计算实际需要处理的端口数（排除被跳过的）
    local active_ports=()
    for port_spec in "${port_specs[@]}"; do
        local port=${port_spec%%/*}
        local protocol=${port_spec##*/}
        local port_with_proto="$port/$protocol"
        local skip=false
        for internal in "${internal_arr[@]}"; do
            [[ "$internal" == "$port_with_proto" ]] && { skip=true; break; }
        done
        if [[ "$skip" == "false" ]]; then
            for specific in "${specific_arr[@]}"; do
                local spec_proto="${specific%% *}"
                [[ "$spec_proto" == "$port_with_proto" ]] && { skip=true; break; }
            done
        fi
        [[ "$skip" == "false" ]] && active_ports+=("$port_spec")
    done

    local active_count=${#active_ports[@]}
    local total_rules=$((total_ips * active_count))
    (( total_rules == 0 )) && total_rules=1

    (
    local current_rule=0
    for ip in "${ip_ranges[@]}"; do
        validate_ip_cidr "$ip" || continue
        is_internal_ip "$ip" && continue

        for port_spec in "${active_ports[@]}"; do
            ((current_rule++))

            local port=${port_spec%%/*}
            local protocol=${port_spec##*/}

            local pct=$(( current_rule * 100 / total_rules ))
            echo "$pct"
            apply_single_rule "$ip" "$port" "$protocol"
        done
    done
    echo "$current_rule" > "$added_count_file"
    ) | whiptail --title "添加规则" --gauge "正在添加 $REGION_NAME IP 访问规则...\n\n进度: 0%" 8 60 0

    local added_count
    added_count=$(<"$added_count_file")
    rm -f "$added_count_file"

    local action_word="添加"
    [[ "$DRY_RUN" == "true" ]] && action_word="预览"

    whiptail --title "完成" --msgbox "规则${action_word}完成!\n\n共${action_word} $added_count 条规则\n\n已跳过已有特定IP规则的端口" 10 35
}

restore_ufw_rules() {
    [[ -f "$POLICY_BACKUP" ]] || { whiptail --title "错误" --msgbox "错误: 备份文件不存在" 8 25; return 1; }

    if [[ "$DRY_RUN" == "true" ]]; then
        whiptail --title "预览" --msgbox "预览模式: 跳过规则恢复操作\n\n备份文件: $POLICY_BACKUP" 8 35
        return 0
    fi

    if grep -q "^# Generated by iptables-restore" "$POLICY_BACKUP" 2>/dev/null; then
        if sudo ufw disable >/dev/null 2>&1; then
            if sudo ufw import < "$POLICY_BACKUP" 2>/dev/null; then
                sudo ufw enable >/dev/null 2>&1
                whiptail --title "完成" --msgbox "规则恢复完成!\n\n(ufw import 方式)" 8 25
                return 0
            fi
        fi
    fi

    sudo ufw disable >/dev/null 2>&1

    local in_rule_section=false
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" =~ ^Status: ]] && { in_rule_section=true; continue; }
        [[ "$line" =~ ^[[:space:]]*$ ]] && continue
        if [[ "$in_rule_section" == "true" && "$line" =~ ^[0-9]+ ]]; then
            local to from action
            to=$(echo "$line" | awk '{print $8}' | grep -oE '^([0-9]+|[0-9]+:[0-9]+)')
            action=$(echo "$line" | awk '{print $3}')
            from=$(echo "$line" | awk '{print $6}')
            if [[ -n "$to" && -n "$action" ]]; then
                local protocol="tcp"
                local port_spec="$to"
                if [[ "$from" == *"(v6)"* || "$from" == *"Anywhere (IPv6)"* ]]; then
                    sudo ufw "$action" "$port_spec/$protocol" comment "Restore" v6 >/dev/null 2>&1 || true
                else
                    sudo ufw "$action" "$port_spec/$protocol" comment "Restore" >/dev/null 2>&1 || true
                fi
            fi
        fi
    done < "$POLICY_BACKUP"

    sudo ufw enable >/dev/null 2>&1
    whiptail --title "完成" --msgbox "规则恢复完成!" 8 25
}

show_welcome() {
    local mode_info=""
    if [[ "$DRY_RUN" == "true" ]]; then
        mode_info="\n\n⚠ 预览模式: 不会实际修改防火墙"
    fi
    whiptail --title "UFW 防火墙优化脚本 V1.3.1" --msgbox "欢迎使用 UFW 防火墙优化脚本\n\n本脚本可以:\n• 设置防火墙规则 (限制特定国家IP访问)\n• 恢复原有UFW规则\n• 智能错误回滚\n\n版本: 1.3.1 (TUI版)${mode_info}" 14 45
}

select_main_option() {
    local choice
    choice=$(whiptail --title "主菜单" --menu "请选择操作:" 15 45 4 \
        "1" "设置防火墙规则" \
        "2" "恢复原有规则" \
        "3" "查看当前UFW状态" \
        "4" "退出" 3>&1 1>&2 2>&3)
    echo "$choice"
}

select_region_tui() {
    local menu_items=()
    for code in "${!REGIONS[@]}"; do
        menu_items+=("$code" "${REGIONS[$code]}")
    done

    local choice
    choice=$(whiptail --title "选择区域" --menu "请选择要允许访问的国家/地区:\n(仅该区域IP可访问服务，其他IP将被拒绝)" 18 45 8 \
        "${menu_items[@]}" 3>&1 1>&2 2>&3)

    if [[ -n "$choice" && -n "${REGIONS[$choice]}" ]]; then
        REGION_CODE="$choice"
        REGION_NAME="${REGIONS[$choice]}"
        whiptail --title "确认" --yesno "已选择: $REGION_NAME\n\n将只允许 $REGION_NAME 的IP访问指定端口\n其他国家的IP将被拒绝\n\n确认继续?" 12 40
        return $?
    else
        whiptail --title "提示" --msgbox "已取消选择" 8 25
        return 1
    fi
}

show_ufw_status() {
    local status
    status=$(sudo ufw status verbose 2>&1)
    whiptail --title "UFW 状态" --msgbox "$status" 25 70
}

main() {
    for arg in "$@"; do
        case "$arg" in
            --dry-run) DRY_RUN="true" ;;
        esac
    done

    check_whiptail
    show_welcome

    while true; do
        local choice
        choice=$(select_main_option)

        case "$choice" in
            1)
                if ! select_region_tui; then
                    continue
                fi

                whiptail --title "正在备份" --infobox "正在备份当前 UFW 规则...\n\n请稍候..." 8 35
                save_ufw_policy

                whiptail --title "备份成功" --msgbox "✓ 备份完成!\n\n备份文件: $POLICY_BACKUP\n\n点击 '确定' 继续..." 10 40

                validate_port_file

                trap cleanup_on_error ERR
                apply_rules_for_ip_and_ports

                cleanup_universal_rules

                if [[ "$DRY_RUN" != "true" ]]; then
                    sudo ufw default deny incoming
                    sudo ufw default allow outgoing
                    sudo ufw --force enable
                else
                    echo "[DRY-RUN] ufw default deny incoming" >&2
                    echo "[DRY-RUN] ufw default allow outgoing" >&2
                    echo "[DRY-RUN] ufw --force enable" >&2
                fi
                trap - ERR

                rm -f "$ADDED_RULES_FILE"

                if [[ "$DRY_RUN" == "true" ]]; then
                    whiptail --title "预览完成" --msgbox "预览模式完成!\n\n允许区域: $REGION_NAME\n\n以上为预览输出，未实际修改防火墙" 10 40
                else
                    whiptail --title "完成" --msgbox "✓ 配置完成!\n\n允许区域: $REGION_NAME\n默认策略: 拒绝所有入站\n\n如需恢复，运行 '恢复原有规则'" 10 40
                fi
                ;;
            2)
                if whiptail --title "恢复规则" --yesno "确定要恢复原有 UFW 规则吗?\n\n将从 $POLICY_BACKUP 文件恢复规则" 10 40; then
                    restore_ufw_rules
                fi
                ;;
            3)
                show_ufw_status
                ;;
            4|"")
                whiptail --title "退出" --msgbox "感谢使用!\n\n如有问题请提交 Issue" 8 25
                break
                ;;
            *)
                break
                ;;
        esac
    done
}

main "$@"