#!/bin/bash
set -euo pipefail

TEMP_FILE="apnic_delegated_stats.txt"
SERVICE_DESCRIPTION="China_Access"
RESTRICTED_PORTS_FILE="restricted_ports.txt"

save_ufw_policy() {
    echo "备份当前ufw规则"
    sudo ufw status > ufw.policy 2>&1

    if [[ ! -f "ufw.policy" ]]; then
        echo "备份失败"
        exit 1
    fi

    echo "提取ufw规则端口"
    grep -i "allow" ufw.policy | awk -F' ' '{print $1}' > restricted_ports.txt

}


validate_port_file() {
    echo "验证端口文件..."
    if [[ ! -f "$RESTRICTED_PORTS_FILE" ]]; then
        echo "错误: 缺少 $RESTRICTED_PORTS_FILE"
        exit 1
    fi
    if [[ ! -s "$RESTRICTED_PORTS_FILE" ]]; then
        echo "错误: $RESTRICTED_PORTS_FILE 文件为空"
        exit 1
    fi
    echo "端口文件验证成功"
}

parse_port_entry() {
    local entry=$1 protocol port_range
    
    IFS='/' read -r port_range protocol <<< "$entry"
    protocol=${protocol:-tcp} # 默认协议为tcp
    
    if [[ "$protocol" != "tcp" && "$protocol" != "udp" ]]; then
        echo "错误：$entry 使用无效协议" >&2
        return 1
    fi

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
    
    (( ${#ports[@]} == 0 )) && { echo "错误：没有找到有效端口配置" >&2; exit 1; }
    echo "${ports[@]}"
}

get_china_ips() {
    echo "正在从APNIC下载并解析中国IP段..."
    wget -qO - "https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest" | awk -F\| '/CN\|ipv4/ {print $4 "/" 32-log($5)/log(2)}' > china_ips.txt
    cat china_ips.txt
}

apply_rules_for_ip_and_ports() {
    local ip_ranges=($(get_china_ips))
    IFS=$' ' read -ra RESTRICTED_PORTS <<< "$(load_ports)"
    
    for ip in "${ip_ranges[@]}"; do
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
            for port_spec in "${RESTRICTED_PORTS[@]}"; do
                echo "正在添加规则：允许来自 $ip 到任意地址的 ${port_spec%%/*} 端口 (协议: ${port_spec##*/}) 的访问 ($SERVICE_DESCRIPTION)"
                cmd="sudo ufw allow proto ${port_spec##*/} from $ip to any port ${port_spec%%/*} comment '$SERVICE_DESCRIPTION'"
                echo "执行命令: $cmd"
                eval "$cmd"
            done
        else
            echo "忽略无效IP段: $ip"
        fi
    done
}





apply_rule() {
    local port=$1
    local action=$2
    local from=$3
    local protocol=${port##*/}
    local port_spec=${port%%/*}
    
    if [[ "$from" == *"Anywhere"* ]]; then
        # 处理IPv4规则
        if [[ "$port" != *"(v6)"* ]]; then
            cmd="sudo ufw $action $port_spec/$protocol comment '$SERVICE_DESCRIPTION'"
            echo "执行命令: $cmd"
            eval "$cmd"
        fi
        # 处理IPv6规则
        if [[ "$port" == *"(v6)"* ]]; then
            cmd="sudo ufw $action $port_spec/$protocol comment '$SERVICE_DESCRIPTION' v6"
            echo "执行命令: $cmd"
            eval "$cmd"
        fi
    else
        # 如果有特定来源IP地址，则单独处理
        echo "忽略复杂规则（当前仅支持来自Anywhere的规则）: $port $action $from"
    fi
}


main() {

    echo "####################################"
    echo "1、ufw禁止所有非中国ip连接"
    echo "2、恢复ufw规则为默认初始值"
    echo "####################################"
    echo ''

    read -p  "请输入数字选项1或2，来启动相应的功能" XUANXIANG; 
    case ${XUANXIANG} in
        1 )
            save_ufw_policy
            validate_port_file
            sudo ufw default deny incoming
            sudo ufw default allow outgoing
    
            apply_rules_for_ip_and_ports
    
            sudo ufw --force enable
            sudo ufw status verbose
            rm -f "$TEMP_FILE"
            echo "配置完成"
        2 )
            POLICY_FILE="ufw.policy"
            SERVICE_DESCRIPTION="Custom_Rules"

            # 检查文件是否存在且可读
            if [ ! -f "$POLICY_FILE" ]; then
                echo "错误: 文件 $POLICY_FILE 不存在"
                exit 1
            fi


            # 解析策略文件并应用规则
            awk 'NR>2 {print}' "$POLICY_FILE" | while read -r line; do
                to=$(echo "$line" | awk '{print $1}')
                action=$(echo "$line" | awk '{print tolower($2)}')
                from=$(echo "$line" | awk '{$1=$2=""; print substr($0,3)}')

                apply_rule "$to" "$action" "$from"
            done

            # 刷新UFW以确保所有规则生效
            sudo ufw reload

            ;;
    esac


}

main
