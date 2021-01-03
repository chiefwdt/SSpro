#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

sh_ver="7.7.7"
filepath=$(cd "$(dirname "$0")"; pwd)
file=$(echo -e "${filepath}"|awk -F "$0" '{print $1}')
ssr_folder="/usr/local/shadowsocksr"
config_file="${ssr_folder}/config.json"
config_user_file="${ssr_folder}/user-config.json"
config_user_api_file="${ssr_folder}/userapiconfig.py"
config_user_mudb_file="${ssr_folder}/mudb.json"
ssr_log_file="${ssr_folder}/ssserver.log"
Libsodiumr_file="/usr/local/lib/libsodium.so"
Libsodiumr_ver_backup="1.0.15"
Server_Speeder_file="/serverspeeder/bin/serverSpeeder.sh"
LotServer_file="/appex/bin/serverSpeeder.sh"
BBR_file="${file}/bbr.sh"
jq_file="${ssr_folder}/jq"

Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[Информация]${Font_color_suffix}"
Error="${Red_font_prefix}[Ошибка]${Font_color_suffix}"
T="${Green_font_prefix}[Заметка]${Font_color_suffix}"
Separator_1="——————————————————————————————"


check_root(){
	[[ $EUID != 0 ]] && echo -e "${Error} Скрипт не запущен от root. Пропишите ${Green_background_prefix} sudo su ${Font_color_suffix} И перезапустите программу." && exit 1
}
check_sys(){
	if [[ -f /etc/redhat-release ]]; then
		release="centos"
	elif cat /etc/issue | grep -q -E -i "debian"; then
		release="debian"
	elif cat /etc/issue | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
	elif cat /proc/version | grep -q -E -i "debian"; then
		release="debian"
	elif cat /proc/version | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
    fi
	bit=`uname -m`
}
check_pid(){
	PID=`ps -ef |grep -v grep | grep server.py |awk '{print $2}'`
}
check_crontab(){
	[[ ! -e "/usr/bin/crontab" ]] && echo -e "${Error} Отсутствует crontab: для установки на CentOS пропишите yum install crond -y , Debian/Ubuntu: apt-get install cron -y !" && exit 1
}
SSR_installation_status(){
	[[ ! -e ${ssr_folder} ]] && echo -e "${Error} Не найден ShadowsocksR!" && exit 1
}
Server_Speeder_installation_status(){
	[[ ! -e ${Server_Speeder_file} ]] && echo -e "${Error} Server Speeder не установлен !" && exit 1
}
LotServer_installation_status(){
	[[ ! -e ${LotServer_file} ]] && echo -e "${Error} LotServer не установлен !" && exit 1
}
BBR_installation_status(){
	if [[ ! -e ${BBR_file} ]]; then
		echo -e "${Error} BBR не найден, начинаем скачивание..."
		cd "${file}"
		if ! wget -N --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/bbr.sh; then
			echo -e "${Error} Загрузка BBR прошла неуспешно !" && exit 1
		else
			echo -e "${Info} BBR успешно загружен !"
			chmod +x bbr.sh
		fi
	fi
}
# 设置 防火墙规则
Add_iptables(){
	if [[ ! -z "${ssr_port}" ]]; then
		iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ssr_port} -j ACCEPT
		iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${ssr_port} -j ACCEPT
		ip6tables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ssr_port} -j ACCEPT
		ip6tables -I INPUT -m state --state NEW -m udp -p udp --dport ${ssr_port} -j ACCEPT
	fi
}
Del_iptables(){
	if [[ ! -z "${port}" ]]; then
		iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
		iptables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
		ip6tables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
		ip6tables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
	fi
}
Save_iptables(){
	if [[ ${release} == "centos" ]]; then
		service iptables save
		service ip6tables save
	else
		iptables-save > /etc/iptables.up.rules
		ip6tables-save > /etc/ip6tables.up.rules
	fi
}
Set_iptables(){
	if [[ ${release} == "centos" ]]; then
		service iptables save
		service ip6tables save
		chkconfig --level 2345 iptables on
		chkconfig --level 2345 ip6tables on
	else
		iptables-save > /etc/iptables.up.rules
		ip6tables-save > /etc/ip6tables.up.rules
		echo -e '#!/bin/bash\n/sbin/iptables-restore < /etc/iptables.up.rules\n/sbin/ip6tables-restore < /etc/ip6tables.up.rules' > /etc/network/if-pre-up.d/iptables
		chmod +x /etc/network/if-pre-up.d/iptables
	fi
}
# 读取 配置信息
Get_IP(){
	ip=$(wget -qO- -t1 -T2 ipinfo.io/ip)
	if [[ -z "${ip}" ]]; then
		ip=$(wget -qO- -t1 -T2 api.ip.sb/ip)
		if [[ -z "${ip}" ]]; then
			ip=$(wget -qO- -t1 -T2 members.3322.org/dyndns/getip)
			if [[ -z "${ip}" ]]; then
				ip="VPS_IP"
			fi
		fi
	fi
}
Get_User_info(){
	Get_user_port=$1
	user_info_get=$(python mujson_mgr.py -l -p "${Get_user_port}")
	match_info=$(echo "${user_info_get}"|grep -w "### user ")
	if [[ -z "${match_info}" ]]; then
		echo -e "${Error} Не удалось получить информацию о пользователе ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} " && exit 1
	fi
	user_name=$(echo "${user_info_get}"|grep -w "user :"|awk -F "user : " '{print $NF}')
	port=$(echo "${user_info_get}"|grep -w "port :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	password=$(echo "${user_info_get}"|grep -w "passwd :"|awk -F "passwd : " '{print $NF}')
	method=$(echo "${user_info_get}"|grep -w "method :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	protocol=$(echo "${user_info_get}"|grep -w "protocol :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	protocol_param=$(echo "${user_info_get}"|grep -w "protocol_param :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	[[ -z ${protocol_param} ]] && protocol_param="0(неограниченно)"
	obfs=$(echo "${user_info_get}"|grep -w "obfs :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	#transfer_enable=$(echo "${user_info_get}"|grep -w "transfer_enable :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}'|awk -F "ytes" '{print $1}'|sed 's/KB/ KB/;s/MB/ MB/;s/GB/ GB/;s/TB/ TB/;s/PB/ PB/')
	#u=$(echo "${user_info_get}"|grep -w "u :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	#d=$(echo "${user_info_get}"|grep -w "d :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	forbidden_port=$(echo "${user_info_get}"|grep -w "forbidden_port :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	[[ -z ${forbidden_port} ]] && forbidden_port="неограниченно"
	speed_limit_per_con=$(echo "${user_info_get}"|grep -w "speed_limit_per_con :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	speed_limit_per_user=$(echo "${user_info_get}"|grep -w "speed_limit_per_user :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	Get_User_transfer "${port}"
}
Get_User_transfer(){
	transfer_port=$1
	#echo "transfer_port=${transfer_port}"
	all_port=$(${jq_file} '.[]|.port' ${config_user_mudb_file})
	#echo "all_port=${all_port}"
	port_num=$(echo "${all_port}"|grep -nw "${transfer_port}"|awk -F ":" '{print $1}')
	#echo "port_num=${port_num}"
	port_num_1=$(echo $((${port_num}-1)))
	#echo "port_num_1=${port_num_1}"
	transfer_enable_1=$(${jq_file} ".[${port_num_1}].transfer_enable" ${config_user_mudb_file})
	#echo "transfer_enable_1=${transfer_enable_1}"
	u_1=$(${jq_file} ".[${port_num_1}].u" ${config_user_mudb_file})
	#echo "u_1=${u_1}"
	d_1=$(${jq_file} ".[${port_num_1}].d" ${config_user_mudb_file})
	#echo "d_1=${d_1}"
	transfer_enable_Used_2_1=$(echo $((${u_1}+${d_1})))
	#echo "transfer_enable_Used_2_1=${transfer_enable_Used_2_1}"
	transfer_enable_Used_1=$(echo $((${transfer_enable_1}-${transfer_enable_Used_2_1})))
	#echo "transfer_enable_Used_1=${transfer_enable_Used_1}"
	
	if [[ ${transfer_enable_1} -lt 1024 ]]; then
		transfer_enable="${transfer_enable_1} B"
	elif [[ ${transfer_enable_1} -lt 1048576 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1024'}')
		transfer_enable="${transfer_enable} KB"
	elif [[ ${transfer_enable_1} -lt 1073741824 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1048576'}')
		transfer_enable="${transfer_enable} MB"
	elif [[ ${transfer_enable_1} -lt 1099511627776 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1073741824'}')
		transfer_enable="${transfer_enable} GB"
	elif [[ ${transfer_enable_1} -lt 1125899906842624 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1099511627776'}')
		transfer_enable="${transfer_enable} TB"
	fi
	#echo "transfer_enable=${transfer_enable}"
	if [[ ${u_1} -lt 1024 ]]; then
		u="${u_1} B"
	elif [[ ${u_1} -lt 1048576 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1024'}')
		u="${u} KB"
	elif [[ ${u_1} -lt 1073741824 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1048576'}')
		u="${u} MB"
	elif [[ ${u_1} -lt 1099511627776 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1073741824'}')
		u="${u} GB"
	elif [[ ${u_1} -lt 1125899906842624 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1099511627776'}')
		u="${u} TB"
	fi
	#echo "u=${u}"
	if [[ ${d_1} -lt 1024 ]]; then
		d="${d_1} B"
	elif [[ ${d_1} -lt 1048576 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1024'}')
		d="${d} KB"
	elif [[ ${d_1} -lt 1073741824 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1048576'}')
		d="${d} MB"
	elif [[ ${d_1} -lt 1099511627776 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1073741824'}')
		d="${d} GB"
	elif [[ ${d_1} -lt 1125899906842624 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1099511627776'}')
		d="${d} TB"
	fi
	#echo "d=${d}"
	if [[ ${transfer_enable_Used_1} -lt 1024 ]]; then
		transfer_enable_Used="${transfer_enable_Used_1} B"
	elif [[ ${transfer_enable_Used_1} -lt 1048576 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1024'}')
		transfer_enable_Used="${transfer_enable_Used} KB"
	elif [[ ${transfer_enable_Used_1} -lt 1073741824 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1048576'}')
		transfer_enable_Used="${transfer_enable_Used} MB"
	elif [[ ${transfer_enable_Used_1} -lt 1099511627776 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1073741824'}')
		transfer_enable_Used="${transfer_enable_Used} GB"
	elif [[ ${transfer_enable_Used_1} -lt 1125899906842624 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1099511627776'}')
		transfer_enable_Used="${transfer_enable_Used} TB"
	fi
	#echo "transfer_enable_Used=${transfer_enable_Used}"
	if [[ ${transfer_enable_Used_2_1} -lt 1024 ]]; then
		transfer_enable_Used_2="${transfer_enable_Used_2_1} B"
	elif [[ ${transfer_enable_Used_2_1} -lt 1048576 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1024'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} KB"
	elif [[ ${transfer_enable_Used_2_1} -lt 1073741824 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1048576'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} MB"
	elif [[ ${transfer_enable_Used_2_1} -lt 1099511627776 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1073741824'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} GB"
	elif [[ ${transfer_enable_Used_2_1} -lt 1125899906842624 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1099511627776'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} TB"
	fi
	#echo "transfer_enable_Used_2=${transfer_enable_Used_2}"
}
Get_User_transfer_all(){
	if [[ ${transfer_enable_Used_233} -lt 1024 ]]; then
		transfer_enable_Used_233_2="${transfer_enable_Used_233} B"
	elif [[ ${transfer_enable_Used_233} -lt 1048576 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1024'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} KB"
	elif [[ ${transfer_enable_Used_233} -lt 1073741824 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1048576'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} MB"
	elif [[ ${transfer_enable_Used_233} -lt 1099511627776 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1073741824'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} GB"
	elif [[ ${transfer_enable_Used_233} -lt 1125899906842624 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1099511627776'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} TB"
	fi
}
urlsafe_base64(){
	date=$(echo -n "$1"|base64|sed ':a;N;s/\n/ /g;ta'|sed 's/ //g;s/=//g;s/+/-/g;s/\//_/g')
	echo -e "${date}"
}
ss_link_qr(){
	SSbase64=$(urlsafe_base64 "${method}:${password}@${ip}:${port}")
	SSurl="ss://${SSbase64}"
	SSQRcode="https://api.qrserver.com/v1/create-qr-code/?data=${SSurl}"
	ss_link=" SS link : ${Green_font_prefix}${SSurl}${Font_color_suffix} \n SS QR код : ${Green_font_prefix}${SSQRcode}${Font_color_suffix}"
}
ssr_link_qr(){
	SSRprotocol=$(echo ${protocol} | sed 's/_compatible//g')
	SSRobfs=$(echo ${obfs} | sed 's/_compatible//g')
	SSRPWDbase64=$(urlsafe_base64 "${password}")
	SSRbase64=$(urlsafe_base64 "${ip}:${port}:${SSRprotocol}:${method}:${SSRobfs}:${SSRPWDbase64}")
	SSRurl="ssr://${SSRbase64}"
	SSRQRcode="https://api.qrserver.com/v1/create-qr-code/?data=${SSRurl}"
	ssr_link=" SSR link: ${Red_font_prefix}${SSRurl}${Font_color_suffix} \n SSR QR код : ${Red_font_prefix}${SSRQRcode}${Font_color_suffix} \n "
}
ss_ssr_determine(){
	protocol_suffix=`echo ${protocol} | awk -F "_" '{print $NF}'`
	obfs_suffix=`echo ${obfs} | awk -F "_" '{print $NF}'`
	if [[ ${protocol} = "origin" ]]; then
		if [[ ${obfs} = "plain" ]]; then
			ss_link_qr
			ssr_link=""
		else
			if [[ ${obfs_suffix} != "compatible" ]]; then
				ss_link=""
			else
				ss_link_qr
			fi
		fi
	else
		if [[ ${protocol_suffix} != "compatible" ]]; then
			ss_link=""
		else
			if [[ ${obfs_suffix} != "compatible" ]]; then
				if [[ ${obfs_suffix} = "plain" ]]; then
					ss_link_qr
				else
					ss_link=""
				fi
			else
				ss_link_qr
			fi
		fi
	fi
	ssr_link_qr
}
# Display configuration information
View_User(){
	SSR_installation_status
	List_port_user
	while true
	do
		echo -e "Введите порт аккаунта для анализа"
		read -e -p "(По умолчанию: отмена):" View_user_port
		[[ -z "${View_user_port}" ]] && echo -e "Отмена..." && exit 1
		View_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${View_user_port}"',')
		if [[ ! -z ${View_user} ]]; then
			Get_User_info "${View_user_port}"
			View_User_info
			break
		else
			echo -e "${Error} Введите правильный порт !"
		fi
	done
}
View_User_info(){
	ip=$(cat ${config_user_api_file}|grep "SERVER_PUB_ADDR = "|awk -F "[']" '{print $2}')
	[[ -z "${ip}" ]] && Get_IP
	ss_ssr_determine
	clear && echo "===================================================" && echo
	echo -e " Информация о пользователе [${user_name}] ：" && echo
	echo -e " IP\t    : ${Green_font_prefix}${ip}${Font_color_suffix}"
	echo -e " Порт\t    : ${Green_font_prefix}${port}${Font_color_suffix}"
	echo -e " Пароль\t    : ${Green_font_prefix}${password}${Font_color_suffix}"
	echo -e " Шифрование : ${Green_font_prefix}${method}${Font_color_suffix}"
	echo -e " Протокол   : ${Red_font_prefix}${protocol}${Font_color_suffix}"
	echo -e " Obfs\t    : ${Red_font_prefix}${obfs}${Font_color_suffix}"
	echo -e " Количество устройств : ${Green_font_prefix}${protocol_param}${Font_color_suffix}"
	echo -e " Общая скорость ключа : ${Green_font_prefix}${speed_limit_per_con} KB/S${Font_color_suffix}"
	echo -e " Скорость соединения у каждого пользователя : ${Green_font_prefix}${speed_limit_per_user} KB/S${Font_color_suffix}"
	echo -e " Запрещенные порты : ${Green_font_prefix}${forbidden_port} ${Font_color_suffix}"
	echo
	echo -e " Использованный трафик : Upload: ${Green_font_prefix}${u}${Font_color_suffix} + Download: ${Green_font_prefix}${d}${Font_color_suffix} = ${Green_font_prefix}${transfer_enable_Used_2}${Font_color_suffix}"
	echo -e " Осталось трафика : ${Green_font_prefix}${transfer_enable_Used} ${Font_color_suffix}"
	echo -e " Всего трафика : ${Green_font_prefix}${transfer_enable} ${Font_color_suffix}"
	echo -e "${ss_link}"
	echo -e "${ssr_link}"
	echo -e " ${Green_font_prefix} Подсказка: ${Font_color_suffix}
 Откройте ссылку в браузере для получения QR кода。"
	echo && echo "==================================================="
}
# Создание юзера
Set_config_user(){
	echo "Имя пользователя"
	read -e -p "(По умолчанию: Admin):" ssr_user
	[[ -z "${ssr_user}" ]] && ssr_user="Admin"
	ssr_user=$(echo "${ssr_user}_$(date +"%d/%m")" |sed 's/ //g')
	echo && echo ${Separator_1} && echo -e "	Имя пользователя : ${Green_font_prefix}${ssr_user}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_port(){
	echo "Порт
	1. Авто
	2. Вручную"	
	read -e -p "По умолчанию: (1.Авто)" how_to_port
	[[ -z "${how_to_port}" ]] && how_to_port="1"
	if [[ ${how_to_port} == "1" ]]; then
		echo -e "Порт автоматически сгенерирован."
		ssr_port=$(shuf -i 1000-9999 -n 1)
		while true
		do
		echo $((${ssr_port}+0)) &>/dev/null
		if [[ $? == 0 ]]; then
		if [[ ${ssr_port} -ge 1 ]] && [[ ${ssr_port} -le 65535 ]]; then
			echo && echo ${Separator_1} && echo -e "	Порт: : ${Green_font_prefix}${ssr_port}${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} Введите корректный порт(1-65535)"
		fi
	else
		echo -e "${Error} Введите корректный порт(1-65535)"
	fi
	done
	elif [[ ${how_to_port} == "2" ]]; then
		while true
		do
			read -e -p "Порт:" ssr_port
			[[ -z "$ssr_port" ]] && break
			echo $((${ssr_port}+0)) &>/dev/null
			if [[ $? == 0 ]]; then
				if [[ ${ssr_port} -ge 1 ]] && [[ ${ssr_port} -le 65535 ]]; then
					echo && echo ${Separator_1} && echo -e "	Порт: : ${Green_font_prefix}${ssr_port}${Font_color_suffix}" && echo ${Separator_1} && echo
					break
				else
					echo -e "${Error} Введите корректный порт(1-65535)"
				fi
			else
				echo -e "${Error} Введите корректный порт(1-65535)"
			fi
		done
	else 
		echo -e "Порт автоматически сгенерирован."
		ssr_port=$(shuf -i 1000-9999 -n 1)
		while true
		do
		echo $((${ssr_port}+0)) &>/dev/null
		if [[ $? == 0 ]]; then
			if [[ ${ssr_port} -ge 1 ]] && [[ ${ssr_port} -le 65535 ]]; then
			echo && echo ${Separator_1} && echo -e "	Порт: : ${Green_font_prefix}${ssr_port}${Font_color_suffix}" && echo ${Separator_1} && echo
			break
			else
			echo -e "${Error} Введите корректный порт(1-65535)"
			fi
		else
		echo -e "${Error} Введите корректный порт(1-65535)"
		fi
		done
	fi
}
Set_config_password(){
	echo "Пароль:
	1. Пароль = порт
	2. Рандомный пароль"
	read -e -p "По умолчанию: (1.Пароль = порт)" how_to_pass
	[[ -z "${how_to_pass}" ]] && how_to_pass="1"
	if [[ ${how_to_pass} == "1" ]]; then
		ssr_password=${ssr_port}
	elif [[ ${how_to_pass} == "2" ]]; then
		ssr_password=$(date +%s%N | md5sum | head -c 16)
	else 
		ssr_password=${ssr_port}
	fi
	echo && echo ${Separator_1} && echo -e "	Пароль : ${Green_font_prefix}${ssr_password}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_method(){
		ssr_method="chacha20-ietf"
}
Set_config_protocol(){
ssr_protocol="origin"
}
Set_config_obfs(){
ssr_obfs="plain"
}
Set_config_protocol_param(){
	while true
	do
	ssr_protocol_param=""
	[[ -z "$ssr_protocol_param" ]] && ssr_protocol_param="" && break
	echo $((${ssr_protocol_param}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_protocol_param} -ge 1 ]] && [[ ${ssr_protocol_param} -le 9999 ]]; then
			break
		else
			echo -e "${Error} Введите корректный номер(1-9999)"
		fi
	else
		echo -e "${Error} Введите корректный номер(1-9999)"
	fi
	done
}
Set_config_speed_limit_per_con(){
	while true
	do
	ssr_speed_limit_per_con=""
	[[ -z "$ssr_speed_limit_per_con" ]] && ssr_speed_limit_per_con=0 && break
	echo $((${ssr_speed_limit_per_con}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_speed_limit_per_con} -ge 1 ]] && [[ ${ssr_speed_limit_per_con} -le 131072 ]]; then
			break
		else
			echo -e "${Error} Введите корректный номер(1-131072)"
		fi
	else
		echo -e "${Error} Введите корректный номер(1-131072)"
	fi
	done
}
Set_config_speed_limit_per_user(){
	while true
	do
	echo
	ssr_speed_limit_per_user=""
	[[ -z "$ssr_speed_limit_per_user" ]] && ssr_speed_limit_per_user=0 && break
	echo $((${ssr_speed_limit_per_user}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_speed_limit_per_user} -ge 1 ]] && [[ ${ssr_speed_limit_per_user} -le 131072 ]]; then
			break
		else
			echo -e "${Error} Введите корректный номер(1-131072)"
		fi
	else
		echo -e "${Error} Введите корректный номер(1-131072)"
	fi
	done
}
Set_config_transfer(){
	while true
	do
	echo
	ssr_transfer=""
	[[ -z "$ssr_transfer" ]] && ssr_transfer="838868" && break
	echo $((${ssr_transfer}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_transfer} -ge 1 ]] && [[ ${ssr_transfer} -le 838868 ]]; then
			break
		else
			echo -e "${Error} Введите корректный номер(1-838868)"
		fi
	else
		echo -e "${Error} Введите корректный номер(1-838868)"
	fi
	done
}
Set_config_forbid(){
	ssr_forbid=""
	[[ -z "${ssr_forbid}" ]] && ssr_forbid=""
}
Set_config_enable(){
	user_total=$(echo $((${user_total}-1)))
	for((integer = 0; integer <= ${user_total}; integer++))
	do
		echo -e "integer=${integer}"
		port_jq=$(${jq_file} ".[${integer}].port" "${config_user_mudb_file}")
		echo -e "port_jq=${port_jq}"
		if [[ "${ssr_port}" == "${port_jq}" ]]; then
			enable=$(${jq_file} ".[${integer}].enable" "${config_user_mudb_file}")
			echo -e "enable=${enable}"
			[[ "${enable}" == "null" ]] && echo -e "${Error} Не удалось получить отключенный статус текущего порта [${ssr_port}]!" && exit 1
			ssr_port_num=$(cat "${config_user_mudb_file}"|grep -n '"port": '${ssr_port}','|awk -F ":" '{print $1}')
			echo -e "ssr_port_num=${ssr_port_num}"
			[[ "${ssr_port_num}" == "null" ]] && echo -e "${Error} Не удалось получить количество строк текущего порта[${ssr_port}]!" && exit 1
			ssr_enable_num=$(echo $((${ssr_port_num}-5)))
			echo -e "ssr_enable_num=${ssr_enable_num}"
			break
		fi
	done
	if [[ "${enable}" == "1" ]]; then
		echo -e "Порт [${ssr_port}] находится в состоянии：${Green_font_prefix}включен${Font_color_suffix} , сменить статус на ${Red_font_prefix}выключен${Font_color_suffix} ?[Y/n]"
		read -e -p "(По умолчанию: Y):" ssr_enable_yn
		[[ -z "${ssr_enable_yn}" ]] && ssr_enable_yn="y"
		if [[ "${ssr_enable_yn}" == [Yy] ]]; then
			ssr_enable="0"
		else
			echo "Отмена..." && exit 0
		fi
	elif [[ "${enable}" == "0" ]]; then
		echo -e "Порт [${ssr_port}] находится в состоянии：${Green_font_prefix}отключен${Font_color_suffix} , сменить статус на  ${Red_font_prefix}включен${Font_color_suffix} ?[Y/n]"
		read -e -p "(По умолчанию: Y):" ssr_enable_yn
		[[ -z "${ssr_enable_yn}" ]] && ssr_enable_yn = "y"
		if [[ "${ssr_enable_yn}" == [Yy] ]]; then
			ssr_enable="1"
		else
			echo "Отмена..." && exit 0
		fi
	else
		echo -e "${Error} какая то ошибка с акком, гг[${enable}] !" && exit 1
	fi
}
Set_user_api_server_pub_addr(){
	addr=$1
	if [[ "${addr}" == "Modify" ]]; then
		server_pub_addr=$(cat ${config_user_api_file}|grep "SERVER_PUB_ADDR = "|awk -F "[']" '{print $2}')
		if [[ -z ${server_pub_addr} ]]; then
			echo -e "${Error} Не получилось получить IP сервера！" && exit 1
		else
			echo -e "${Info} Текущий IP： ${Green_font_prefix}${server_pub_addr}${Font_color_suffix}"
		fi
	fi
	echo "Введите IP сервера"
	read -e -p "(Автоматическое определение IP при нажатии Enter):" ssr_server_pub_addr
	if [[ -z "${ssr_server_pub_addr}" ]]; then
		Get_IP
		if [[ ${ip} == "VPS_IP" ]]; then
			while true
			do
			read -e -p "${Error} Введите IP сервера сами!" ssr_server_pub_addr
			if [[ -z "$ssr_server_pub_addr" ]]; then
				echo -e "${Error} Не может быть пустым！"
			else
				break
			fi
			done
		else
			ssr_server_pub_addr="${ip}"
		fi
	fi
	echo && echo ${Separator_1} && echo -e "	IP сервера : ${Green_font_prefix}${ssr_server_pub_addr}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_all(){
	lal=$1
	if [[ "${lal}" == "Modify" ]]; then
		Set_config_password
		Set_config_method
		Set_config_protocol
		Set_config_obfs
		Set_config_protocol_param
		Set_config_speed_limit_per_con
		Set_config_speed_limit_per_user
		Set_config_transfer
		Set_config_forbid
	else
		Set_config_user
		Set_config_port
		Set_config_password
		Set_config_method
		Set_config_protocol
		Set_config_obfs
		Set_config_protocol_param
		Set_config_speed_limit_per_con
		Set_config_speed_limit_per_user
		Set_config_transfer
		Set_config_forbid
	fi
}
# Изменить конфигурацию клиента
Modify_config_password(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -k "${ssr_password}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить пароль пользователя ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Пароль пользователя успешно изменен ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} (Может занять около 10 секунд для обновления конфигурации)"
	fi
}
Modify_config_method(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -m "${ssr_method}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить шифрование ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Шифрование успешно изменено ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} (Может занять около 10 секунд для обновления конфигурации)"
	fi
}
Modify_config_protocol(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -O "${ssr_protocol}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить протокол ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Протокол успешно изменен ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} (Может занять около 10 секунд для обновления конфигурации)"
	fi
}
Modify_config_obfs(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -o "${ssr_obfs}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить Obfs plugin ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Obfs plugin успешно изменен ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} (Может занять около 10 секунд для обновления конфигурации)"
	fi
}
Modify_config_protocol_param(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -G "${ssr_protocol_param}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить лимит устройств ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Лимит устройств успешно изменен ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} (Может занять около 10 секунд для обновления конфигурации)"
	fi
}
Modify_config_speed_limit_per_con(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -s "${ssr_speed_limit_per_con}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить лимит скорости ключа ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Лимит скорости ключа успешно изменен ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} (Может занять около 10 секунд для обновления конфигурации)"
	fi
}
Modify_config_speed_limit_per_user(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -S "${ssr_speed_limit_per_user}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить лимит скорости пользователей ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Лимит скорости пользователей успешно изменен ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} (Может занять около 10 секунд для обновления конфигурации)"
	fi
}
Modify_config_connect_verbose_info(){
	sed -i 's/"connect_verbose_info": '"$(echo ${connect_verbose_info})"',/"connect_verbose_info": '"$(echo ${ssr_connect_verbose_info})"',/g' ${config_user_file}
}
Modify_config_transfer(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -t "${ssr_transfer}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить общий трафик пользователя ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Общий трафик пользователя успешно изменен ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} (Может занять около 10 секунд для обновления конфигурации)"
	fi
}
Modify_config_forbid(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -f "${ssr_forbid}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Не удалось изменить запрещенные порты пользователя ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Запрещенные порты пользователя успешно изменены ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} (Может занять около 10 секунд для обновления конфигурации)"
	fi
}
Modify_config_enable(){
	sed -i "${ssr_enable_num}"'s/"enable": '"$(echo ${enable})"',/"enable": '"$(echo ${ssr_enable})"',/' ${config_user_mudb_file}
}
Modify_user_api_server_pub_addr(){
	sed -i "s/SERVER_PUB_ADDR = '${server_pub_addr}'/SERVER_PUB_ADDR = '${ssr_server_pub_addr}'/" ${config_user_api_file}
}
Modify_config_all(){
	Modify_config_password
	Modify_config_method
	Modify_config_protocol
	Modify_config_obfs
	Modify_config_protocol_param
	Modify_config_speed_limit_per_con
	Modify_config_speed_limit_per_user
	Modify_config_transfer
	Modify_config_forbid
}
setiplimit(){
	del_user_port=$ssr_port
	del_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${del_user_port}"',')
	if [[ ! -z ${del_user} ]]; then
		clear
		echo -e "Настройка мер пресечений нарушения правил для клиента с портом $del_user_port"
		echo -e 'cd "/usr/local/shadowsocksr"' > "/usr/local/shadowsocksr/${del_user_port}checking.sh"
		echo -e "port=$del_user_port" > "/usr/local/shadowsocksr/${del_user_port}checking.sh"
		echo -e 'user_IP_1=$(netstat -anp |grep '\''ESTABLISHED'\'' |grep '\''python'\'' |grep '\''tcp6'\'' |grep ":${port} " |awk '\''{print $5}'\'' |awk -F ":" '\''{print $1}'\'' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}")' >> "/usr/local/shadowsocksr/${del_user_port}checking.sh"
		echo -e 'user_IP_total=$(echo -e "${user_IP_1}"|wc -l)' >> "/usr/local/shadowsocksr/${del_user_port}checking.sh"
		echo -e 'if [[ $user_IP_total -gt 1 ]]; then
	if [[ $user_IP_total -gt 1 ]]; then
		cd "/usr/local/shadowsocksr"
		ssr_password=$(date +%s%N | md5sum | head -c 16)
		python "/usr/local/shadowsocksr/mujson_mgr.py" -e -p "${port}" -k "${ssr_password}"
		sed -i "${port}checking.sh/d" "/usr/local/shadowsocksr/crontab.bak" 
		crontab -r
		crontab "/usr/local/shadowsocksr/crontab.bak"
		rm "/usr/local/shadowsocksr/${port}checking.sh"
	fi
else
	echo
fi' >> "/usr/local/shadowsocksr/${del_user_port}checking.sh"
		if [[ ! -e "/usr/local/shadowsocksr/crontab.bak" ]]; then
			echo -e "\n* * * * * /bin/bash /usr/local/shadowsocksr/${del_user_port}checking.sh" > "/usr/local/shadowsocksr/crontab.bak"
		else
			echo -e "\n* * * * * /bin/bash /usr/local/shadowsocksr/${del_user_port}checking.sh" >> "/usr/local/shadowsocksr/crontab.bak"
		fi
		crontab "/usr/local/shadowsocksr/crontab.bak"
		echo -e "При подключении более 1 IP адреса к ключу с портом $del_user_port, пароль будет сменен на случайный."	
	else
		echo -e "${Error} Введите корректный порт !"
	fi	
}
Check_python(){
	python_ver=`python -h`
	if [[ -z ${python_ver} ]]; then
		echo -e "${Info} Python не установлен, начинаю установку..."
		if [[ ${release} == "centos" ]]; then
			yum install -y python
		else
			apt-get install -y python
		fi
	fi
}
Centos_yum(){
	yum update
	cat /etc/redhat-release |grep 7\..*|grep -i centos>/dev/null
	if [[ $? = 0 ]]; then
		yum install -y vim unzip crond net-tools
	else
		yum install -y vim unzip crond
	fi
}
Debian_apt(){
	apt-get update
	cat /etc/issue |grep 9\..*>/dev/null
	if [[ $? = 0 ]]; then
		apt-get install -y vim unzip cron net-tools
	else
		apt-get install -y vim unzip cron
	fi
}
# 下载 ShadowsocksR
Download_SSR(){
	cd "/usr/local"
	wget -N --no-check-certificate "https://github.com/ToyoDAdoubiBackup/shadowsocksr/archive/manyuser.zip"
	#git config --global http.sslVerify false
	#env GIT_SSL_NO_VERIFY=true git clone -b manyuser https://github.com/ToyoDAdoubiBackup/shadowsocksr.git
	#[[ ! -e ${ssr_folder} ]] && echo -e "${Error} ShadowsocksR服务端 下载失败 !" && exit 1
	[[ ! -e "manyuser.zip" ]] && echo -e "${Error} Не удалось скачать архив с ShadowsocksR !" && rm -rf manyuser.zip && exit 1
	unzip "manyuser.zip"
	[[ ! -e "/usr/local/shadowsocksr-manyuser/" ]] && echo -e "${Error} Ошибка распаковки ShadowsocksR !" && rm -rf manyuser.zip && exit 1
	mv "/usr/local/shadowsocksr-manyuser/" "/usr/local/shadowsocksr/"
	[[ ! -e "/usr/local/shadowsocksr/" ]] && echo -e "${Error} Переименование ShadowsocksR неуспешно !" && rm -rf manyuser.zip && rm -rf "/usr/local/shadowsocksr-manyuser/" && exit 1
	rm -rf manyuser.zip
	cd "shadowsocksr"
	cp "${ssr_folder}/config.json" "${config_user_file}"
	cp "${ssr_folder}/mysql.json" "${ssr_folder}/usermysql.json"
	cp "${ssr_folder}/apiconfig.py" "${config_user_api_file}"
	[[ ! -e ${config_user_api_file} ]] && echo -e "${Error} Не удалось скопировать apiconfig.py для ShadowsocksR !" && exit 1
	sed -i "s/API_INTERFACE = 'sspanelv2'/API_INTERFACE = 'mudbjson'/" ${config_user_api_file}
	server_pub_addr="127.0.0.1"
	Modify_user_api_server_pub_addr
	#sed -i "s/SERVER_PUB_ADDR = '127.0.0.1'/SERVER_PUB_ADDR = '${ip}'/" ${config_user_api_file}
	sed -i 's/ \/\/ only works under multi-user mode//g' "${config_user_file}"
	echo -e "${Info} ShadowsocksR успешно установлен !"
}
Service_SSR(){
	if [[ ${release} = "centos" ]]; then
		if ! wget --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/service/ssrmu_centos -O /etc/init.d/ssrmu; then
			echo -e "${Error} Не удалось загрузить скрипт для управления ShadowsocksR !" && exit 1
		fi
		chmod +x /etc/init.d/ssrmu
		chkconfig --add ssrmu
		chkconfig ssrmu on
	else
		if ! wget --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/service/ssrmu_debian -O /etc/init.d/ssrmu; then
			echo -e "${Error} Не удалось загрузить скрипт для управления ShadowsocksR !" && exit 1
		fi
		chmod +x /etc/init.d/ssrmu
		update-rc.d -f ssrmu defaults
	fi
	echo -e "${Info} Скрипт для управления ShadowsocksR успешно установлен !"
}
# 安装 JQ解析器
JQ_install(){
	if [[ ! -e ${jq_file} ]]; then
		cd "${ssr_folder}"
		if [[ ${bit} = "x86_64" ]]; then
			mv "jq-linux64" "jq"
			#wget --no-check-certificate "https://github.com/stedolan/jq/releases/download/jq-1.5/jq-linux64" -O ${jq_file}
		else
			mv "jq-linux32" "jq"
			#wget --no-check-certificate "https://github.com/stedolan/jq/releases/download/jq-1.5/jq-linux32" -O ${jq_file}
		fi
		[[ ! -e ${jq_file} ]] && echo -e "${Error} Парсер JQ не удалось переименовать !" && exit 1
		chmod +x ${jq_file}
		echo -e "${Info} Установка JQ завершена, продолжение..." 
	else
		echo -e "${Info} Парсер JQ успешно установлен..."
	fi
}
# 安装 依赖
Installation_dependency(){
	if [[ ${release} == "centos" ]]; then
		Centos_yum
	else
		Debian_apt
	fi
	[[ ! -e "/usr/bin/unzip" ]] && echo -e "${Error} Установка unzip неуспешна !" && exit 1
	Check_python
	#echo "nameserver 8.8.8.8" > /etc/resolv.conf
	#echo "nameserver 8.8.4.4" >> /etc/resolv.conf
	\cp -f /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
	if [[ ${release} == "centos" ]]; then
		/etc/init.d/crond restart
	else
		/etc/init.d/cron restart
	fi
}
Install_SSR(){
	check_root
	[[ -e ${ssr_folder} ]] && echo -e "${Error} ShadowsocksR уже установлен !" && exit 1
	echo -e "${Info} типа че то происходит..."
	Set_user_api_server_pub_addr
	Set_config_all
	echo -e "${Info} типа че то происходит..."
	Installation_dependency
	echo -e "${Info} типа че то происходит..."
	Download_SSR
	echo -e "${Info} типа че то происходит..."
	Service_SSR
	echo -e "${Info} типа че то происходит..."
	JQ_install
	echo -e "${Info} типа че то происходит..."
	Add_port_user "install"
	echo -e "${Info} типа че то происходит..."
	Set_iptables
	echo -e "${Info} типа че то происходит..."
	Add_iptables
	echo -e "${Info} типа че то происходит..."
	Save_iptables
	echo -e "${Info} типа че то происходит..."
	Start_SSR
	Get_User_info "${ssr_port}"
	View_User_info
}
Update_SSR(){
	SSR_installation_status
	echo -e "Данная функция отключена."
	#cd ${ssr_folder}
	#git pull
	#Restart_SSR
}
Uninstall_SSR(){
	[[ ! -e ${ssr_folder} ]] && echo -e "${Error} ShadowsocksR не установлен !" && exit 1
	echo "Удалить ShadowsocksR？[y/N]" && echo
	read -e -p "(По умолчанию: n):" unyn
	[[ -z ${unyn} ]] && unyn="n"
	if [[ ${unyn} == [Yy] ]]; then
		check_pid
		[[ ! -z "${PID}" ]] && kill -9 ${PID}
		user_info=$(python mujson_mgr.py -l)
		user_total=$(echo "${user_info}"|wc -l)
		if [[ ! -z ${user_info} ]]; then
			for((integer = 1; integer <= ${user_total}; integer++))
			do
				port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
				Del_iptables
			done
			Save_iptables
		fi
		if [[ ! -z $(crontab -l | grep "ssrmu.sh") ]]; then
			crontab_monitor_ssr_cron_stop
			Clear_transfer_all_cron_stop
		fi
		if [[ ${release} = "centos" ]]; then
			chkconfig --del ssrmu
		else
			update-rc.d -f ssrmu remove
		fi
		rm -rf ${ssr_folder} && rm -rf /etc/init.d/ssrmu
		echo && echo " ShadowsocksR успешно удален !" && echo
	else
		echo && echo " Отмена..." && echo
	fi
}
Check_Libsodium_ver(){
	echo -e "${Info} Начинаю получение последней версии libsodium..."
	Libsodiumr_ver=$(wget -qO- "https://github.com/jedisct1/libsodium/tags"|grep "/jedisct1/libsodium/releases/tag/"|head -1|sed -r 's/.*tag\/(.+)\">.*/\1/')
	[[ -z ${Libsodiumr_ver} ]] && Libsodiumr_ver=${Libsodiumr_ver_backup}
	echo -e "${Info} Последняя версия libsodium: ${Green_font_prefix}${Libsodiumr_ver}${Font_color_suffix} !"
}
Install_Libsodium(){
	if [[ -e ${Libsodiumr_file} ]]; then
		echo -e "${Error} libsodium уже установлен, желаете перезаписать(обновить)？[y/N]"
		read -e -p "(По умолчанию: n):" yn
		[[ -z ${yn} ]] && yn="n"
		if [[ ${yn} == [Nn] ]]; then
			echo "Отмена..." && exit 1
		fi
	else
		echo -e "${Info} libsodium не установлен, начинаю установку..."
	fi
	Check_Libsodium_ver
	if [[ ${release} == "centos" ]]; then
		yum update
		echo -e "${Info} бла бла бла..."
		yum -y groupinstall "Development Tools"
		echo -e "${Info} скачивание..."
		#https://github.com/jedisct1/libsodium/releases/download/1.0.18-RELEASE/libsodium-1.0.18.tar.gz
		wget  --no-check-certificate -N "https://github.com/jedisct1/libsodium/releases/download/${Libsodiumr_ver}-RELEASE/libsodium-${Libsodiumr_ver}.tar.gz"
		echo -e "${Info} распаковка..."
		tar -xzf libsodium-${Libsodiumr_ver}.tar.gz && cd libsodium-${Libsodiumr_ver}
		echo -e "${Info} установка..."
		./configure --disable-maintainer-mode && make -j2 && make install
		echo /usr/local/lib > /etc/ld.so.conf.d/usr_local_lib.conf
	else
		apt-get update
		echo -e "${Info} бла бла бла..."
		apt-get install -y build-essential
		echo -e "${Info} скачивание..."
		wget  --no-check-certificate -N "https://github.com/jedisct1/libsodium/releases/download/${Libsodiumr_ver}-RELEASE/libsodium-${Libsodiumr_ver}.tar.gz"
		echo -e "${Info} распаковка..."
		tar -xzf libsodium-${Libsodiumr_ver}.tar.gz && cd libsodium-${Libsodiumr_ver}
		echo -e "${Info} установка..."
		./configure --disable-maintainer-mode && make -j2 && make install
	fi
	ldconfig
	cd .. && rm -rf libsodium-${Libsodiumr_ver}.tar.gz && rm -rf libsodium-${Libsodiumr_ver}
	[[ ! -e ${Libsodiumr_file} ]] && echo -e "${Error} Установка libsodium неуспешна !" && exit 1
	echo && echo -e "${Info} libsodium успешно установлен !" && echo
}
# 显示 连接信息
debian_View_user_connection_info(){
	format_1=$1
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} Пользователь не найден !" && exit 1
	IP_total=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp6' |awk '{print $5}' |awk -F ":" '{print $1}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" |wc -l`
	user_list_all=""
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		user_IP_1=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp6' |grep ":${user_port} " |awk '{print $5}' |awk -F ":" '{print $1}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"`
		if [[ -z ${user_IP_1} ]]; then
			user_IP_total="0"
		else
			user_IP_total=`echo -e "${user_IP_1}"|wc -l`
			if [[ ${format_1} == "IP_address" ]]; then
				get_IP_address
			else
				user_IP=`echo -e "\n${user_IP_1}"`
			fi
		fi
		user_info_233=$(python mujson_mgr.py -l|grep -w "${user_port}"|awk '{print $2}'|sed 's/\[//g;s/\]//g')
		user_list_all=${user_list_all}"Юзер: ${Green_font_prefix}"${user_info_233}"${Font_color_suffix} Порт: ${Green_font_prefix}"${user_port}"${Font_color_suffix} Кол-во IP: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix} Подкл. юзеры: ${Green_font_prefix}${user_IP}${Font_color_suffix}\n"
		user_IP=""
	done
	echo -e "Всего пользователей: ${Green_background_prefix} "${user_total}" ${Font_color_suffix} Общее число IP адресов: ${Green_background_prefix} "${IP_total}" ${Font_color_suffix} "
	echo -e "${user_list_all}"
}
centos_View_user_connection_info(){
	format_1=$1
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} Пользователь не найден !" && exit 1
	IP_total=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp' | grep '::ffff:' |awk '{print $5}' |awk -F ":" '{print $4}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" |wc -l`
	user_list_all=""
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		user_IP_1=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp' |grep ":${user_port} "|grep '::ffff:' |awk '{print $5}' |awk -F ":" '{print $4}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"`
		if [[ -z ${user_IP_1} ]]; then
			user_IP_total="0"
		else
			user_IP_total=`echo -e "${user_IP_1}"|wc -l`
			if [[ ${format_1} == "IP_address" ]]; then
				get_IP_address
			else
				user_IP=`echo -e "\n${user_IP_1}"`
			fi
		fi
		user_info_233=$(python mujson_mgr.py -l|grep -w "${user_port}"|awk '{print $2}'|sed 's/\[//g;s/\]//g')
		user_list_all=${user_list_all}"Юзер: ${Green_font_prefix}"${user_info_233}"${Font_color_suffix} Порт: ${Green_font_prefix}"${user_port}"${Font_color_suffix} Кол-во IP: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix} Подкл. юзеры: ${Green_font_prefix}${user_IP}${Font_color_suffix}\n"
		user_IP=""
	done
	echo -e "Всего пользователей: ${Green_background_prefix} "${user_total}" ${Font_color_suffix} Всего IP адресов: ${Green_background_prefix} "${IP_total}" ${Font_color_suffix} "
	echo -e "${user_list_all}"
}
View_user_connection_info(){
	SSR_installation_status
	echo && ssr_connection_info="1"
	if [[ ${ssr_connection_info} == "1" ]]; then
		View_user_connection_info_1 ""
	elif [[ ${ssr_connection_info} == "2" ]]; then
		echo -e "${Tip} Замечен(ipip.net)，если там больше IP адресов, может занять больше времени..."
		View_user_connection_info_1 "IP_address"
	else
		echo -e "${Error} Введите корректный номер(1-2)" && exit 1
	fi
}
View_user_connection_info_1(){
	format=$1
	if [[ ${release} = "centos" ]]; then
		cat /etc/redhat-release |grep 7\..*|grep -i centos>/dev/null
		if [[ $? = 0 ]]; then
			debian_View_user_connection_info "$format"
		else
			centos_View_user_connection_info "$format"
		fi
	else
		debian_View_user_connection_info "$format"
	fi
}
get_IP_address(){
	#echo "user_IP_1=${user_IP_1}"
	if [[ ! -z ${user_IP_1} ]]; then
	#echo "user_IP_total=${user_IP_total}"
		for((integer_1 = ${user_IP_total}; integer_1 >= 1; integer_1--))
		do
			IP=`echo "${user_IP_1}" |sed -n "$integer_1"p`
			#echo "IP=${IP}"
			IP_address=`wget -qO- -t1 -T2 http://freeapi.ipip.net/${IP}|sed 's/\"//g;s/,//g;s/\[//g;s/\]//g'`
			#echo "IP_address=${IP_address}"
			user_IP="${user_IP}\n${IP}(${IP_address})"
			#echo "user_IP=${user_IP}"
			sleep 1s
		done
	fi
}
# 修改 用户配置
Modify_port(){
	List_port_user
	while true
	do
		echo -e "Введите порт пользователя который нужно изменить!"
		read -e -p "(По умолчанию: отмена):" ssr_port
		[[ -z "${ssr_port}" ]] && echo -e "已取消..." && exit 1
		Modify_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${ssr_port}"',')
		if [[ ! -z ${Modify_user} ]]; then
			break
		else
			echo -e "${Error} Введите правильный порт !"
		fi
	done
}
Modify_Config(){
	SSR_installation_status
	echo && echo -e "Что вы хотите сделать？
 ${Green_font_prefix}1.${Font_color_suffix}  Добавить новую конфигурацию
 ${Green_font_prefix}2.${Font_color_suffix}  Удалить конфигурацию пользователя
————— Изменить конфигурацию пользователя —————
 ${Green_font_prefix}3.${Font_color_suffix}  Изменить пароль пользователя
 ${Green_font_prefix}4.${Font_color_suffix}  Изменить метод шифрования
 ${Green_font_prefix}5.${Font_color_suffix}  Изменить протокол
 ${Green_font_prefix}6.${Font_color_suffix}  Изменить obfs плагин
 ${Green_font_prefix}7.${Font_color_suffix}  Изменить количество устройств
 ${Green_font_prefix}8.${Font_color_suffix}  Изменить общий лимит скорости
 ${Green_font_prefix}9.${Font_color_suffix}  Изменить лимит скорости у пользователя
 ${Green_font_prefix}10.${Font_color_suffix} Изменить общий трафик
 ${Green_font_prefix}11.${Font_color_suffix} Изменить запрещенные порты
 ${Green_font_prefix}12.${Font_color_suffix} Изменить все конфигурации
————— Другое —————
 ${Green_font_prefix}13.${Font_color_suffix} Изменить IP адрес для пользователя
 
 ${Tip} Для изменения имени пользователя или порта используйте ручную модификацию !" && echo
	read -e -p "(По умолчанию: отмена):" ssr_modify
	[[ -z "${ssr_modify}" ]] && echo "Отмена..." && exit 1
	if [[ ${ssr_modify} == "1" ]]; then
		Add_port_user
	elif [[ ${ssr_modify} == "2" ]]; then
		Del_port_user
	elif [[ ${ssr_modify} == "3" ]]; then
		Modify_port
		Set_config_password
		Modify_config_password
	elif [[ ${ssr_modify} == "4" ]]; then
		Modify_port
		Set_config_method
		Modify_config_method
	elif [[ ${ssr_modify} == "5" ]]; then
		Modify_port
		Set_config_protocol
		Modify_config_protocol
	elif [[ ${ssr_modify} == "6" ]]; then
		Modify_port
		Set_config_obfs
		Modify_config_obfs
	elif [[ ${ssr_modify} == "7" ]]; then
		Modify_port
		Set_config_protocol_param
		Modify_config_protocol_param
	elif [[ ${ssr_modify} == "8" ]]; then
		Modify_port
		Set_config_speed_limit_per_con
		Modify_config_speed_limit_per_con
	elif [[ ${ssr_modify} == "9" ]]; then
		Modify_port
		Set_config_speed_limit_per_user
		Modify_config_speed_limit_per_user
	elif [[ ${ssr_modify} == "10" ]]; then
		Modify_port
		Set_config_transfer
		Modify_config_transfer
	elif [[ ${ssr_modify} == "11" ]]; then
		Modify_port
		Set_config_forbid
		Modify_config_forbid
	elif [[ ${ssr_modify} == "12" ]]; then
		Modify_port
		Set_config_all "Modify"
		Modify_config_all
	elif [[ ${ssr_modify} == "13" ]]; then
		Set_user_api_server_pub_addr "Modify"
		Modify_user_api_server_pub_addr
	else
		echo -e "${Error} Введите корректный номер(1-13)" && exit 1
	fi
}
List_port_user(){
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} Пользователь не найден !" && exit 1
	user_list_all=""
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		user_username=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $2}'|sed 's/\[//g;s/\]//g')
		Get_User_transfer "${user_port}"
		transfer_enable_Used_233=$(echo $((${transfer_enable_Used_233}+${transfer_enable_Used_2_1})))
		user_list_all=${user_list_all}"Пользователь: ${Green_font_prefix} "${user_username}"${Font_color_suffix} Порт: ${Green_font_prefix}"${user_port}"${Font_color_suffix} Трафик: ${Green_font_prefix}${transfer_enable_Used_2}${Font_color_suffix}\n"
	done
	Get_User_transfer_all
	echo && echo -e "=== Всего пользователей: ${Green_background_prefix} "${user_total}" ${Font_color_suffix}"
	echo -e ${user_list_all}
	echo -e "=== Общий трафик всех пользователей: ${Green_background_prefix} ${transfer_enable_Used_233_2} ${Font_color_suffix}\n"
}
Add_port_user(){
	lalal=$1
	if [[ "$lalal" == "install" ]]; then
		match_add=$(python mujson_mgr.py -a -u "${ssr_user}" -p "${ssr_port}" -k "${ssr_password}" -m "${ssr_method}" -O "${ssr_protocol}" -G "${ssr_protocol_param}" -o "${ssr_obfs}" -s "${ssr_speed_limit_per_con}" -S "${ssr_speed_limit_per_user}" -t "${ssr_transfer}" -f "${ssr_forbid}"|grep -w "add user info")
	else
		while true
		do
			Set_config_all
			match_port=$(python mujson_mgr.py -l|grep -w "port ${ssr_port}$")
			[[ ! -z "${match_port}" ]] && echo -e "${Error} Порт [${ssr_port}] уже используется, выберите другой !" && exit 1
			match_username=$(python mujson_mgr.py -l|grep -w "user \[${ssr_user}]")
			[[ ! -z "${match_username}" ]] && echo -e "${Error} Имя пользователя [${ssr_user}] уже используется, выберите другое !" && exit 1
			match_add=$(python mujson_mgr.py -a -u "${ssr_user}" -p "${ssr_port}" -k "${ssr_password}" -m "${ssr_method}" -O "${ssr_protocol}" -G "${ssr_protocol_param}" -o "${ssr_obfs}" -s "${ssr_speed_limit_per_con}" -S "${ssr_speed_limit_per_user}" -t "${ssr_transfer}" -f "${ssr_forbid}"|grep -w "add user info")
			if [[ -z "${match_add}" ]]; then
				echo -e "${Error} Не удалось добавить пользователя ${Green_font_prefix}[Имя пользователя: ${ssr_user} , Порт: ${ssr_port}]${Font_color_suffix} "
				break
			else
				Add_iptables
				Save_iptables
				setiplimit
				echo -e "${Info} Пользователь добавлен успешно ${Green_font_prefix}[Пользователь: ${ssr_user} , Порт: ${ssr_port}]${Font_color_suffix} "
				echo
				Get_User_info "${ssr_port}"
				View_User_info
				read -e -p "Хотите настроить автоудаление пользователя?[Y/n]:" autoyn
				[[ -z ${autoyn} ]] && autoyn="y"
				if [[ ${autoyn} == [Yy] ]]; then
					apt install at
					sudo systemctl enable --now atd
					port=${ssr_port}
					clear
					echo
					echo
					echo
					echo
					echo		
					read -e -p "Введите период удаления в днях:" periodofdel
					at now +$periodofdel days <<ENDMARKER
python "/usr/local/shadowsocksr/mujson_mgr.py" -d -p '${ssr_port}'
ENDMARKER
					clear
					echo
					echo
					echo
					echo -e "Пользователь с портом ${Green_font_prefix}$ssr_port${Font_color_suffix} будет удален через $periodofdel дней."
					break
				fi					
				break
			fi
		done
	fi
}
Del_port_user(){
	List_port_user
	while true
	do
		echo -e "Введите порт пользователя для удаления"
		read -e -p "(По умолчанию: отмена):" del_user_port
		[[ -z "${del_user_port}" ]] && echo -e "Отмена..." && exit 1
		del_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${del_user_port}"',')
		if [[ ! -z ${del_user} ]]; then
			port=${del_user_port}
			match_del=$(python mujson_mgr.py -d -p "${del_user_port}"|grep -w "delete user ")
			if [[ -z "${match_del}" ]]; then
				echo -e "${Error} Ошибка удаления пользователя! ${Green_font_prefix}[Порт: ${del_user_port}]${Font_color_suffix} "
				break
			else
				Del_iptables
				Save_iptables
				echo -e "${Info} Удаление пользователя успешно завершено ${Green_font_prefix}[Порт: ${del_user_port}]${Font_color_suffix} "
				echo
				read -e -p "Хотите продолжить удаление пользователей？[Y/n]:" delyn
				[[ -z ${delyn} ]] && delyn="y"
				if [[ ${delyn} == [Nn] ]]; then
					break
				else
					echo -e "${Info} Продолжение удаления пользователей..."
					Del_port_user
				fi
			fi
			break
		else
			echo -e "${Error} Введите корректный порт !"
		fi
	done
}
Manually_Modify_Config(){
	SSR_installation_status
	nano ${config_user_mudb_file}
	echo "Перезапустить ShadowsocksR？[Y/n]" && echo
	read -e -p "(По умолчанию: y):" yn
	[[ -z ${yn} ]] && yn="y"
	if [[ ${yn} == [Yy] ]]; then
		Restart_SSR
	fi
}
Clear_transfer(){
	SSR_installation_status
	echo && echo -e "Что вы хотите делать？
 ${Green_font_prefix}1.${Font_color_suffix}  Удалить трафик, использованные одним пользователем
 ${Green_font_prefix}2.${Font_color_suffix}  Удалить трафик всех пользователей
 ${Green_font_prefix}3.${Font_color_suffix}  Запустить самоочистку трафика пользователей
 ${Green_font_prefix}4.${Font_color_suffix}  Остановить самоочистку трафика пользователей
 ${Green_font_prefix}5.${Font_color_suffix}  Модификация времени самоочистки трафика пользователей" && echo
	read -e -p "(По умолчанию: Отмена):" ssr_modify
	[[ -z "${ssr_modify}" ]] && echo "Отмена..." && exit 1
	if [[ ${ssr_modify} == "1" ]]; then
		Clear_transfer_one
	elif [[ ${ssr_modify} == "2" ]]; then
		echo "Вы действительно хотите очистить трафик всех пользователей？[y/N]" && echo
		read -e -p "(По умолчанию: n):" yn
		[[ -z ${yn} ]] && yn="n"
		if [[ ${yn} == [Yy] ]]; then
			Clear_transfer_all
		else
			echo "Отмена..."
		fi
	elif [[ ${ssr_modify} == "3" ]]; then
		check_crontab
		Set_crontab
		Clear_transfer_all_cron_start
	elif [[ ${ssr_modify} == "4" ]]; then
		check_crontab
		Clear_transfer_all_cron_stop
	elif [[ ${ssr_modify} == "5" ]]; then
		check_crontab
		Clear_transfer_all_cron_modify
	else
		echo -e "${Error} Введите корректный номер(1-5)" && exit 1
	fi
}
Clear_transfer_one(){
	List_port_user
	while true
	do
		echo -e "Введите порт пользователя, трафик которого нужно очистить"
		read -e -p "(По умолчанию: отмена):" Clear_transfer_user_port
		[[ -z "${Clear_transfer_user_port}" ]] && echo -e "Отмена..." && exit 1
		Clear_transfer_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${Clear_transfer_user_port}"',')
		if [[ ! -z ${Clear_transfer_user} ]]; then
			match_clear=$(python mujson_mgr.py -c -p "${Clear_transfer_user_port}"|grep -w "clear user ")
			if [[ -z "${match_clear}" ]]; then
				echo -e "${Error} Не удалось очистить трафик пользователя! ${Green_font_prefix}[Порт: ${Clear_transfer_user_port}]${Font_color_suffix} "
			else
				echo -e "${Info} Трафик пользователя успешно очищен! ${Green_font_prefix}[Порт: ${Clear_transfer_user_port}]${Font_color_suffix} "
			fi
			break
		else
			echo -e "${Error} Введите корректный порт !"
		fi
	done
}
Clear_transfer_all(){
	cd "${ssr_folder}"
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} Не найдено пользователей !" && exit 1
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		match_clear=$(python mujson_mgr.py -c -p "${user_port}"|grep -w "clear user ")
		if [[ -z "${match_clear}" ]]; then
			echo -e "${Error} Не удалось очистить трафик пользователя!  ${Green_font_prefix}[Порт: ${user_port}]${Font_color_suffix} "
		else
			echo -e "${Info} Трафик пользователя успешно очищен! ${Green_font_prefix}[Порт: ${user_port}]${Font_color_suffix} "
		fi
	done
	echo -e "${Info} Весь трафик пользователей успешно очищен !"
}
Clear_transfer_all_cron_start(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ssrmu.sh/d" "$file/crontab.bak"
	echo -e "\n${Crontab_time} /bin/bash $file/ssrmu.sh clearall" >> "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssrmu.sh")
	if [[ -z ${cron_config} ]]; then
		echo -e "${Error} Очистка трафика пользователей регулярно не запущено !" && exit 1
	else
		echo -e "${Info} Очистка трафика пользователей регулярно запущено !"
	fi
}
Clear_transfer_all_cron_stop(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ssrmu.sh/d" "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssrmu.sh")
	if [[ ! -z ${cron_config} ]]; then
		echo -e "${Error} Не удалось остановить самоочистку трафика пользователей !" && exit 1
	else
		echo -e "${Info} Удалось остановить самоочистку трафика пользователей !"
	fi
}
Clear_transfer_all_cron_modify(){
	Set_crontab
	Clear_transfer_all_cron_stop
	Clear_transfer_all_cron_start
}
Set_crontab(){
		echo -e "Введите временный интервал для очистки трафика
 === Описание формата ===
 * * * * * Минуты, часы, дни, месяцы, недели
 ${Green_font_prefix} 0 2 1 * * ${Font_color_suffix} Означает каждый месяц 1-го числа в 2 часа
 ${Green_font_prefix} 0 2 15 * * ${Font_color_suffix} Означает каждый месяц 15-го числа в 2 часа
 ${Green_font_prefix} 0 2 */7 * * ${Font_color_suffix} Каждые 7 дней в 2 часа
 ${Green_font_prefix} 0 2 * * 0 ${Font_color_suffix} Каждое воскресенье
 ${Green_font_prefix} 0 2 * * 3 ${Font_color_suffix} Каждую среду" && echo
	read -e -p "(По умолчанию: 0 2 1 * * Тоесть каждое 1-е число месяца в 2 часа):" Crontab_time
	[[ -z "${Crontab_time}" ]] && Crontab_time="0 2 1 * *"
}
Start_SSR(){
	SSR_installation_status
	check_pid
	[[ ! -z ${PID} ]] && echo -e "${Error} ShadowsocksR запущен !" && exit 1
	/etc/init.d/ssrmu start
}
Stop_SSR(){
	SSR_installation_status
	check_pid
	[[ -z ${PID} ]] && echo -e "${Error} ShadowsocksR не запущен !" && exit 1
	/etc/init.d/ssrmu stop
}
Server_IP_Checker(){
	 echo -e "IP данного сервера = $(curl "ifconfig.me") " && echo
}
Set_user_api_server_pub_addr(){
	addr=$1
	if [[ "${addr}" == "Modify" ]]; then
		server_pub_addr=$(cat ${config_user_api_file}|grep "SERVER_PUB_ADDR = "|awk -F "[']" '{print $2}')
		if [[ -z ${server_pub_addr} ]]; then
			echo -e "${Error} Не удалось получить IP сервера！" && exit 1
		else
			echo -e "${Info} Текущий IP： ${Green_font_prefix}${server_pub_addr}${Font_color_suffix}"
		fi
	fi
	echo "Введите доменное имя или IP-адрес сервера"
	read -e -p "(Автоматическое определение IP при нажатии Enter):" ssr_server_pub_addr
	if [[ -z "${ssr_server_pub_addr}" ]]; then
		Get_IP
		if [[ ${ip} == "VPS_IP" ]]; then
			while true
			do
			read -e -p "${Error} Введите IP сервера вручную!" ssr_server_pub_addr
			if [[ -z "$ssr_server_pub_addr" ]]; then
				echo -e "${Error} Не может быть пустым！"
			else
				break
			fi
			done
		else
			ssr_server_pub_addr="${ip}"
		fi
	fi
	echo && echo ${Separator_1} && echo -e "	IP сервера : ${Green_font_prefix}${ssr_server_pub_addr}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Modify_user_api_server_pub_addr(){
	sed -i "s/SERVER_PUB_ADDR = '${server_pub_addr}'/SERVER_PUB_ADDR = '${ssr_server_pub_addr}'/" ${config_user_api_file}
}
Restart_SSR(){
	SSR_installation_status
	check_pid
	[[ ! -z ${PID} ]] && /etc/init.d/ssrmu stop
	/etc/init.d/ssrmu start
}
# Меню
menu_status(){
	if [[ -e ${ssr_folder} ]]; then
		check_pid
		if [[ ! -z "${PID}" ]]; then
			echo -e " Текущий статус: ${Green_font_prefix}установлен${Font_color_suffix} и ${Green_font_prefix}запущен${Font_color_suffix}"
		else
			echo -e " Текущий статус: ${Green_font_prefix}установлен${Font_color_suffix} но ${Red_font_prefix}не запущен${Font_color_suffix}"
		fi
		cd "${ssr_folder}"
	else
		echo -e " Текущий статус: ${Red_font_prefix}не установлен${Font_color_suffix}"
	fi
}
Upload_DB(){
	echo -e "${Green_font_prefix}Перед вам выйдет строка с ссылкой на файлообменник, откуда вы сможете скачать базу данных. 
	Пример строки:{'success':'true','key':**********,'link':https://file.io/***********,'expiry':14 days} 
	Введите строку из поля 'link' в браузере, и ваша база данных будет скачана. ${Font_color_suffix}"
	curl -F "file=@/usr/local/shadowsocksr/mudb.json" "https://file.io" && echo -e "${Green_font_prefix}Закрытие программы...${Font_color_suffix}"
}
Download_DB(){
	echo -e "${Green_font_prefix} Внимание: это приведет к перезаписи всей базы пользователей, вы готовы что хотите продолжить?${Font_color_suffix}(y/n)"
	read -e -p "(По умолчанию: отмена):" base_override
	[[ -z "${base_override}" ]] && echo "Отмена..." && exit 1
	if [[ ${base_override} == "y" ]]; then
		read -e -p "${Green_font_prefix} Введите ссылку на базу: (полученная в 15 пункте):(Если вы ее не сделали, то введите 'n')${Font_color_suffix}" base_link && echo
		[[ -z "${base_link}" ]] && echo "Отмена..." && exit 1
		if [[ ${base_link} == "n" ]]; then
   echo "Отмена..." && exit 1
else 
   cd /usr/local/shadowsocksr
   rm "/usr/local/shadowsocksr/mudb.json"
   curl -o "mudb.json" "${base_link}"   
   echo -e "База успешно импортирована!"
fi
	elif [[ ${base_override} == "n" ]]; then
		echo "Отмена..." && exit 1
	fi
}
check_sys
[[ ${release} != "debian" ]] && [[ ${release} != "ubuntu" ]] && [[ ${release} != "centos" ]] && echo -e "${Error} 本脚本不支持当前系统 ${release} !" && exit 1
action=$1
if [[ "${action}" == "clearall" ]]; then
	Clear_transfer_all
elif [[ "${action}" == "monitor" ]]; then
	crontab_monitor_ssr
else
	domainofserver=$(cat ${config_user_api_file} | grep "SERVER_PUB_ADDR = " | awk -F "[']" '{print $2}')
 echo -e "${Blue_background_prefix}Chieftain && xyl1gun4eg && Veron SSpro Control${Font_color_suffix}
 
 Ты на сервере ${Green_background_prefix}$domainofserver${Font_color_suffix}

  ${Green_font_prefix}1.${Font_color_suffix} Создать ключ
  ${Green_font_prefix}2.${Font_color_suffix} Удалить ключ
  ${Green_font_prefix}3.${Font_color_suffix} Изменить пароль
  ${Green_font_prefix}4.${Font_color_suffix} Информация о клиентах
  ${Green_font_prefix}5.${Font_color_suffix} Изменить адрес сервера
————————————
  ${Green_font_prefix}6.${Font_color_suffix} Выгрузить БД
  ${Green_font_prefix}7.${Font_color_suffix} Загрузить БД
 ————————————
  ${Green_font_prefix}8.${Font_color_suffix} Очистить трафик
  ${Green_font_prefix}9.${Font_color_suffix} Изменить конфигурацию
————————————
 ${Green_font_prefix}10.${Font_color_suffix} Установить Libsodium
 ${Green_font_prefix}11.${Font_color_suffix} Выкл ShadowSocksR
 ${Green_font_prefix}12.${Font_color_suffix} Вкл ShadowSocksR
 ${Green_font_prefix}13.${Font_color_suffix} Перезапустить ShadowsocksR
 ${Green_font_prefix}14.${Font_color_suffix} Установить ShadowSocksR
 ${Green_font_prefix}15.${Font_color_suffix} Удалить ShadowSocksR
 ${Green_font_prefix}16.${Font_color_suffix} Просмотреть ip сервера
————————————
 "
	menu_status
	echo && read -e -p "Введите корректный номер [1-16]：" num
case "$num" in
	1)
	Add_port_user
	;;
	2)
	Del_port_user
	;;
	3)
	Modify_port
	Set_config_password
	Modify_config_password
	;;
	4)
	View_User
	;;
	5)
	Set_user_api_server_pub_addr "Modify"
	Modify_user_api_server_pub_addr
	;;
	6)
	Upload_DB
	;;
	7)
	Download_DB
	;;
	8)
	Clear_transfer
	;;
	9)
	Manually_Modify_Config
	;;
	10)
	Install_Libsodium
	;;
	11)
	Stop_SSR
	;;
	12)
	Start_SSR
	;;
	13)
	Restart_SSR
	;;
	14)
	Install_SSR
        ;;
        15)
	Uninstall_SSR
        ;;
        16)
        Server_IP_Checker
	     ;;
	*)
	echo -e "${Error} Введите корректный номер [1-16]"
	;;
esac
fi
