#! /bin/bash



echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>系统基本信息<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
hostname=$(uname -n)
system=$(cat /etc/os-release | grep "^NAME" | awk -F\" '{print $2}')
version=$(cat /etc/redhat-release | awk '{print $7$8}')
kernel=$(uname -r)
platform=$(uname -p)
address=$(ip addr | grep inet | grep -v "inet6" | grep -v "127.0.0.1" | awk '{ print $2; }' | tr '\n' '\t' )
cpumodel=$(cat /proc/cpuinfo | grep name | awk -F ": " '{print $2}' | head -n 1 )
cpu=$(cat /proc/cpuinfo | grep 'processor' | sort | uniq | wc -l)
machinemodel=$(dmidecode | grep "Product Name" | sed 's/^[ \t]*//g' | head -n 1 )
date=$(date)

echo "主机名:           $hostname"
echo "系统名称:         $system"
echo "系统版本:         $version"
echo "内核版本:         $kernel"
echo "系统类型:         $platform"
echo "本机IP地址:       $address"
echo "CPU型号:          $cpumodel"
echo "CPU核数:          $cpu"
echo "机器型号:         $machinemodel"
echo "系统时间:         $date"


echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
echo " "
echo " "
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>资源使用情况<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
summemory=$(free -h |grep "Mem:" | awk '{print $2}')
usagememory=$(free -h |grep "Mem:" | awk '{print $3}')
freememory=$(free -h |grep "Mem:" | awk '{print $4}')
sumswap=$(free -h |grep "Swap:" | awk '{print $2}')
usageswap=$(free -h |grep "Swap:" | awk '{print $3}')
freeswap=$(free -h |grep "Swap:" | awk '{print $4}')
loadavg=$(uptime | awk '{print $8" "$9" "$10" "$11" "$12" "$13}')
runtime=$(cat /proc/uptime| awk -F. '{run_days=$1 / 86400;run_hour=($1 % 86400)/3600;run_minute=($1 % 3600)/60;run_second=$1 % 60;printf("%d天%d时%d分%d秒",run_days,run_hour,run_minute,run_second)}')
uptime=$(date -d "$(awk -F. '{print $1}' /proc/uptime) second ago" +"%Y-%m-%d %H:%M:%S")

echo "总内存大小:           $summemory"
echo "已使用内存大小:       $usagememory"
echo "可使用内存大小:       $freememory"
echo "总交换分区大小:       $sumswap"
echo "已使用交换分区大小：  $usageswap"
echo "可使用交换分区大小:   $freeswap"
echo "系统负载:             $loadavg"
echo "系统运行时间:         $runtime"
echo "系统启动时间：        $uptime"
echo =============================================================================
echo "僵尸进程:"
ps -ef | grep zombie | grep -v grep
if [ $? == 1 ];then
    echo "无僵尸进程"
else
    echo "有僵尸进程"
fi
echo =============================================================================
echo  "路由表:"
route -n
echo =============================================================================
echo  "监听端口:"
netstat -tunlp
echo =============================================================================
echo "开机启动的服务:"
systemctl list-unit-files | grep enabled


echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
echo " "
echo " "
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>系统用户情况<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
echo  "活动用户:"
w | tail -n +2
echo =============================================================================
echo  "系统所有用户:"
cut -d: -f1,2,3,4 /etc/passwd
echo =============================================================================
echo  "系统所有组:"
cut -d: -f1,2,3 /etc/group
echo =============================================================================
echo  "当前用户的计划任务:"
crontab -l


echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
echo " "
echo " "
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>身份鉴别安全<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
#密码复杂度
grep -i "^password.*requisite.*pam_cracklib.so" /etc/pam.d/system-auth  > /dev/null
if [ $? == 0 ];then
    echo "密码复杂度:         已设置"
else
    grep -i "pam_pwquality\.so" /etc/pam.d/system-auth > /dev/null
    if [ $? == 0 ];then
	echo "密码复杂度:         已设置"
    else
	echo "密码复杂度:         未设置,请加固密码"
    fi
fi

#登陆失败锁定检测
grep -i "^auth.*required.*pam_tally2.so.*$" /etc/pam.d/system-auth  > /dev/null
if [ $? == 0 ];then
  echo "登入失败锁定处理:   已开启"
else
  echo "登入失败锁定处理:   未开启,请加固登入失败锁定功能"
fi
echo =============================================================================
#禁止root远程登陆
grep -i "^PermitRootLogin.*no" /etc/ssh/sshd_config > /dev/null
if [ $? == 0 ];then
  echo "禁止root远程登陆:   已开启"
else
  echo "禁止root远程登陆:   未开启,请加禁止root远程登陆功能"
fi
echo =============================================================================
awk -F":" '{if($2!~/^!|^*/){print "("$1")" " 是一个未被锁定的账户,请管理员检查是否是可疑账户"}}' /etc/shadow
echo =============================================================================
more /etc/login.defs | grep -E "PASS_MAX_DAYS" | grep -v "#" |awk -F' '  '{if($2!=90){print "密码最长使用期限是:    "$2"天,请管理员改成90天"}}'
more /etc/login.defs | grep -E "PASS_MIN_DAYS" | grep -v "#" |awk -F' '  '{if($2!=1){print "密码最短使用期限是:    "$2"天,请管理员改成1天"}}'
more /etc/login.defs | grep -E "PASS_WARN_AGE" | grep -v "#" |awk -F' '  '{if($2!=28){print "密码过期警告时间是:    "$2"天,请管理员改成28天"}}'
more /etc/login.defs | grep -E "PASS_MIN_LEN" | grep -v "#" |awk -F' '  '{if($2!=8){print "密码长度最小值是:      "$2",请管理员改成8"}}'


echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
echo " "
echo " "
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>访问控制安全<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
echo "系统中存在以下非系统默认用户:"
more /etc/passwd |awk -F ":" '{if($3>500){print "/etc/passwd里面的"$1 "的UID为"$3"，该账户非系统默认账户，请管理员确认是否为可疑账户"}}'
echo =============================================================================
echo "系统特权用户:"
awk -F: '$3==0 {print $1}' /etc/passwd
echo =============================================================================
echo "空口令账户:"
awk -F: '($2=="") {print $1"该账户为空口令账户，请管理员确认是否为新增账户，如果为新建账户，请配置密码"}' /etc/shadow


echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
echo " "
echo " "
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>安全审计<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
echo "查看rsyslog日志审计服务是否开启:"
if service rsyslog status | egrep " active \(running";then
  echo "rsyslog服务已开启"
else
  echo "rsyslog服务未开启，建议通过service rsyslog start开启日志审计功能"
fi
echo =============================================================================
echo "检查重要文件权限"
file_passwd=$(ls -l /etc/passwd | awk '{print $1}')  #不超过644
file_group=$(ls -l /etc/group | awk '{print $1}')   #不超过644
file_shadow=$(ls -l /etc/shadow | awk '{print $1}')  #不超过400
file_crontab=$(ls -l /etc/crontab | awk '{print $1}')  #不超过644
echo "/etc/passwd 文件权限为${file_passwd} ----- 建议不超过644"
echo "/etc/group 文件权限为${file_group} ----- 建议不超过644"
echo "/etc/shadow 文件权限为${file_shadow} ----- 建议不超过400"
echo "/etc/crontab 文件权限为${file_crontab} ----- 建议不超过644"
echo =============================================================================
#检查rsyslog.conf
grep -i "^\*\.info\;mail\.none\;authpriv\.none\;cron\.none.*/var/log/messages" /etc/rsyslog.conf > /dev/null
if [ $? == 0 ];then
  echo "已存在*.info;mail.none;authpriv.none;cron.none /var/log/messages"
else
  echo "请补充*.info;mail.none;authpriv.none;cron.none /var/log/messages"
fi

grep -i "^authpriv\.\*.*/var/log/secure" /etc/rsyslog.conf > /dev/null
if [ $? == 0 ];then
  echo "已存在authpriv.* /var/log/secure"
else
  echo "请补充authpriv.* /var/log/secure"
fi

grep -i "^\*\.err.*/var/log/errors" /etc/rsyslog.conf > /dev/null
if [ $? == 0 ];then
  echo "已存在*.err /var/log/errors"
else
  echo "请补充*.err /var/log/errors"
fi

grep -i "^kern\.warning\;authpriv\.none.*/var/log/warn" /etc/rsyslog.conf > /dev/null
if [ $? == 0 ];then
  echo "已存在kern.warning;authpriv.none /var/log/warn"
else
  echo "请补充kern.warning;authpriv.none /var/log/warn"
fi

grep -i "^\*\.emerg.*/var/log/emerg.log" /etc/rsyslog.conf > /dev/null
if [ $? == 0 ];then
  echo "已存在*.emerg /var/log/emerg.log"
else
  echo "请补充*.emerg /var/log/emerg.log"
fi

grep -i "^local7\.\*.*/var/log/boot.log" /etc/rsyslog.conf > /dev/null
if [ $? == 0 ];then
  echo "已存在local7.* /var/log/boot.log"
else
  echo "请补充local7.* /var/log/boot.log"
fi

echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
echo " "
echo " "
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>剩余信息保护<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
echo "分区情况:"
echo "如果磁盘空间利用率过高，请及时调整"
df -hT
echo =============================================================================
echo "可用块设备信息:"
lsblk
echo =============================================================================
echo "文件系统信息:"
more /etc/fstab  | grep -v "^#" | grep -v "^$"
echo " "
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>入侵防范安全<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
echo "系统入侵行为:"
more /var/log/secure |grep refused
if [ $? == 0 ];then
    echo "有入侵行为，请分析处理"
else
    echo "无入侵行为"
fi
echo ""
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
echo " "
echo " "
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>资源控制安全<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
echo "查看系统SSH远程访问设置策略(hosts.allow允许列表和host.deny拒绝列表):"
if more /etc/hosts.allow | grep -E "sshd"; then
  echo "hosts.allow远程访问策略已设置"
else
  echo "hosts.allow远程访问策略未设置"
fi

if more /etc/hosts.deny | grep -E "sshd"; then
  echo "host.deny远程访问策略已设置"
else
  echo "host.deny远程访问策略未设置"
fi
echo =============================================================================
echo "登陆超时限制设置："
grep -i "TMOUT" /etc/profile /etc/bashrc
if [ $? == 0 ];then
    echo "已设置登入超时限制"
else
    echo "未设置登入超时限制,请设置,设置方法:在/etc/profile或者/etc/bashrc里面添加参数TMOUT=1800"
fi









