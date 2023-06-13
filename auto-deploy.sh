#!/bin/bash
# 下再免密批量ssh密钥验证
read  -p "输入同步ssh密钥设备密码： $1" -s passwd
yum -y install sshpass

# 生成密钥 
if [[ $(hostname) == *"master"* ]]; then
  ssh-keygen -t rsa -b 2048 -N '' -f  /root/.ssh/id_rsa -q
  chmod 0400 /root/.ssh/id_rsa
  for i in {10..12}
  do
  sshpass -p$passwd ssh-copy-id -i ~/.ssh/id_rsa.pub -o "StrictHostKeyChecking=no" root@192.168.0.$i
  done
fi

# 修改主机名
#----------------------------
hostnamectl set-hostname k8s-master
ssh 192.168.0.11 hostnamectl set-hostname k8s-worker1
ssh 192.168.0.12 hostnamectl set-hostname k8s-worker2

# /etc/hosts域名解析
#----------------
cat >> /etc/hosts << EOF
192.168.0.10 k8s-master etcd-1 registry
192.168.0.11 k8s-worker1 etcd-2
192.168.0.12 k8s-worker2 etcd-3
EOF
#-------------------------------------------------------------------------------------------------



####################################### 函数定义 ##################################################
#--------------------------------------------------------------------------------------------------
hostname=$(hostname)
hostip=$(ifconfig eth0 | awk '/inet / {print $2}')
workerip1=$(awk '/.*worker1.*/{print $1}' /etc/hosts)
workerip2=$(awk '/.*worker2.*/{print $1}' /etc/hosts)
registry=$(awk '/.*k8s-master.*/{print $4}' /etc/hosts):5000

# etcd包名和url
etcdfile="etcd-v3.5.1-linux-amd64.tar.gz"
etcdurl="https://github.com/etcd-io/etcd/releases/download/v3.5.1/etcd-v3.5.1-linux-amd64.tar.gz"

# docker包名和url
dockerfile="docker-20.10.9.tgz"
dockerurl="https://download.docker.com/linux/static/stable/x86_64/docker-20.10.9.tgz"

# kubernetes包名和url
k8sfile="kubernetes-server-linux-amd64.tar.gz"
k8surl="https://dl.k8s.io/v1.22.17/kubernetes-server-linux-amd64.tar.gz"

#-------------------------------------------------------------------------------------------------



####################################### 基础环境配置 ##################################################
#-----------------------------------------------------------------------------------------------------
# 同步本地域名解析
rsync -av /etc/hosts $workerip1:/etc/
rsync -av /etc/hosts $workerip2:/etc/

# 创建相关目录
mkdir -p /opt/etcd/{bin,cfg,ssl}
mkdir -p /opt/k8s/{bin,cfg,ssl,logs,yaml}
mkdir -p /data/TLS/{etcd,k8s}

rsync -av /opt/{etcd,k8s} $workerip1:/opt/
rsync -av /opt/{etcd,k8s} $workerip2:/opt/

# 启用IPVS模式
#-----------------
cat > /etc/sysctl.d/k8s.conf << EOF
net.ipv4.ip_forward = 1
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
fs.may_detach_mounts = 1
vm.overcommit_memory=1
vm.panic_on_oom=0
fs.inotify.max_user_watches=89100
fs.file-max=52706963
fs.nr_open=52706963
net.netfilter.nf_conntrack_max=2310720
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_keepalive_intvl =15
net.ipv4.tcp_max_tw_buckets = 36000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_orphans = 327680
net.ipv4.tcp_orphan_retries = 3
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.ip_conntrack_max = 65536
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_timestamps = 0
net.core.somaxconn = 16384
EOF

sysctl --system

yum -y install ipvsadm ipset conntrack-tools >> /dev/null
[ $? == 0 ] && echo "下载完成" || echo "软件名错误或不存在" 

ssh root@$workerip1 'bash -c "echo -e \"net.ipv4.ip_forward = 1\nnet.bridge.bridge-nf-call-iptables = 1\nnet.bridge.bridge-nf-call-ip6tables = 1\nfs.may_detach_mounts = 1\nvm.overcommit_memory=1\nvm.panic_on_oom=0\nfs.inotify.max_user_watches=89100\nfs.file-max=52706963\nfs.nr_open=52706963\nnet.netfilter.nf_conntrack_max=2310720\nnet.ipv4.tcp_keepalive_time = 600\nnet.ipv4.tcp_keepalive_probes = 3\nnet.ipv4.tcp_keepalive_intvl =15\nnet.ipv4.tcp_max_tw_buckets = 36000\nnet.ipv4.tcp_tw_reuse = 1\nnet.ipv4.tcp_max_orphans = 327680\nnet.ipv4.tcp_orphan_retries = 3\nnet.ipv4.tcp_syncookies = 1\nnet.ipv4.tcp_max_syn_backlog = 16384\nnet.ipv4.ip_conntrack_max = 65536\nnet.ipv4.tcp_max_syn_backlog = 16384\nnet.ipv4.tcp_timestamps = 0\nnet.core.somaxconn = 16384\" >> /etc/sysctl.d/k8s.conf"'
ssh root@$workerip2 'bash -c "echo -e \"net.ipv4.ip_forward = 1\nnet.bridge.bridge-nf-call-iptables = 1\nnet.bridge.bridge-nf-call-ip6tables = 1\nfs.may_detach_mounts = 1\nvm.overcommit_memory=1\nvm.panic_on_oom=0\nfs.inotify.max_user_watches=89100\nfs.file-max=52706963\nfs.nr_open=52706963\nnet.netfilter.nf_conntrack_max=2310720\nnet.ipv4.tcp_keepalive_time = 600\nnet.ipv4.tcp_keepalive_probes = 3\nnet.ipv4.tcp_keepalive_intvl =15\nnet.ipv4.tcp_max_tw_buckets = 36000\nnet.ipv4.tcp_tw_reuse = 1\nnet.ipv4.tcp_max_orphans = 327680\nnet.ipv4.tcp_orphan_retries = 3\nnet.ipv4.tcp_syncookies = 1\nnet.ipv4.tcp_max_syn_backlog = 16384\nnet.ipv4.ip_conntrack_max = 65536\nnet.ipv4.tcp_max_syn_backlog = 16384\nnet.ipv4.tcp_timestamps = 0\nnet.core.somaxconn = 16384\" >> /etc/sysctl.d/k8s.conf"'

ssh $workerip1 sysctl --system
ssh $workerip2 sysctl --system

ssh $workerip1 yum -y install ipvsadm ipset conntrack-tools >> /dev/null
[ $? == 0 ] && echo "下载完成" || echo "软件名错误或不存在" 
ssh $workerip2 yum -y install ipvsadm ipset conntrack-tools >> /dev/null
[ $? == 0 ] && echo "下载完成" || echo "软件名错误或不存在" 

# 关闭交换分区
#---------------------
swapoff -a
sed '/swap/ s,^,#,'  /etc/fstab -i
free -h

ssh $workerip1 swapoff -a
ssh $workerip2 swapoff -a

ssh $workerip1 "sed '/swap/ s,^,#,'  /etc/fstab -i"
ssh $workerip2 "sed '/swap/ s,^,#,'  /etc/fstab -i"

ssh $workerip1 free -h
ssh $workerip2 free -h

# 关闭SELinux
#-----------------------
setenforce 0
sed -i 's,SELINUX=enforcing,SELINUX=disabled,g' /etc/selinux/config
getenforce

ssh $workerip1 "sed -i 's,SELINUX=enforcing,SELINUX=disabled,g' /etc/selinux/config"
ssh $workerip2 "sed -i 's,SELINUX=enforcing,SELINUX=disabled,g' /etc/selinux/config"

ssh $workerip1 setenforce 0
ssh $workerip2 setenforce 0

# 关闭firewalld
#-------------------------
systemctl stop firewalld 
systemctl disable firewalld
yum -y remove firewalld  >> /dev/null
[ $? == 0 ] && echo "成功删除firewalld" || echo "删除失败或不存在" 

ssh root@$workerip1 systemctl stop firewalld
ssh root@$workerip2 systemctl stop firewalld

ssh root@$workerip1 systemctl disable firewalld
ssh root@$workerip2 systemctl disable firewalld

ssh root@$workerip1 yum -y remove firewalld >> /dev/null
[ $? == 0 ] && echo "成功删除firewalld" || echo "删除失败或不存在" 
ssh root@$workerip2 yum -y remove firewalld >> /dev/null
[ $? == 0 ] && echo "成功删除firewalld" || echo "删除失败或不存在" 

# 时间同步
#---------------------------
yum -y install cronie
yum -y install ntp ntpdate
sed '/^server/  s,^,#,' /etc/ntp.conf -i
sed '/^#server 3/a  server 127.127.1.1' /etc/ntp.conf -i
systemctl restart ntpd.service 
[ $? == 0 ] && echo "服务启动成功" || echo "服务启动失败"
service ntpd status | grep "running" >> /dev/null
[ $? == 0 ] && echo "状态正常成功" || echo "服务状态异常"
systemctl enable ntpd.service


ssh $workerip1 yum -y install ntp
ssh $workerip1 "sed -E '/^server 3/a\server $hostip\\nFudge $hostip stratum 10' /etc/ntp.conf"
ssh $workerip1 systemctl restart ntpd.service
[ $? == 0 ] && echo "重启成功" || echo "重启失败"
ssh $workerip1 systemctl stop ntpd.service
[ $? == 0 ] && echo "关闭成功"
ssh $workerip1 service ntpd status  >> /dev/null
[ $? == 0 ] && echo "关闭状态"
ssh $workerip1 ntpdate $hostip
[ $? == 0 ] && echo "worker1时间同步成功" || echo "worker1时间同步失败"
ssh $workerip1 "echo \"* */5 * * * ntpdate $hostip\" | crontab -"

ssh $workerip2 yum -y install ntp
ssh $workerip2 "sed -E '/^server 3/a\server $hostip\\nFudge $hostip stratum 10' /etc/ntp.conf"
ssh $workerip2 systemctl restart ntpd.service
[ $? == 0 ] && echo "重启成功" || echo "重启失败"
ssh $workerip2 systemctl stop ntpd.service
[ $? == 0 ] && echo "关闭成功"
ssh $workerip2 service ntpd status >> /dev/null
[ $? == 0 ] && echo "关闭状态"
ssh $workerip2 ntpdate $hostip
[ $? == 0 ] && echo "worker2时间同步成功" || echo "worker2时间同步失败"
ssh $workerip2 "echo \"* */5 * * * ntpdate $hostip\" | crontab -"

#配置加载系统模块
#---------------------
cat > /etc/modules-load.d/ipvs.conf <<EOF 
ip_vs
ip_vs_rr
ip_vs_wrr
ip_vs_sh
nf_conntrack_ipv4
ipip
EOF
systemctl restart systemd-modules-load
systemctl enable systemd-modules-load
lsmod | grep ip_vs

ssh $workerip1 'bash -c "echo -e \"ip_vs\nip_vs_rr\nip_vs_wrr\nip_vs_sh\nnf_conntrack_ipv4\nipip\" >> /etc/modules-load.d/ipvs.conf"'
ssh $workerip2 'bash -c "echo -e \"ip_vs\nip_vs_rr\nip_vs_wrr\nip_vs_sh\nnf_conntrack_ipv4\nipip\" >> /etc/modules-load.d/ipvs.conf"'

ssh $workerip1 systemctl restart systemd-modules-load
ssh $workerip2 systemctl restart systemd-modules-load

ssh $workerip1 systemctl enable systemd-modules-load
ssh $workerip2 systemctl enable systemd-modules-load

ssh $workerip1 lsmod | grep ip_vs
ssh $workerip2 lsmod | grep ip_vs

# 设置limit打开数
#-----------------------
cat >> /etc/security/limits.conf<<EOF
* soft nofile 655360
* soft nofile 655360
* soft nproc 655650
* hard nproc 655650
EOF

ssh root@$workerip1 'bash -c "echo -e \"* soft nofile 655360\n* soft nofile 655360\n* soft nproc 655650\n* hard nproc 655650\" >> /etc/security/limits.conf"'

ssh root@$workerip2 'bash -c "echo -e \"* soft nofile 655360\n* soft nofile 655360\n* soft nproc 655650\n* hard nproc 655650\" >> /etc/security/limits.conf"'

# 下载相关工具
#----------------------
cd
yum -y install wget >> /dev/null
[ $? == 0 ] && echo "wget已下载" || echo "wget下载失败"

cfssl=(
  "https://pkg.cfssl.org/R1.2/cfssl_linux-amd64"
  "https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64"
  "https://pkg.cfssl.org/R1.2/cfssl-certinfo_linux-amd64"
)

for i in "${cfssl[@]}"; do
  if [[ "$(ls -A | grep ${i##*/} 2> /dev/null)" == "" ]];then
     echo "正在下载cfssl证书工具"
     wget "$i"
  else
     echo "${i##*/}"已存在
  fi
done

# 赋予执行权限，移到$PATH路径下
chmod +x cfssl*
cp cfssl_linux-amd64 /usr/local/bin/cfssl
cp cfssljson_linux-amd64 /usr/local/bin/cfssljson
cp cfssl-certinfo_linux-amd64 /usr/local/bin/cfssl-certinfo
#---------------------------------------------------------------------------------------------------



##################################### 部署本地镜像仓库 #############################################
#-------------------------------------------------------------------------------------------------
# 下载docker本地仓库程序
yum install -y docker-distribution &> /dev/null
[ $? == 0 ] && echo "docker-distribution已下载" || echo "docker-distribution下载失败"

# 启动程序
systemctl restart docker-distribution.service

# 设置开机自启
systemctl enable docker-distribution.service --now
#-------------------------------------------------------------------------------------------------



######################################## 部署docker ###############################################
#-------------------------------------------------------------------------------------------------
cd
# 下载docker二进制包

if [ -f "$dockerfile" ];then
  echo "$dockerfile 已存在，跳过下载。"
else
  echo "$dockerfile 正在下载。"
  wget "$dockerurl"
fi

# 解压二进制包
tar zxvf $dockerfile 
[ $? == 0 ] && echo "docker解压成功" || echo "docker解压失败" >> /root/k8s-deploy.log

# mv到$PATH可执行路径
rsync -av docker/* /usr/bin/ >> /dev/null
[ $? == 0 ] && echo "docker已同步至master:/usr/bin" || echo "docker同步master失败" >> /root/k8s-deploy.log
rsync -av docker/* $workerip1:/usr/bin/ >> /dev/nul
[ $? == 0 ] && echo "docker已同步至worker1:/usr/bin" || echo "docker同步worker1失败" >> /root/k8s-deploy.log
rsync -av docker/* $workerip2:/usr/bin/ >> /dev/nul
[ $? == 0 ] && echo "docker已同步至worker2:/usr/bin" || echo "docker同步worker2失败" >> /root/k8s-deploy.log


# 创建daemon.json的父目录
mkdir -p /etc/docker

# 配置镜像加速器、仓库地址、cgroup驱动等
cat > /etc/docker/daemon.json <<EOF
{
    "registry-mirrors": ["https://cy3j0usn.mirror.aliyuncs.com","https://k8s.gcr.io"],
    "exec-opts": ["native.cgroupdriver=systemd"],
    "insecure-registries": ["$hostip:5000","$registry"]
}
EOF

# 同步daemon.json
rsync -av /etc/docker $workerip1:/etc/ >> /dev/null
[ $? == 0 ] && echo "daemon.json已同步" || echo "daemon.json同步失败" >> /root/k8s-deploy.log
rsync -av /etc/docker $workerip2:/etc/ >> /dev/null
[ $? == 0 ] && echo "daemon.json已同步" || echo "daemon.json同步失败" >> /root/k8s-deploy.log

# system启动文件
cat > /usr/lib/systemd/system/docker.service << EOF
[Unit]
Description=Docker Application Container Engine
Documentation=https://docs.docker.com
After=network-online.target firewalld.service
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/bin/dockerd
ExecReload=/bin/kill -s HUP $MAINPID
LimitNOFILE=infinity
LimitNPROC=infinity
TimeoutStartSec=0
Delegate=yes
KillMode=process
Restart=on-failure
StartLimitBurst=3
StartLimitInterval=60s

[Install]
WantedBy=multi-user.target
EOF

# 同步启动文件
rsync -av /usr/lib/systemd/system/docker.service $workerip1:/usr/lib/systemd/system/ >> /dev/null
[ $? == 0 ] && echo "docker启动文件已同步至worker1" || echo "docker启动文件同步至worker1失败" 
rsync -av /usr/lib/systemd/system/docker.service $workerip2:/usr/lib/systemd/system/ >> /dev/null
[ $? == 0 ] && echo "docker启动文件已同步至worker2" || echo "docker启动文件同步至worker2失败"

# 重新加载配置文件
systemctl daemon-reload
ssh root@$workerip1 systemctl daemon-reload
ssh root@$workerip2 systemctl daemon-reload

# 启动docker
systemctl restart docker 
ssh root@$workerip1 systemctl restart docker
ssh root@$workerip2 systemctl restart docker

# 设置开机自启
systemctl enable docker --now
ssh root@$workerip1 systemctl enable docker --now
ssh root@$workerip2 systemctl enable docker --now

# 查看docker状态
systemctl status docker | grep -C1 "running" >> /dev/null
[ $? == 0 ] && echo "docker状态正常" || echo "docker状态异常" >> /root/k8s-deploy.log
ssh root@$workerip1 systemctl status docker | grep -C1 "running" >> /dev/null
[ $? == 0 ] && echo "docker状态正常" || echo "docker状态异常" >> /root/k8s-deploy.log
ssh root@$workerip2 systemctl status docker | grep -C1 "running" >> /dev/null
[ $? == 0 ] && echo "docker状态正常" || echo "docker状态异常" >> /root/k8s-deploy.log

# 查看加速器等设置情况
docker info | tail -9 | head -6 | grep "$registry" >> /dev/null
[ $? == 0 ] && echo "加速器设置成功" || echo "加速器设置失败" >> /root/k8s-deploy.log
ssh root@$workerip1 docker info | tail -9 | head -6 | grep "$registry" >> /dev/null
[ $? == 0 ] && echo "加速器设置成功" || echo "加速器设置失败" >> /root/k8s-deploy.log
ssh root@$workerip2 docker info | tail -9 | head -6 | grep "$registry" >> /dev/null
[ $? == 0 ] && echo "加速器设置成功" || echo "加速器设置失败" >> /root/k8s-deploy.log

# 下载相关镜像
# 定义需要下载的镜像列表
images=(
  "registry.cn-hangzhou.aliyuncs.com/google_containers/pause:3.6"
  "registry.cn-hangzhou.aliyuncs.com/google_containers/nginx-ingress-controller:v1.1.1"
  "registry.cn-hangzhou.aliyuncs.com/google_containers/kube-webhook-certgen:v1.1.1"
  "coredns/coredns:1.8.5"
)

for image in "${images[@]}"; do
  # 判断镜像是否已经存在
  if [[ "$(docker images -q $image 2> /dev/null)" == "" ]]; then
    echo "开始下载镜像：$image"
    docker pull "$image"
  else
    echo "镜像已存在：$image"
  fi
done

# 判断是否存在 myos.tar.xz 文件并进行加载
if [[ -f "myos.tar.xz" ]]; then
  echo "开始加载镜像 myos.tar.xz"
  docker load -i myos.tar.xz
else
  echo "文件 myos.tar.xz 不存在，跳过加载。"
fi

# 判断是否存在 flannel.tar.xz 文件并进行加载
if [[ -f "flannel.tar.xz" ]]; then
  echo "开始加载镜像 flannel.tar.xz"
  docker load -i flannel.tar.xz
else
  echo "文件 flannel.tar.xz 不存在，跳过加载。"
fi

# 上传私用镜像仓库
docker images | while read i t _;do
[[ "${t}" == "TAG" ]] && continue
[[ "${i}" =~ ^"$registry/".+ ]] && continue
docker tag ${i}:${t} $registry/library/${i##*/}:${t}
docker push $registry/library/${i##*/}:${t}
docker rmi ${i}:${t} $registry/library/${i##*/}:${t}
done
#-------------------------------------------------------------------------------------------------



####################################### 部署etcd集群 #############################################
#-------------------------------------------------------------------------------------------------
# 证书生成和签发 # 进入证书工作目录
cd /data/TLS/etcd

# 自签CA证书
cat > ca-config.json << EOF
{
  "signing": {
    "default": {
      "expiry": "87600h"
    },
    "profiles": {
      "etcd": {
         "expiry": "87600h",
         "usages": [
            "signing",
            "key encipherment",
            "server auth",
            "client auth"
        ]
      }
    }
  }
}
EOF

# 编写csr请求文件
cat > ca-csr.json << EOF
{
    "CN": "etcd CA",
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "L": "Guangzhou",
            "ST": "Guangzhou"
        }
    ]
}
EOF

# 生成CA证书，生成ca.pem和ca-key.pem、ca.csr
cfssl gencert -initca ca-csr.json | cfssljson -bare ca
[ $? == 0 ] && echo "CA证书已经生成" || echo "CA证书生成失败" >> /root/k8s-deploy.log

#hosts内可以多写几个预留IP
cat > server-csr.json << EOF
{
    "CN": "etcd",
    "hosts": [
    "$hostip",
    "$workerip1",
    "$workerip2",
    "192.168.0.13",
    "192.168.0.14"
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "L": "Guangzhou",
            "ST": "Guangzhou"
        }
    ]
}
EOF

# 生成server证书，生成server.pem和server-key.pem、server.csr文件
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=etcd server-csr.json | cfssljson -bare server
[ $? == 0 ] && echo "etcd证书生成成功" || echo "etcd证书生成失败" >> /root/k8s-deploy.log

# 拷贝证书到etcd证书目录下
rsync -av /data/TLS/etcd/*.pem /opt/etcd/ssl/ >> /dev/null
[ $? == 0 ] && echo "*.pem文件传输成功" || echo "*.pem文件传输失败" >> /root/k8s-deploy.log

# wget下载etcd二进制文件
cd

if [ -f "$etcdfile" ];then
  echo "$etcdfile 已存在，跳过下载。"
else
  echo "$etcdfile 正在下载。"
  wget "$etcdurl"
fi

# 解压tar包
tar xf $etcdfile 
[ $? == 0 ] && echo "etcd解压成功" || echo "etcd解压失败" >> /root/k8s-deploy.log

# 移动可执行二进制文件到etcd工作目录
mv etcd-v3.5.1-linux-amd64/etcd* /opt/etcd/bin >> /dev/null
[ $? == 0 ] && echo "etcd移动成功" || echo "etcd移动失败" >> /root/k8s-deploy.log

# 创建配置文件  # 注意修改节点名和对应IP地址
cat > /opt/etcd/cfg/etcd.conf << EOF
#[Member]
ETCD_NAME="etcd-1"
ETCD_DATA_DIR="/var/lib/etcd/default.etcd"
ETCD_LISTEN_PEER_URLS="https://$hostip:2380"
ETCD_LISTEN_CLIENT_URLS="https://$hostip:2379"

#[Clustering]
ETCD_INITIAL_ADVERTISE_PEER_URLS="https://$hostip:2380"
ETCD_ADVERTISE_CLIENT_URLS="https://$hostip:2379"
ETCD_INITIAL_CLUSTER="etcd-1=https://$hostip:2380,etcd-2=https://$workerip1:2380,etcd-3=https://$workerip2:2380"
ETCD_INITIAL_CLUSTER_TOKEN="etcd-cluster"
ETCD_INITIAL_CLUSTER_STATE="new"
EOF

# 同步etcd目录
rsync -av /opt/etcd  $workerip1:/opt/ >> /dev/null
[ $? == 0 ] && echo "同步etcd目录成功" || echo "同步etcd目录失败" >> /root/k8s-deploy.log
rsync -av /opt/etcd  $workerip2:/opt/ >> /dev/null
[ $? == 0 ] && echo "同步etcd目录成功" || echo "同步etcd目录失败" >> /root/k8s-deploy.log

# 修改对应节点配置
sed  's,ETCD_NAME="etcd-1",ETCD_NAME="etcd-2",' /opt/etcd/cfg/etcd.conf | sed -E "/ETCD_INITIAL_CLUSTER/! s,$hostip,$workerip1,g" | ssh root@$workerip1 "cat > /opt/etcd/cfg/etcd.conf"
sed  's,ETCD_NAME="etcd-1",ETCD_NAME="etcd-3",' /opt/etcd/cfg/etcd.conf | sed -E "/ETCD_INITIAL_CLUSTER/! s,$hostip,$workerip2,g" | ssh root@$workerip2 "cat > /opt/etcd/cfg/etcd.conf"

# system启动文件
cat > /usr/lib/systemd/system/etcd.service << EOF
[Unit]
Description=Etcd Server
After=network.target
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
EnvironmentFile=/opt/etcd/cfg/etcd.conf
ExecStart=/opt/etcd/bin/etcd \
--cert-file=/opt/etcd/ssl/server.pem \
--key-file=/opt/etcd/ssl/server-key.pem \
--peer-cert-file=/opt/etcd/ssl/server.pem \
--peer-key-file=/opt/etcd/ssl/server-key.pem \
--trusted-ca-file=/opt/etcd/ssl/ca.pem \
--peer-trusted-ca-file=/opt/etcd/ssl/ca.pem \
--logger=zap
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# 同步启动文件
rsync -av /usr/lib/systemd/system/etcd.service $workerip1:/usr/lib/systemd/system/etcd.service &> /dev/null
[ $? == 0 ] && echo "etcd启动文件同步成功" || echo "etcd启动文件同步失败" >> /root/k8s-deploy.log
rsync -av /usr/lib/systemd/system/etcd.service $workerip2:/usr/lib/systemd/system/etcd.service &> /dev/null
[ $? == 0 ] && echo "etcd启动文件同步成功" || echo "etcd启动文件同步失败" >> /root/k8s-deploy.log

# 启动etcd
systemctl daemon-reload
ssh root@$workerip1 systemctl daemon-reload
ssh root@$workerip2 systemctl daemon-reload

systemctl restart etcd &
ssh -t root@$workerip1 "systemctl restart etcd"
ssh -t root@$workerip2 "systemctl restart etcd"

systemctl enable etcd &> /dev/null
ssh root@$workerip1 systemctl enable etcd &> /dev/null
ssh root@$workerip2 systemctl enable etcd &> /dev/null

systemctl status etcd | grep -C2 "running" &> /dev/null
[ $? == 0 ] && echo "master-etcd状态正常" || echo "master-etcd状态异常" >> /root/k8s-deploy.log
ssh root@$workerip1 systemctl status etcd | grep -C2 "running" &> /dev/null
[ $? == 0 ] && echo "worker1-etcd状态正常" || echo "worker1-etcd状态异常" >> /root/deploy.log
ssh root@$workerip1 systemctl status etcd | grep -C2 "running" &> /dev/null
[ $? == 0 ] && echo "worker2-etcd状态正常" || echo "worker2-etcd状态异常" >> /root/deploy.log

# 验证etcd集群启动状态
/opt/etcd/bin/etcdctl --cacert=/opt/etcd/ssl/ca.pem --cert=/opt/etcd/ssl/server.pem --key=/opt/etcd/ssl/server-key.pem --endpoints="https://$hostip:2379,https://$workerip1:2379,https://$workerip2:2379" endpoint health >> /root/k8s-deploy.log

/opt/etcd/bin/etcdctl --cacert=/opt/etcd/ssl/ca.pem --cert=/opt/etcd/ssl/server.pem --key=/opt/etcd/ssl/server-key.pem --endpoints="https://$hostip:2379,https://$workerip1:2379,https://$workerip2:2379" member list >> /root/k8s-deploy.log
#-------------------------------------------------------------------------------------------------



###################################### 部署kubernetes ############################################
#-------------------------------------------------------------------------------------------------
cd
# wget下载二进制tar包，所有组件都在包内

if [ -f "$k8sfile" ];then
  echo "$k8sfile 已存在，跳过下载。"
else
  echo "$k8sfile 正在下载"
  wget "$k8surl"
fi

# 解压tar包
tar xf $k8sfile

# 拷贝二进制文件到相关节点、相关位置
cd kubernetes/server/bin
rsync -av kube-apiserver kube-controller-manager kube-scheduler kubectl kubelet kube-proxy /opt/k8s/bin &> /dev/nul
[ $? == 0 ] && echo "k8s组件已同步至/opt/k8s/bin下" || echo "k8s组件同步至/opt/k8s/bin下失败" >> /root/k8s-deploy.log
rsync -av kubectl  /usr/bin &> /dev/null
[ $? == 0 ] && echo "kubectl已同步至/usr/bin下" || echo "kubectl同步至/usr/bin下失败" >> /root/k8s-deploy.log
rsync -av kubelet kube-proxy root@$workerip1:/opt/k8s/bin/ &> /dev/null
[ $? == 0 ] && echo "kubelet、proxy组件已同步至worker1" || echo "kubelet、proxy同步至worker1失败"
rsync -av kubelet kube-proxy root@$workerip2:/opt/k8s/bin/ &> /dev/null
[ $? == 0 ] && echo "kubelet、proxy组件已同步至worker2" || echo "kubelet、proxy同步至worker2失败"

# 进入证书工作目录
cd /data/TLS/k8s

# 自签CA证书
cat > ca-config.json << EOF
{
  "signing": {
    "default": {
      "expiry": "87600h"
    },
    "profiles": {
      "kubernetes": {
         "expiry": "87600h",
         "usages": [
            "signing",
            "key encipherment",
            "server auth",
            "client auth"
        ]
      }
    }
  }
}
EOF

# 请求文件
cat > ca-csr.json << EOF
{
    "CN": "kubernetes",
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "L": "Guangzhou",
            "ST": "Guangzhou",
            "O": "k8s",
            "OU": "System"
        }
    ]
}
EOF

# 生成CA证书
cfssl gencert -initca ca-csr.json | cfssljson -bare ca
[ $? == 0 ] && echo "CA证书生成成功" || echo "CA证书生成失败" >> /root/k8s-deploy.log

# 签署kube-apiserver HTTPS证书
# 创建证书请求文件
cat > server-csr.json << EOF
{
    "CN": "kubernetes",
    "hosts": [
      "10.0.0.1",
      "127.0.0.1",
      "$hostip",
      "$workerip1",
      "$workerip2",
      "192.168.0.13",
      "kubernetes",
      "kubernetes.default",
      "kubernetes.default.svc",
      "kubernetes.default.svc.cluster",
      "kubernetes.default.svc.cluster.local"
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "L": "Guangzhou",
            "ST": "Guangzhou",
            "O": "k8s",
            "OU": "System"
        }
    ]
}
EOF

# 生成证书
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes server-csr.json | cfssljson -bare server
[ $? == 0 ] && echo "apiserver HTTPS已签署" || echo "apiserver HTTPS签署失败" >> /root/k8s-deploy.log

# 同步证书到master的k8s工作目录
rsync -av /data/TLS/k8s/ca*pem /opt/k8s/ssl/ &> /dev/null
[ $? == 0 ] && echo "ca证书已同步至/opt/k8s/ssl下" || echo "ca证书同步失败" >> /root/k8s-deploy.log
rsync -av /data/TLS/k8s/server*pem /opt/k8s/ssl/ &> /dev/null
[ $? == 0 ] && echo "apiserver证书已同步至/opt/k8s/ssl下" || echo "apiserver证书同步失败" >> /root/k8s-deploy.log

# 同步证书到工作节点
rsync -av /data/TLS/k8s/ca.pem root@$workerip1:/opt/k8s/ssl &> /dev/null
[ $? == 0 ] && echo "worker1节点ca证书同步成功" || echo "worker1节点ca证书同步失败" >> /root/k8s-deploy.log
rsync -av /data/TLS/k8s/ca.pem root@$workerip2:/opt/k8s/ssl &> /dev/null
[ $? == 0 ] && echo "worker2节点ca证书同步成功" || echo "worker2节点ca证书同步失败" >> /root/k8s-deploy.log

# 创建kube-apiserver配置文件
cat > /opt/k8s/cfg/kube-apiserver.conf << EOF
KUBE_APISERVER_OPTS="--logtostderr=false \
--feature-gates=RemoveSelfLink=false \
--v=2 \
--log-dir=/opt/k8s/logs \
--bind-address=$hostip \
--secure-port=6443 \
--advertise-address=$hostip \
--anonymous-auth=false \
--allow-privileged=true \
--runtime-config=api/all=true \
--service-cluster-ip-range=10.0.0.0/24 \
--enable-admission-plugins=NamespaceLifecycle,LimitRanger,ServiceAccount,ResourceQuota,NodeRestriction,DefaultStorageClass \
--authorization-mode=RBAC,Node \
--enable-bootstrap-token-auth \
--token-auth-file=/opt/k8s/cfg/token.csv \
--service-node-port-range=30000-32767 \
--kubelet-client-certificate=/opt/k8s/ssl/server.pem \
--kubelet-client-key=/opt/k8s/ssl/server-key.pem \
--tls-cert-file=/opt/k8s/ssl/server.pem  \
--tls-private-key-file=/opt/k8s/ssl/server-key.pem \
--client-ca-file=/opt/k8s/ssl/ca.pem \
--apiserver-count=1 \
--service-account-issuer=api \
--service-account-key-file=/opt/k8s/ssl/ca-key.pem \
--service-account-signing-key-file=/opt/k8s/ssl/server-key.pem \
--service-account-signing-key-file=/opt/k8s/ssl/ca-key.pem \
--etcd-servers=https://$hostip:2379,https://$workerip1:2379,https://$workerip2:2379 \
--etcd-cafile=/opt/etcd/ssl/ca.pem \
--etcd-certfile=/opt/etcd/ssl/server.pem \
--etcd-keyfile=/opt/etcd/ssl/server-key.pem \
--requestheader-client-ca-file=/opt/k8s/ssl/ca.pem \
--proxy-client-cert-file=/opt/k8s/ssl/server.pem \
--proxy-client-key-file=/opt/k8s/ssl/server-key.pem \
--requestheader-allowed-names=kubernetes \
--requestheader-extra-headers-prefix=X-Remote-Extra- \
--requestheader-group-headers=X-Remote-Group \
--requestheader-username-headers=X-Remote-User \
--enable-aggregator-routing=true \
--audit-log-maxage=30 \
--audit-log-maxbackup=3 \
--audit-log-maxsize=100 \
--event-ttl=1h \
--audit-log-path=/opt/k8s/logs/k8s-audit.log"
EOF

# 启动TLS Bootstrapping机制
# TLS Bootstraping机制：Master apiserver启用TLS认证后，Node节点kubelet和kube-proxy要与kube-apiserver进行通信，必须使用CA签发的有效证书才可以，当Node节点很多时，这种客户端证书颁发需要大量工作，同样也会增加集群扩展复杂度。为了简化流程，Kubernetes引入了TLS bootstraping机制来自动颁发客户端证书，kubelet会以一个低权限用户自动向apiserver申请证书，kubelet的证书由apiserver动态签署。所以强烈建议在Node上使用这种方式，目前主要用于kubelet，kube-proxy还是由我们统一颁发一个证书。
token=$(head -c 16 /dev/urandom | od -An -t x | tr -d ' ')

# 创建token文件
cat > /opt/k8s/cfg/token.csv << EOF
$token,kubelet-bootstrap,10001,"system:node-bootstrapper"
EOF
# 格式：token，用户名，UID，用户组

# system启动文件
# master做即可
cat > /usr/lib/systemd/system/kube-apiserver.service << EOF
[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/kubernetes/kubernetes
After=network.target

[Service]
EnvironmentFile=/opt/k8s/cfg/kube-apiserver.conf
ExecStart=/opt/k8s/bin/kube-apiserver \$KUBE_APISERVER_OPTS
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# 重新加载配置文件
systemctl daemon-reload

# 启动kube-apiserver组件
systemctl restart kube-apiserver

# 设置开机自启
systemctl enable kube-apiserver

# 查看kube-apiserver组件运行状态
systemctl status kube-apiserver.service | grep "running" &> /dev/null
[ $? == 0 ] && echo "apiserver启动成功" || echo "apiserver启动失败" >> /root/k8s-deploy.log
#-------------------------------------------------------------------------------------------------



############################# 部署kube-controller-manager ########################################
#-------------------------------------------------------------------------------------------------
# 创建kube-controller-manager配置文件
cat > /opt/k8s/cfg/kube-controller-manager.conf << EOF
KUBE_CONTROLLER_MANAGER_OPTS="--logtostderr=false \\
--v=2 \\
--log-dir=/opt/k8s/logs \\
--leader-elect=true \\
--kubeconfig=/opt/k8s/cfg/kube-controller-manager.kubeconfig \\
--bind-address=127.0.0.1 \\
--allocate-node-cidrs=true \\
--cluster-cidr=10.244.0.0/16 \\
--service-cluster-ip-range=10.0.0.0/24 \\
--cluster-signing-cert-file=/opt/k8s/ssl/ca.pem \\
--cluster-signing-key-file=/opt/k8s/ssl/ca-key.pem  \\
--root-ca-file=/opt/k8s/ssl/ca.pem \\
--service-account-private-key-file=/opt/k8s/ssl/ca-key.pem \\
--cluster-signing-duration=87600h0m0s"
EOF

# 签署controller-manager HTTPS证书
cd /data/TLS/k8s

# 创建证书请求文件
cat > kube-controller-manager-csr.json << EOF
{
  "CN": "system:kube-controller-manager",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "L": "Guangzhou", 
      "ST": "Guangzhou",
      "O": "system:masters",
      "OU": "System"
    }
  ]
}
EOF

# 生成证书
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes kube-controller-manager-csr.json | cfssljson -bare kube-controller-manager
[ $? == 0 ] && echo "controller-manager HTTPS已签署" || echo "controller-manager HTTPS签署失败" >> /root/k8s-deploy.log

# 生成controller-manager的kubeconfig文件
cd /data/TLS/k8s

KUBE_CONFIG="/opt/k8s/cfg/kube-controller-manager.kubeconfig"
KUBE_APISERVER="https://$hostip:6443"

kubectl config set-cluster kubernetes \
  --certificate-authority=/opt/k8s/ssl/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=${KUBE_CONFIG}
kubectl config set-credentials kube-controller-manager \
  --client-certificate=./kube-controller-manager.pem \
  --client-key=./kube-controller-manager-key.pem \
  --embed-certs=true \
  --kubeconfig=${KUBE_CONFIG}
kubectl config set-context default \
  --cluster=kubernetes \
  --user=kube-controller-manager \
  --kubeconfig=${KUBE_CONFIG}
kubectl config use-context default --kubeconfig=${KUBE_CONFIG}

# system启动文件
cat > /usr/lib/systemd/system/kube-controller-manager.service << EOF
[Unit]
Description=Kubernetes Controller Manager
Documentation=https://github.com/kubernetes/kubernetes
After=kube-apiserver.service

[Service]
EnvironmentFile=/opt/k8s/cfg/kube-controller-manager.conf
ExecStart=/opt/k8s/bin/kube-controller-manager \$KUBE_CONTROLLER_MANAGER_OPTS
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# 重新加载配置文件
systemctl daemon-reload

# 启动kube-controller-manager
systemctl restart kube-controller-manager

# 设置开机自启
systemctl enable kube-controller-manager

# 查看kube-controller-manager
systemctl status kube-controller-manager | grep "running" &> /dev/null
[ $? == 0 ] && echo "controller-manager状态正常" || echo "controller-manager状态异常" >> /root/k8s-deploy.log
#-------------------------------------------------------------------------------------------------



#################################### 部署kube-scheduler ##########################################
#-------------------------------------------------------------------------------------------------
# 创建kube-scheduler配置文件
cat > /opt/k8s/cfg/kube-scheduler.conf << EOF
KUBE_SCHEDULER_OPTS="--logtostderr=false \\
--v=2 \\
--log-dir=/opt/k8s/logs \\
--leader-elect \\
--kubeconfig=/opt/k8s/cfg/kube-scheduler.kubeconfig \\
--bind-address=127.0.0.1"
EOF

# 签署kube-scheduler HTTPS证书
cat > kube-scheduler-csr.json << EOF
{
  "CN": "system:kube-scheduler",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "L": "Guangzhou",
      "ST": "Guangzhou",
      "O": "system:masters",
      "OU": "System"
    }
  ]
}
EOF

# 生成证书
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes kube-scheduler-csr.json | cfssljson -bare kube-scheduler
[ $? == 0 ] && echo "scheduler HTTPS已签署" || echo "scheduler HTTPS签署失败"

# 生成kube-scheduler的kubeconfig文件
cd /data/TLS/k8s

KUBE_CONFIG="/opt/k8s/cfg/kube-scheduler.kubeconfig"
KUBE_APISERVER="https://$hostip:6443"

kubectl config set-cluster kubernetes \
  --certificate-authority=/opt/k8s/ssl/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=${KUBE_CONFIG}
kubectl config set-credentials kube-scheduler \
  --client-certificate=./kube-scheduler.pem \
  --client-key=./kube-scheduler-key.pem \
  --embed-certs=true \
  --kubeconfig=${KUBE_CONFIG}
kubectl config set-context default \
  --cluster=kubernetes \
  --user=kube-scheduler \
  --kubeconfig=${KUBE_CONFIG}
kubectl config use-context default --kubeconfig=${KUBE_CONFIG}

# system启动文件
cat > /usr/lib/systemd/system/kube-scheduler.service << EOF
[Unit]
Description=Kubernetes Scheduler
Documentation=https://github.com/kubernetes/kubernetes
After=kube-apiserver.service

[Service]
EnvironmentFile=/opt/k8s/cfg/kube-scheduler.conf
ExecStart=/opt/k8s/bin/kube-scheduler \$KUBE_SCHEDULER_OPTS
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# 重新加载配置文件
systemctl daemon-reload

# 启动kube-scheduler
systemctl restart kube-scheduler

# 设置开机自启
systemctl enable kube-scheduler

# 查看kube-scheduler
systemctl status kube-scheduler | grep "running" &> /dev/null
[ $? == 0 ] && echo "scheduler状态正常" || echo "scheduler状态异常"
#-------------------------------------------------------------------------------------------------




####################################### 部署kubelet ##############################################
#-------------------------------------------------------------------------------------------------
# 创建kubelet配置文件
cat > /opt/k8s/cfg/kubelet.conf << EOF
KUBELET_OPTS="--logtostderr=false \\
--v=2 \\
--log-dir=/opt/k8s/logs \\
--hostname-override=k8s-master \\
--network-plugin=cni \\
--kubeconfig=/opt/k8s/cfg/kubelet.kubeconfig \\
--bootstrap-kubeconfig=/opt/k8s/cfg/bootstrap.kubeconfig \\
--config=/opt/k8s/cfg/kubelet-config.yml \\
--cert-dir=/opt/k8s/ssl \\
--pod-infra-container-image=$registry/library/pause:3.6"
EOF

# 进入证书工作目录
cd /data/TLS/k8s

# 生成kubectl连接集群请求证书
cat > admin-csr.json <<EOF
{
  "CN": "admin",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "L": "Guangzhou",
      "ST": "Guangzhou",
      "O": "system:masters",
      "OU": "System"
    }
  ]
}
EOF

# 生成kubectl进入集群证书
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes admin-csr.json | cfssljson -bare admin
[ $? == 0 ] && echo "kubectl请求证书已生成" || echo "kubectl请求证书生成失败" >> /root/k8s-deploy.log

# 创建隐藏文件
mkdir -p /root/.kube

# 生成kubeconfig文件
KUBE_CONFIG="/root/.kube/config"
KUBE_APISERVER="https://$hostip:6443"

kubectl config set-cluster kubernetes \
  --certificate-authority=/opt/k8s/ssl/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=${KUBE_CONFIG}
kubectl config set-credentials cluster-admin \
  --client-certificate=./admin.pem \
  --client-key=./admin-key.pem \
  --embed-certs=true \
  --kubeconfig=${KUBE_CONFIG}
kubectl config set-context default \
  --cluster=kubernetes \
  --user=cluster-admin \
  --kubeconfig=${KUBE_CONFIG}
kubectl config use-context default --kubeconfig=${KUBE_CONFIG}

# 查看组件状态
kubectl  get cs >> /root/k8s-deploy.log

# system启动文件
cat > /usr/lib/systemd/system/kubelet.service << EOF
[Unit]
Description=Kubernetes Kubelet
After=docker.service

[Service]
EnvironmentFile=/opt/k8s/cfg/kubelet.conf
ExecStart=/opt/k8s/bin/kubelet \$KUBELET_OPTS
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# 创建yaml配置文件
cat > /opt/k8s/cfg/kubelet-config.yml << EOF
kind: KubeletConfiguration
apiVersion: kubelet.config.k8s.io/v1beta1
address: 0.0.0.0
port: 10250
readOnlyPort: 10255
cgroupDriver: systemd
clusterDNS:
- 10.0.0.2
clusterDomain: cluster.local 
failSwapOn: false
authentication:
  anonymous:
    enabled: false
  webhook:
    cacheTTL: 2m0s
    enabled: true
  x509:
    clientCAFile: /opt/k8s/ssl/ca.pem 
authorization:
  mode: Webhook
  webhook:
    cacheAuthorizedTTL: 5m0s
    cacheUnauthorizedTTL: 30s
evictionHard:
  imagefs.available: 15%
  memory.available: 100Mi
  nodefs.available: 10%
  nodefs.inodesFree: 5%
maxOpenFiles: 1000000
maxPods: 110
EOF

# 创建bootstrap.kubeconfig文件 # kubelet初次加入集群引导作用
# 进入指定目录操作
cd /data/TLS/k8s

# 以下命令在命令行直接执行
KUBE_CONFIG="/opt/k8s/cfg/bootstrap.kubeconfig"
KUBE_APISERVER="https://$hostip:6443"
TOKEN=`cat /opt/k8s/cfg/token.csv|awk -F',' '{print $1}'` 

kubectl config set-cluster kubernetes \
  --certificate-authority=/opt/k8s/ssl/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=${KUBE_CONFIG}
kubectl config set-credentials "kubelet-bootstrap" \
  --token=${TOKEN} \
  --kubeconfig=${KUBE_CONFIG}
kubectl config set-context default \
  --cluster=kubernetes \
  --user="kubelet-bootstrap" \
  --kubeconfig=${KUBE_CONFIG}
kubectl config use-context default --kubeconfig=${KUBE_CONFIG}

# 授权用户请求证书
cat > /opt/k8s/yaml/kubelet-bootstrap-rbac.yaml << EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: create-csrs-for-bootstrapping
subjects:
- kind: Group
  name: system:bootstrappers
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: system:node-bootstrapper
  apiGroup: rbac.authorization.k8s.io  
EOF

# 导入yaml
kubectl apply -f /opt/k8s/yaml/kubelet-bootstrap-rbac.yaml

# 同步kubelet配置
rsync -av /opt/k8s/cfg/{kubelet.conf,kubelet-config.yml,bootstrap.kubeconfig} $workerip1:/opt/k8s/cfg/ &> /dev/null
[ $? == 0 ] && echo "kubelet配置已同步至worker1" || echo "kubelet配置同步至worker1失败" >> /root/k8s-deploy.log
rsync -av /opt/k8s/cfg/{kubelet.conf,kubelet-config.yml,bootstrap.kubeconfig} $workerip2:/opt/k8s/cfg/ &> /dev/null
[ $? == 0 ] && echo "kubelet配置已同步至worker2" || echo "kubelet配置同步至worker2失败" >> /root/k8s-deploy.log

# 同步启动文件
rsync -av /usr/lib/systemd/system/kubelet.service root@$workerip1:/usr/lib/systemd/system/kubelet.service &> /dev/null
[ $? == 0 ] && echo "kubelet启动文件已同步至worker1" || echo "kubelet启动文件同步至worker1失败" >> /root/k8s-deploy.log
rsync -av /usr/lib/systemd/system/kubelet.service root@$workerip2:/usr/lib/systemd/system/kubelet.service &> /dev/null
[ $? == 0 ] && echo "kubelet启动文件已同步至worker2" || echo "kubelet启动文件同步至worker2失败" >> /root/k8s-deploy.log

# 修改工作节点kubelet配置文件
ssh root@$workerip1 "sed '/.*hostname-.*/ s,master,worker1,' /opt/k8s/cfg/kubelet.conf -i"
ssh root@$workerip2 "sed '/.*hostname-.*/ s,master,worker2,' /opt/k8s/cfg/kubelet.conf -i"

# kubelet-bootstrap授权创建证书
kubectl create clusterrolebinding kubelet-bootstrap --clusterrole=system:node-bootstrapper --user=kubelet-bootstrap

# 重新加载配置文件
systemctl daemon-reload
ssh root@$workerip1 systemctl daemon-reload
ssh root@$workerip2 systemctl daemon-reload

# 启动kubelet
systemctl restart kubelet
ssh root@$workerip1 systemctl restart kubelet
ssh root@$workerip2 systemctl restart kubelet

# 设置开机自启
systemctl enable kubelet
ssh root@$workerip1 systemctl enable kubelet
ssh root@$workerip2 systemctl enable kubelet

# 查看kubelet
systemctl status kubelet | grep "running" >> /dev/null
[ $? == 0 ] && echo "kubelet状态正常" || echo "kubelet状态异常" >> /root/k8s-deploy.log
ssh root@$workerip1 systemctl status kubelet | grep "running" >> /dev/null
[ $? == 0 ] && echo "worker1节点kubelet状态正常" || echo "worker1节点kubelet状态异常" >> /root/k8s-deploy.log
ssh root@$workerip2 systemctl status kubelet | grep "running" >> /dev/null
[ $? == 0 ] && echo "worker2节点kubelet状态正常" || echo "worker2节点kubelet状态异常" >> /root/k8s-deploy.log

# 批量批准证书加入集群
for csr in $(kubectl get csr |awk 'NR>1 {print $1}');do kubectl certificate approve $csr; done

# 查看节点进入集群状态
kubectl get nodes  >> /root/k8s-deploy.log

# 设置TAB键
source <(kubectl completion bash)
#-------------------------------------------------------------------------------------------------



##################################### 部署kube-proxy #############################################
#------------------------------------------------------------------------------------------------
# 创建kube-proxy配置文件
cat > /opt/k8s/cfg/kube-proxy.conf << EOF
KUBE_PROXY_OPTS="--logtostderr=false \\
--v=2 \\
--log-dir=/opt/k8s/logs \\
--config=/opt/k8s/cfg/kube-proxy-config.yml"
EOF

# 创建IPVS模式的yaml文件
cat > /opt/k8s/cfg/kube-proxy-config.yml  << EOF
kind: KubeProxyConfiguration
apiVersion: kubeproxy.config.k8s.io/v1alpha1
bindAddress: 0.0.0.0
metricsBindAddress: 0.0.0.0:10249
iptables:
  masqueradeAll: true
  masqueradeBit: null
  minSyncPeriod: 0s
  syncPeriod: 0s
ipvs:
  masqueradeAll: true
  excludeCIDRs: null
  minSyncPeriod: 0s
  scheduler: "rr"
  strictARP: false
  syncPeriod: 0s
  tcpFinTimeout: 0s
  tcpTimeout: 0s
  udpTimeout: 0s
mode: "ipvs"
clientConnection:
  kubeconfig: /opt/k8s/cfg/kube-proxy.kubeconfig
hostnameOverride: k8s-master
clusterCIDR: 10.0.0.0/24
EOF

# 修改hostnameOverride为节点hostname
# clusterCIDR: kube-proxy 根据 --cluster-cidr 判断集群内部和外部流量，指定 --cluster-cidr 或 --masquerade-all 选项后 kube-proxy 才会对访问 Service IP 的请求做SNAT
# clusterCIDR: 10.0.0.0/24这个是集群service段,和kube-apiserver.conf还有kube-controller-manager.conf中--service-cluster-ip-range=10.0.0.0/24参数保持一致
# 进入证书工作目录
cd /data/TLS/k8s

# 创建证书请求文件
cat > kube-proxy-csr.json << EOF
{
  "CN": "system:kube-proxy",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "L": "Guangzhou",
      "ST": "Guangzhou",
      "O": "k8s",
      "OU": "System"
    }
  ]
}
EOF

# 生成证书
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes kube-proxy-csr.json | cfssljson -bare kube-proxy
[ $? == 0 ] && echo "kube-proxy证书已生成" || echo "kube-proxy证书生成失败" >> /root/k8s-deploy.log

# 生成kube-proxy的kubeconfig文件
KUBE_CONFIG="/opt/k8s/cfg/kube-proxy.kubeconfig"
KUBE_APISERVER="https://$hostip:6443"

kubectl config set-cluster kubernetes \
  --certificate-authority=/opt/k8s/ssl/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=${KUBE_CONFIG}
kubectl config set-credentials kube-proxy \
  --client-certificate=./kube-proxy.pem \
  --client-key=./kube-proxy-key.pem \
  --embed-certs=true \
  --kubeconfig=${KUBE_CONFIG}
kubectl config set-context default \
  --cluster=kubernetes \
  --user=kube-proxy \
  --kubeconfig=${KUBE_CONFIG}
kubectl config use-context default --kubeconfig=${KUBE_CONFIG}

# system启动文件
cat > /usr/lib/systemd/system/kube-proxy.service << EOF
[Unit]
Description=Kubernetes Proxy
After=docker.service

[Service]
EnvironmentFile=/opt/k8s/cfg/kube-proxy.conf
ExecStart=/opt/k8s/bin/kube-proxy \$KUBE_PROXY_OPTS
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# 同步配置到工作节点
rsync -av /opt/k8s/cfg/{kube-proxy.conf,kube-proxy-config.yml,kube-proxy.kubeconfig} root@$workerip1:/opt/k8s/cfg/ >> /dev/null
[ $? == 0 ] && echo "proxy配置已同步至worker1" || echo "proxy配置同步至worker1失败" >> /root/k8s-deploy.log
rsync -av /opt/k8s/cfg/{kube-proxy.conf,kube-proxy-config.yml,kube-proxy.kubeconfig} root@$workerip2:/opt/k8s/cfg/ >> /dev/null
[ $? == 0 ] && echo "proxy配置已同步至worker2" || echo "proxy配置同步至worker2失败" >> /root/k8s-deploy.log

# 同步启动文件
rsync -av /usr/lib/systemd/system/kube-proxy.service root@$workerip1:/usr/lib/systemd/system/kube-proxy.service >> /dev/null
[ $? == 0 ] && echo "proxy启动文件已同步至worker1" || echo "proxy启动文件同步至worker1失败" >> /root/k8s-deploy.log
rsync -av /usr/lib/systemd/system/kube-proxy.service root@$workerip2:/usr/lib/systemd/system/kube-proxy.service >> /dev/null
[ $? == 0 ] && echo "proxy启动文件已同步至worker2" || echo "proxy启动文件同步至worker2失败" >> /root/k8s-deploy.log

# 修改工作节点kube-proxy配置文件
ssh 192.168.0.11 "sed '/^hostname.*/ s,master,worker1,' /opt/k8s/cfg/kube-proxy-config.yml -i"
ssh 192.168.0.11 "sed '/^hostname.*/ s,master,worker2,' /opt/k8s/cfg/kube-proxy-config.yml -i"

# master，worker都做
# 重新加载配置文件
systemctl daemon-reload
ssh root@$workerip1 systemctl daemon-reload
ssh root@$workerip2 systemctl daemon-reload

# 启动kube-proxy
systemctl restart kube-proxy
ssh root@$workerip1 systemctl restart kube-proxy
ssh root@$workerip2 systemctl restart kube-proxy

# 设置开机自启
systemctl enable kube-proxy
ssh root@$workerip1 systemctl enable kube-proxy
ssh root@$workerip2 systemctl enable kube-proxy

# 查看kube-proxy
systemctl status kube-proxy | grep "running" >> /dev/null
[ $? == 0 ] && echo "kube-proxy状态正常" || echo "kube-proxy状态异常" >> /root/k8s-deploy.log
ssh root@$workerip1 systemctl status kube-proxy | grep "running" >> /dev/null
[ $? == 0 ] && echo "worker1节点kube-proxy状态正常" || echo "worker1节点kube-proxy状态异常" >> /root/k8s-deploy.log
ssh root@$workerip2 systemctl status kube-proxy | grep "running" >> /dev/null
[ $? == 0 ] && echo "worker2节点kube-proxy状态正常" || echo "worker2节点kube-proxy状态异常" >> /root/k8s-deploy.log

# 验证IPVS模式
ipvsadm -l >> /root/k8s-deploy.log

# kube-apiserver访问授权
cd /opt/k8s/yaml

# 如果不进行授权，将无法管理容器
cat > /opt/k8s/yaml/apiserver-to-kubelet-rbac.yaml << EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  annotations:
    rbac.authorization.kubernetes.io/autoupdate: "true"
  labels:
    kubernetes.io/bootstrapping: rbac-defaults
  name: system:kube-apiserver-to-kubelet
rules:
  - apiGroups:
      - ""
    resources:
      - nodes/proxy
      - nodes/stats
      - nodes/log
      - nodes/spec
      - nodes/metrics
      - pods/log
    verbs:
      - "*"
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: system:kube-apiserver
  namespace: ""
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:kube-apiserver-to-kubelet
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: User
    name: kubernetes
EOF

# 导入yaml
kubectl apply -f apiserver-to-kubelet-rbac.yaml

######################################## 部署cni网络 #############################################
#-------------------------------------------------------------------------------------------------
# 创建cni插件工作目录和生成配置目录
mkdir -p /opt/cni/bin  /etc/cni/net.d
ssh root@$workerip1 mkdir -p /opt/cni/bin  /etc/cni/net.d
ssh root@$workerip2 mkdir -p /opt/cni/bin  /etc/cni/net.d

# 解压缩
cd 
tar zvxf cni-plugins-linux-amd64-v0.9.1.tgz -C /opt/cni/bin
[ $? == 0 ] && echo "cni插件解压成功" || echo "cni插件解压失败" >> /root/k8s-deploy.log

# 分发内容
rsync -av --delete  /opt/cni/ root@$workerip1:/opt/cni >> /dev/null
[ $? == 0 ] && echo "cni插件已同步至worker1" || echo "cni同步至worker1失败" >> /root/k8s-deploy.log
rsync -av --delete  /opt/cni/ root@$workerip2:/opt/cni >> /dev/null
[ $? == 0 ] && echo "cni插件已同步至worker2" || echo "cni同步至worker2失败" >> /root/k8s-deploy.log

# 部署flannel网络插件
cd

# 写入yaml文件
cat > kube-flannel.yml << EOF
---
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: psp.flannel.unprivileged
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: docker/default
    seccomp.security.alpha.kubernetes.io/defaultProfileName: docker/default
    apparmor.security.beta.kubernetes.io/allowedProfileNames: runtime/default
    apparmor.security.beta.kubernetes.io/defaultProfileName: runtime/default
spec:
  privileged: false
  volumes:
  - configMap
  - secret
  - emptyDir
  - hostPath
  allowedHostPaths:
  - pathPrefix: "/etc/cni/net.d"
  - pathPrefix: "/etc/kube-flannel"
  - pathPrefix: "/run/flannel"
  readOnlyRootFilesystem: false
  # Users and groups
  runAsUser:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny
  # Privilege Escalation
  allowPrivilegeEscalation: false
  defaultAllowPrivilegeEscalation: false
  # Capabilities
  allowedCapabilities: ['NET_ADMIN', 'NET_RAW']
  defaultAddCapabilities: []
  requiredDropCapabilities: []
  # Host namespaces
  hostPID: false
  hostIPC: false
  hostNetwork: true
  hostPorts:
  - min: 0
    max: 65535
  # SELinux
  seLinux:
    # SELinux is unused in CaaSP
    rule: 'RunAsAny'
---
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: flannel
rules:
- apiGroups: ['extensions']
  resources: ['podsecuritypolicies']
  verbs: ['use']
  resourceNames: ['psp.flannel.unprivileged']
- apiGroups:
  - ""
  resources:
  - pods
  verbs:
  - get
- apiGroups:
  - ""
  resources:
  - nodes
  verbs:
  - list
  - watch
- apiGroups:
  - ""
  resources:
  - nodes/status
  verbs:
  - patch
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: flannel
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: flannel
subjects:
- kind: ServiceAccount
  name: flannel
  namespace: kube-system
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: flannel
  namespace: kube-system
---
kind: ConfigMap
apiVersion: v1
metadata:
  name: kube-flannel-cfg
  namespace: kube-system
  labels:
    tier: node
    app: flannel
data:
  cni-conf.json: |
    {
      "name": "cbr0",
      "cniVersion": "0.3.1",
      "plugins": [
        {
          "type": "flannel",
          "delegate": {
            "hairpinMode": true,
            "isDefaultGateway": true
          }
        },
        {
          "type": "portmap",
          "capabilities": {
            "portMappings": true
          }
        }
      ]
    }
  net-conf.json: |
    {
      "Network": "10.244.0.0/16",
      "Backend": {
        "Type": "vxlan"
      }
    }
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: kube-flannel-ds
  namespace: kube-system
  labels:
    tier: node
    app: flannel
spec:
  selector:
    matchLabels:
      app: flannel
  template:
    metadata:
      labels:
        tier: node
        app: flannel
    spec:
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
            - matchExpressions:
              - key: kubernetes.io/os
                operator: In
                values:
                - linux
      hostNetwork: true
      priorityClassName: system-node-critical
      tolerations:
      - operator: Exists
        effect: NoSchedule
      serviceAccountName: flannel
      initContainers:
      - name: install-cni-plugin
        image: $registry/library/mirrored-flannelcni-flannel-cni-plugin:v1.0.0
        command:
        - cp
        args:
        - -f
        - /flannel
        - /opt/cni/bin/flannel
        volumeMounts:
        - name: cni-plugin
          mountPath: /opt/cni/bin
      - name: install-cni
        image: $registry/library/mirrored-flannelcni-flannel:v0.16.1
        command:
        - cp
        args:
        - -f
        - /etc/kube-flannel/cni-conf.json
        - /etc/cni/net.d/10-flannel.conflist
        volumeMounts:
        - name: cni
          mountPath: /etc/cni/net.d
        - name: flannel-cfg
          mountPath: /etc/kube-flannel/
      containers:
      - name: kube-flannel
        image: $registry/library/mirrored-flannelcni-flannel:v0.16.1
        command:
        - /opt/bin/flanneld
        args:
        - --ip-masq
        - --kube-subnet-mgr
        resources:
          requests:
            cpu: "100m"
            memory: "50Mi"
          limits:
            cpu: "100m"
            memory: "50Mi"
        securityContext:
          privileged: false
          capabilities:
            add: ["NET_ADMIN", "NET_RAW"]
        env:
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        volumeMounts:
        - name: run
          mountPath: /run/flannel
        - name: flannel-cfg
          mountPath: /etc/kube-flannel/
      volumes:
      - name: run
        hostPath:
          path: /run/flannel
      - name: cni-plugin
        hostPath:
          path: /opt/cni/bin
      - name: cni
        hostPath:
          path: /etc/cni/net.d
      - name: flannel-cfg
        configMap:
          name: kube-flannel-cfg
EOF

# 导入yaml文件
kubectl apply -f kube-flannel.yml
#--------------------------------------------------------------------------------------------------------------



############################################ 部署CoreDNS #######################################################
#--------------------------------------------------------------------------------------------------------------
# 写入yaml文件
cat > coredns.yaml << EOF
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: coredns
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  labels:
    kubernetes.io/bootstrapping: rbac-defaults
  name: system:coredns
rules:
  - apiGroups:
    - ""
    resources:
    - endpoints
    - services
    - pods
    - namespaces
    verbs:
    - list
    - watch
  - apiGroups:
    - discovery.k8s.io
    resources:
    - endpointslices
    verbs:
    - list
    - watch
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  annotations:
    rbac.authorization.kubernetes.io/autoupdate: "true"
  labels:
    kubernetes.io/bootstrapping: rbac-defaults
  name: system:coredns
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:coredns
subjects:
- kind: ServiceAccount
  name: coredns
  namespace: kube-system
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns
  namespace: kube-system
data:
  Corefile: |
    .:53 {
        errors
        health {
          lameduck 5s
        }
        ready
        kubernetes cluster.local {
          fallthrough in-addr.arpa ip6.arpa
        }
        prometheus :9153
        forward . /etc/resolv.conf {
          max_concurrent 1000
        }
        cache 30
        loop
        reload
        loadbalance
    }
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: coredns
  namespace: kube-system
  labels:
    k8s-app: kube-dns
    kubernetes.io/name: "CoreDNS"
    app.kubernetes.io/name: coredns
spec:
  # replicas: not specified here:
  # 1. Default is 1.
  # 2. Will be tuned in real time if DNS horizontal auto-scaling is turned on.
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
  selector:
    matchLabels:
      k8s-app: kube-dns
      app.kubernetes.io/name: coredns
  template:
    metadata:
      labels:
        k8s-app: kube-dns
        app.kubernetes.io/name: coredns
    spec:
      priorityClassName: system-cluster-critical
      serviceAccountName: coredns
      tolerations:
        - key: "CriticalAddonsOnly"
          operator: "Exists"
      nodeSelector:
        kubernetes.io/os: linux
      affinity:
         podAntiAffinity:
           requiredDuringSchedulingIgnoredDuringExecution:
           - labelSelector:
               matchExpressions:
               - key: k8s-app
                 operator: In
                 values: ["kube-dns"]
             topologyKey: kubernetes.io/hostname
      containers:
      - name: coredns
        image: $registry/library/coredns:1.8.5
        imagePullPolicy: IfNotPresent
        resources:
          limits:
            memory: 170Mi
          requests:
            cpu: 100m
            memory: 70Mi
        args: [ "-conf", "/etc/coredns/Corefile" ]
        volumeMounts:
        - name: config-volume
          mountPath: /etc/coredns
          readOnly: true
        ports:
        - containerPort: 53
          name: dns
          protocol: UDP
        - containerPort: 53
          name: dns-tcp
          protocol: TCP
        - containerPort: 9153
          name: metrics
          protocol: TCP
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            add:
            - NET_BIND_SERVICE
            drop:
            - all
          readOnlyRootFilesystem: true
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
            scheme: HTTP
          initialDelaySeconds: 60
          timeoutSeconds: 5
          successThreshold: 1
          failureThreshold: 5
        readinessProbe:
          httpGet:
            path: /ready
            port: 8181
            scheme: HTTP
      dnsPolicy: Default
      volumes:
        - name: config-volume
          configMap:
            name: coredns
            items:
            - key: Corefile
              path: Corefile
---
apiVersion: v1
kind: Service
metadata:
  name: kube-dns
  namespace: kube-system
  annotations:
    prometheus.io/port: "9153"
    prometheus.io/scrape: "true"
  labels:
    k8s-app: kube-dns
    kubernetes.io/cluster-service: "true"
    kubernetes.io/name: "CoreDNS"
    app.kubernetes.io/name: coredns
spec:
  selector:
    k8s-app: kube-dns
    app.kubernetes.io/name: coredns
  clusterIP: 10.0.0.2
  ports:
  - name: dns
    port: 53
    protocol: UDP
  - name: dns-tcp
    port: 53
    protocol: TCP
  - name: metrics
    port: 9153
    protocol: TCP
EOF

# 生效yaml文件
kubectl apply -f coredns.yaml

# 为master打上污点标签
kubectl taint node k8s-master node-role.kubernetes.io/master:NoSchedule
