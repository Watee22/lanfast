// FlClash 覆写脚本：将 LanFast 与局域网流量彻底排除出代理与 TUN 虚拟网卡
// 使用方法（不中断当前网络）：
//   1. 打开 FlClash → 左侧「脚本（Scripts）」→ 点击「＋」新建脚本，名称填 LanFast
//   2. 把本文件全部内容粘贴进去并保存
//   3. 回到「配置（Profiles）」→ 点击当前配置右侧菜单 →「覆写」→ 选择「脚本」→ 勾选 LanFast

function main(config) {
  // 1. TUN 虚拟网卡路由层排除（即使在 Global 全局模式下也直接绕过 TUN）
  config.tun = config.tun || {};
  const excludeAddrs = [
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "224.0.0.0/4",
    "255.255.255.255/32",
    // 如果你部署了公网中转服务器，取消下面这行注释并填入你的服务器 IP：
    // "你的公网中转IP/32",
  ];
  const existingEx = Array.isArray(config.tun["route-exclude-address"])
    ? config.tun["route-exclude-address"]
    : [];
  config.tun["route-exclude-address"] = Array.from(new Set([...existingEx, ...excludeAddrs]));

  // 2. 规则层直连（Rule 规则模式下生效）
  const lanfastRules = [
    "DST-PORT,53530,DIRECT",
    "DST-PORT,53531,DIRECT",
    "DST-PORT,53532,DIRECT",
    "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
    "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
    // 如果你部署了公网中转服务器，取消下面这行注释并填入你的服务器 IP：
    // "IP-CIDR,你的公网中转IP/32,DIRECT,no-resolve",
  ];
  const existingRules = Array.isArray(config.rules) ? config.rules : [];
  config.rules = [...lanfastRules, ...existingRules];

  return config;
}
