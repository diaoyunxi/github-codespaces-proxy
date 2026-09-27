#pragma once
/**
 * 启动自更新：检查 GitHub Release 是否有比当前更新的版本，
 * 若有则下载对应平台的资产（Windows 为 zip、Linux 为 deb），
 * 解包替换本进程文件后重启自身。
 *
 * 设计要点：
 *  - 全程走 HTTPS，Windows 用系统证书库的 WinHTTP，Linux 用 OpenSSL 默认 CA。
 *  - 更新在后台线程里做，不阻塞代理启动；成功时直接退出并交由更新脚本重启。
 *  - 失败后仅打日志并继续用当前版本运行，不会陷入重启死循环。
 */
#include <string>

namespace hwp {

/** 启动时尝试自更新。
 *  @param currentVersion 形如 "1.0.1"
 *  @param repo          GitHub "owner/name"
 *  @param caFile        可选自定义 CA，空串表示用系统默认
 *  @param argc/argv     原进程参数，用于重启时原样传回
 *  若触发更新并成功，本函数不会返回（进程会被重启）。
 */
void maybeSelfUpdate(const std::string& currentVersion,
                     const std::string& repo,
                     const std::string& caFile,
                     int argc, char** argv);

}  // namespace hwp
