/*
 * Copyright (C) 2020 GlobalLogic
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once

#include <unistd.h>

#include <unordered_map>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <set>

enum class ProbingStage : uint8_t {
    Unknown,
    Success,
    Added,
    Binded,
    Removed,
    Error
};

struct DevId {
    DevId(uint16_t _vid, uint16_t _pid = 0x0000)
        : pid(_pid),
          vid(_vid) {
    }

    bool operator<(const DevId& rhs) const {
        return (devId < rhs.devId);
    }

    operator bool() const {
        return (devId != 0);
    }

    union {
        struct {
            const uint16_t pid;
            const uint16_t vid;
        } __attribute__((packed));
        const uint32_t devId;
    };
};

struct netlink_desc {
public:
    netlink_desc(int fd) : _fd(fd) {
    }

    ~netlink_desc() {
        close(_fd);
    }

    operator int() const {
        return _fd;
    }

private:
    const int _fd;
    netlink_desc(const netlink_desc&) = delete;
    netlink_desc& operator=(const netlink_desc&) = delete;
};

class UsbScanner {
public:
    using on_change_cb =
        std::function<void(const std::string&, DevId, ProbingStage)>;

    UsbScanner(const std::set<DevId>& knownDevices, const std::string& classDev,
               on_change_cb cb);
    virtual ~UsbScanner();

    ProbingStage Start();
    void Stop();

private:
    UsbScanner(const UsbScanner&) = delete;

    UsbScanner& operator=(const UsbScanner&) = delete;

    std::vector<std::string> ReadDir(const std::string& path);
    std::string GetDevPath(const std::string& sysPath);
    void UeventListen(const netlink_desc& socketDesc);
    DevId GetPidVid(std::string sysPath);
    void printMsg(char* src, int len);
    bool IsKnownDevice(DevId devId);
    void ScanConnectedUsbDevices();
    char* ReceiveMessage(int socketDesc);
    void HandleMessage(const char* message, ProbingStage stage);
    ProbingStage GetStage(const char* message);

    std::unordered_map<std::string, std::string> mDevices;
    std::set<DevId> mKnownDevices;
    static std::thread mThread;
    static std::mutex mLock;
    on_change_cb onChange;
    std::string mClassDev;
    static std::set<UsbScanner*> subscribers;
    static bool mNeedStop;
};
