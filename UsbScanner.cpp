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

#include <include/usb-scanner/UsbScanner.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>

#include <stdexcept>
#include <iostream>
#include <fstream>
#include <cerrno>
#include <memory>
#include <chrono>

#define LOG_TAG "UsbScanner"
#define LOG_NDEBUG 1

#include <log/log.h>
#include <cutils/uevent.h>

#ifdef __cpp_exceptions
#define safeCall(x) \
try\
{\
    (x);\
}\
catch (const std::exception &e)\
{\
    ALOGI("%s", e.what());\
}\
catch (...)\
{\
    ALOGI("%s", "Internal error");\
}
#else
#define safeCall(x) (x);
#endif

static const std::string actionTag{"ACTION="};
static const std::string systemTag{"SUBSYSTEM="};
static const std::string pathTag{"DEVPATH="};
static const std::string actionAdd{"add"};
static const std::string actionBind{"bind"};
static const std::string actionRemove{"remove"};
static const std::string sysfsPath{"/sys"};
static const std::string nameTag{"DEVNAME="};
static const std::string devFs{"/dev/"};
static const std::string classesPath{"/sys/class/"};
static const int ueventMsgLen = 4096;
static const int endChar = 2;
static const int bufSize = 256 * 1024;

std::thread UsbScanner::mThread;
std::mutex UsbScanner::mLock;
std::set<UsbScanner*> UsbScanner::subscribers;
bool UsbScanner::mNeedStop = false;

UsbScanner::UsbScanner(const std::set<DevId>& knownDevices,
                       const std::string& classDev, on_change_cb cb)
    : mKnownDevices(knownDevices),
      onChange(cb),
      mClassDev(classDev) {
}

UsbScanner::~UsbScanner() {
    Stop();
}

const char* FindTag(const char* p, const std::string& tag) {
    while (*p) {
        if (!std::strncmp(p, tag.c_str(), tag.length())) {
            return p + tag.length();
        }

        while (*p++) {
            ;
        }
    }

    return nullptr;
}

void UsbScanner::HandleMessage(const char* message, ProbingStage stage) {
    std::string sysPath;

    if (const char* p = FindTag(message, pathTag)) {
        sysPath = sysfsPath + p;
    }

    switch (stage) {
        case ProbingStage::Removed: {
            auto device = mDevices.find(sysPath);

            if (device != mDevices.end()) {
                ALOGV("Controlled device is unplugged. path: %s", device->first.c_str());

                if (onChange && !device->second.empty()) {
                    safeCall(onChange(mDevices[sysPath], 0, ProbingStage::Removed));
                }

                mDevices.erase(sysPath);
            }
            break;
        }

        case ProbingStage::Added: {
            if (const char* p = FindTag(message, systemTag)) {
                if (!std::strncmp(p, mClassDev.c_str(), mClassDev.size())) {
                    if (mDevices.count(sysPath) == 0 && IsKnownDevice(GetPidVid(sysPath))) {
                        mDevices.insert({sysPath, ""});
                    }
                }
            }
            break;
        }

        case ProbingStage::Binded: {
            for (auto& device : mDevices) {
                if (!device.first.compare(0, sysPath.length(), sysPath)) {
                    if (!device.second.empty()) {
                        ALOGV("Binded device has been already reported. path: %s",
                              sysPath.c_str());
                        break;
                    }

                    device.second = GetDevPath(device.first);

                    if (!device.second.empty()) {
                        ALOGV("Device is plugged: %s, reported path: %s.", sysPath.c_str(),
                              device.second.c_str());

                        if (onChange) {
                            safeCall(onChange(device.second.c_str(),
                                              GetPidVid(device.first.c_str()),
                                              ProbingStage::Added));
                        }
                        break;
                    }
                }
            }
            break;
        }

        default: {
            break;
        }
    }
}

ProbingStage UsbScanner::GetStage(const char* message) {
    ProbingStage stage = ProbingStage::Unknown;

    if (const char* p = FindTag(message, actionTag)) {
        if (!std::strncmp(p, actionAdd.c_str(), actionAdd.size())) {
            stage = ProbingStage::Added;
        }

        if (!std::strncmp(p, actionBind.c_str(), actionBind.size())) {
            stage = ProbingStage::Binded;
        }

        if (!std::strncmp(p, actionRemove.c_str(), actionRemove.size())) {
            stage = ProbingStage::Removed;
        }
    }

    return stage;
}

void UsbScanner::UeventListen(const netlink_desc& socketDesc) {
    char* message = nullptr;
    pollfd fds = {.fd = socketDesc, .events = POLLIN, .revents = 0};

    while (true) {
        fds.revents = 0;

        if (poll(&fds, 1, 1000) < 0) {
            ALOGE("Poll failed: %s.", std::strerror(errno));

            if (onChange) {
                safeCall(onChange("", 0, ProbingStage::Error));
                break;
            }
        }

        if (mNeedStop) {
            break;
        }

        if (!(fds.revents & POLLIN)) {
            continue;
        }

        message = ReceiveMessage(socketDesc);
        if (!message) {
            safeCall(onChange("", 0, ProbingStage::Error));
            break;
        }

        ProbingStage stage = GetStage(message);

        if (ProbingStage::Unknown == stage) {
            continue;
        }

        std::lock_guard<std::mutex> lock(UsbScanner::mLock);

        for (auto subscriber : subscribers) {
            subscriber->HandleMessage(message, stage);
        }
    }
}

std::string UsbScanner::GetDevPath(const std::string& sysPath) {
    std::string ttyPath;
    std::ifstream uevent(sysPath + "/uevent");

    if (uevent.good()) {
        while (!uevent.eof()) {
            std::string file;
            uevent >> file;
            std::size_t pos = file.find(nameTag);

            if (pos != std::string::npos) {
                ttyPath = devFs + file.substr(pos + nameTag.size());
            }
        }
    }

    return (ttyPath);
}

bool UsbScanner::IsKnownDevice(DevId devId) {
    bool isKnownDevice = false;

    for (auto dev : mKnownDevices) {
        if (dev.vid == devId.vid) {
            if (dev.pid == 0) {
                isKnownDevice = true;
            } else if (dev.pid == devId.pid) {
                isKnownDevice = true;
            }
        }
    }

    return isKnownDevice;
}

char* UsbScanner::ReceiveMessage(int socketDesc) {
    static char message[ueventMsgLen + endChar] = {0};
    const int n = uevent_kernel_multicast_recv(socketDesc, message, ueventMsgLen);

    if (n <= 0) {
        ALOGE("Read failed: %s.", std::strerror(errno));
        return nullptr;
    }

    if (n >= ueventMsgLen) {
        ALOGE("Buffer overflow.");
        return nullptr;
    }

    message[n + 0] = '\0';
    message[n + 1] = '\0';
    return message;
}

std::vector<std::string> UsbScanner::ReadDir(const std::string& path) {
    std::unique_ptr<DIR, int (*)(DIR*)> dir(opendir(path.c_str()), closedir);
    struct dirent* dirEntry = nullptr;
    std::vector<std::string> dirTree;

    if (!dir.get()) {
        ALOGE("%s: %s", strerror(errno), path.c_str());
    } else {
        while ((dirEntry = readdir(dir.get())) != NULL) {
            if (dirEntry->d_name[0] != '.') {
                dirTree.push_back(path + '/' + dirEntry->d_name);
            }
        }
    }

    return dirTree;
}

DevId UsbScanner::GetPidVid(std::string sysPath) {
    uint16_t vid = 0u, pid = 0u;

    while (sysPath.compare(sysfsPath)) {
        std::ifstream idVendor(sysPath + "/idVendor");
        std::ifstream idProduct(sysPath + "/idProduct");

        if (idVendor.good() && idProduct.good()) {
            idVendor >> std::hex >> vid;
            idProduct >> std::hex >> pid;
            break;
        }

        sysPath = sysPath.substr(0, sysPath.rfind('/'));
    }

    return (DevId(vid, pid));
}

void UsbScanner::ScanConnectedUsbDevices() {
    for (const auto& device : ReadDir(classesPath + mClassDev)) {
        char sysPath[PATH_MAX] = {0};

        if (!realpath(device.c_str(), sysPath)) {
            ALOGE("%s", std::strerror(errno));
            continue;
        }

        DevId devId = GetPidVid(sysPath);

        if (devId && IsKnownDevice(devId)) {
            std::string devPath = GetDevPath(device);
            mDevices.insert({sysPath, devPath});

            if (onChange && !devPath.empty()) {
                safeCall(onChange(mDevices[sysPath], devId, ProbingStage::Added));
            }
        }
    }
}

ProbingStage UsbScanner::Start() {
    std::lock_guard<std::mutex> lock(UsbScanner::mLock);

    if (!UsbScanner::mThread.joinable()) {
        int netlinkDesc = -1;
        netlinkDesc = uevent_open_socket(bufSize, true);

        if (netlinkDesc < 0) {
            ALOGE("Can not open a socket: %s.", std::strerror(errno));
            return ProbingStage::Error;
        }

        mNeedStop = false;
        mThread = std::thread([netlinkDesc, this]() {
            UeventListen(netlinkDesc);
        });

        if (!mThread.joinable()) {
            ALOGE("USB scanner not started");
            return ProbingStage::Error;
        }
    }

    if (subscribers.insert(this).second) {
        ScanConnectedUsbDevices();
    }

    return ProbingStage::Success;
}

void UsbScanner::Stop() {
    std::lock_guard<std::mutex> lock(UsbScanner::mLock);

    subscribers.erase(this);
    if (mThread.joinable() && subscribers.size() == 0) {
        mNeedStop = true;
        mThread.join();
    }
}
