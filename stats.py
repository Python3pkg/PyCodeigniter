#!/usr/bin/python
#coding=utf8
import time
import json

def net_stats(interface=None):
    with open('/proc/net/dev') as dev:
        content=dev.read()
    results=[]
    devices=[]
    if interface==None:
        for i in content.splitlines():
            if ':' in i.split()[0]:
                devices.append(i.split()[0].replace(':',''))
    else:
        devices.append(interface)
    def _calc(interface,content):
        for line in content.splitlines():
            if interface in line:
                try:
                    data = line.split('%s:' % interface)[1].split()
                    rx_bits, tx_bits = (int(data[0]) * 8, int(data[8]) * 8)
                    return {interface:[rx_bits,tx_bits]}
                except Exception as er:
                    return {interface:[-1,-1]}
    for interface in devices:
        results.append(_calc(interface,content))
    return results


def mem_stats():
    with open('/proc/meminfo') as f:
        for line in f:
            if line.startswith('MemTotal:'):
                mem_total = int(line.split()[1]) * 1024
            if line.startswith('MemFree:'):
                mem_used = mem_total - (int(line.split()[1]) * 1024)
    return [mem_used, mem_total]


def cpu_util(sample_duration=1):
    with open('/proc/stat') as f1:
        with open('/proc/stat') as f2:
            line1 = f1.readline()
            time.sleep(sample_duration)
            line2 = f2.readline()
    deltas = [int(b) - int(a) for a, b in zip(line1.split()[1:], line2.split()[1:])]
    idle_delta = deltas[3]
    total = sum(deltas)
    util_pct = 100 * (float(total - idle_delta) / total)
    return util_pct


def disk_busy(device=None, sample_duration=1):
    with open('/proc/diskstats') as f1:
        with open('/proc/diskstats') as f2:
            content1 = f1.read()
            time.sleep(sample_duration)
            content2 = f2.read()
    results=[]
    devices=[]
    if device==None:
        for i in content1.splitlines():
            devices.append(i.split()[2])
    else:
        devices.append(device)
    def _calc(device,content1,content2):
        sep = '%s ' % device
        try:
            for line in content1.splitlines():
                if sep in line:
                    io_ms1 = line.strip().split(sep)[1].split()[9]
                    break
            for line in content2.splitlines():
                if sep in line:
                    io_ms2 = line.strip().split(sep)[1].split()[9]
                    break
            delta = int(io_ms2) - int(io_ms1)
            total = sample_duration * 1000
            busy_pct = 100 - (100 * (float(total - delta) / total))
            return { '%s' % device:busy_pct}
        except Exception as er:
            return { '%s' % device:-1}

    for device in devices:
        results.append(_calc(device,content1,content2))
    return results


def load_avg():
    with open('/proc/loadavg') as f:
        line = f.readline()
    load_avg1,load_avg5,load_avg15 = float(line.split()[0]),float(line.split()[1]),float(line.split()[2])  # 1 minute load average
    return [load_avg1,load_avg5,load_avg15]

def main():
    result={}
    stats=[net_stats,load_avg,disk_busy,cpu_util,mem_stats]
    for func in stats:
        result[func.__name__]=func()
    print json.dumps(result)

if __name__ == '__main__':
    main()




