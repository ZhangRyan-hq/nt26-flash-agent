"""Explicit Linux-only NT26 operations; inspect/devices do not open ports."""
from __future__ import annotations
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import time

from . import __version__
from .devices import DeviceError, enumerate_devices, select_device, probe_at, enter_rom
from .package import FLASH_BASE, FLASH_SIZE, parse_package, make_plan
from .profile import load_agent_file, ROM_VERSIONS, AGENT_CONTROL, configure_board
from .protocol import SerialTransport, Session, ProtocolError, build_image_header


def emit(value):
    print(json.dumps(value, ensure_ascii=False, indent=2), flush=True)


def notice(text):
    print(text, file=sys.stderr, flush=True)


def write_json(path, value):
    with open(path, 'x', encoding='utf-8') as f:
        json.dump(value, f, ensure_ascii=False, indent=2)
        f.write('\n')


def wait_rom(args):
    devices = enumerate_devices()
    runtime = (select_device(devices, 'runtime', port=args.at_port)
               if args.at_port else None)
    location = runtime.physical_location if runtime else None
    roms = [d for d in devices if d.role == 'rom']
    if args.port:
        return select_device(devices, 'rom', port=args.port, physical_location=location)
    if roms and runtime is None:
        if any(d.role == 'runtime' for d in devices):
            raise DeviceError('同时发现正常模式和下载模式设备，请明确 --at-port 或 --port。')
        return select_device(devices, 'rom')
    if runtime and any(d.physical_location == location for d in roms):
        return select_device(devices, 'rom', physical_location=location)
    if not args.enter_rom:
        raise DeviceError('未发现下载口。可按住 BOOT 短按 RESET，或使用 --enter-rom。')
    runtime = runtime or select_device(devices, 'runtime')
    notice(f'通过 {runtime.realpath} 请求进入下载模式（不擦写 Flash）')
    location = enter_rom(runtime)['physical_location']
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        devices = enumerate_devices()
        candidates = [d for d in devices if d.role == 'rom' and d.physical_location == location]
        if candidates:
            return select_device(devices, 'rom', port=args.port, physical_location=location)
        time.sleep(0.1)
    raise DeviceError('未等到同一 USB 位置的 17d1:0001 下载口；请检查 BOOT/RESET。')


@contextmanager
def connected(args):
    agent = load_agent_file(args.agent)
    dev = wait_rom(args)
    # Recheck identity immediately before opening; never trust a stale tty number.
    dev = select_device(enumerate_devices(), 'rom', port=dev.realpath,
                        physical_location=dev.physical_location)
    with SerialTransport.open(dev.realpath, baudrate=130000, timeout=3) as transport:
        session = Session(transport, timeout=3, sync_attempts=6)
        notice(f'连接下载口 {dev.realpath}，核对 ROM 并加载临时 RAM 引导程序')
        version = session.load_agent(agent, expected_rom_versions=ROM_VERSIONS,
                                     agent_control=AGENT_CONTROL)
        try:
            runtime_result = configure_board(session)
        except BaseException:
            try:
                session.reset()
            except Exception as reset_error:
                notice(f'恢复复位未确认：{reset_error}；可短按 RESET。')
            raise
        yield session, {'device': dev.to_dict(), 'rom_version_raw': version.hex(),
                        'runtime_result': runtime_result}


def read_flash(session, address, size, label):
    data = bytearray()
    last = -1
    while len(data) < size:
        n = min(0x10000, size - len(data))
        data.extend(session.read_memory(address + len(data), n))
        progress = len(data) * 100 // size
        if progress // 10 != last:
            notice(f'{label}: {progress}%')
            last = progress // 10
    return bytes(data)


def backup_flash(session, directory):
    data = read_flash(session, FLASH_BASE, FLASH_SIZE, '读取完整 4 MiB 备份')
    target = directory / 'flash-before.bin'
    fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    digest = hashlib.sha256(data).hexdigest()
    if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
        raise OSError('备份落盘校验失败')
    write_json(directory / 'backup.json', {'address': FLASH_BASE, 'size': len(data),
                                          'sha256': digest, 'file': target.name})
    return data


def verify_installed_base(package, backup):
    for entry in package.entries[:3]:
        offset = entry.address - FLASH_BASE
        actual = hashlib.sha256(backup[offset:offset + len(entry.data)]).hexdigest()
        if actual != entry.payload_sha256:
            raise ValueError(f'板上 {entry.tag} 与目标包不同，不能仅更新应用；请选择 full 模式。')


def flash_images(session, package, plan, directory, before):
    if plan['mode'] == 'app':
        verify_installed_base(package, before)
    # BL last reduces the interval with a changed bootloader and unfinished AP.
    ordered = sorted(plan['regions'], key=lambda r: r['tag'] == 'BL')
    entries = {entry.tag: entry for entry in package.entries}
    for region in ordered:
        entry = entries[region['tag']]
        notice(f"擦除 {entry.tag}: 0x{region['erase_offset']:x} + 0x{region['erase_size']:x}")
        session.erase(region['erase_offset'], region['erase_size'])
        notice(f'写入 {entry.tag}: {len(entry.data)} 字节')
        last = [-1]
        def progress(done, total):
            percent = done * 100 // total
            if percent // 10 != last[0]:
                notice(f'{entry.tag}: {percent}%')
                last[0] = percent // 10
        session.burn(entry.data, image_type='FLEX' if entry.tag == 'PKGFLXAPP' else entry.tag,
                     address=region['offset'], storage='ap', progress=progress)
    verify_flash(session, package, plan, directory, before)


def verify_flash(session, package, plan, directory, before):
    # Verify the final state, after every erase/burn has finished.
    entries = {entry.tag: entry for entry in package.entries}
    for region in plan['regions']:
        entry = entries[region['tag']]
        got = read_flash(session, entry.address, len(entry.data), f'回读 {entry.tag}')
        if hashlib.sha256(got).hexdigest() != entry.payload_sha256:
            raise ProtocolError(f'{entry.tag} 写后回读 SHA256 不一致，停止烧录')
        write_json(directory / f'verified-{entry.tag}.json', {
            'tag': entry.tag, 'address': entry.address, 'bytes': len(got),
            'sha256': entry.payload_sha256})
    for generated in plan.get('generated_headers', []):
        entry = entries[generated['tag']]
        expected = build_image_header(entry.data, image_type=entry.tag,
                                      address=entry.address - FLASH_BASE)
        got = session.read_memory(FLASH_BASE + generated['offset'], len(expected))
        if got != expected:
            raise ProtocolError(f"{entry.tag} 自动生成的启动头与待烧固件不符")
        write_json(directory / f'verified-header-{entry.tag}.json', {
            'tag': entry.tag, 'offset': generated['offset'], 'bytes': len(got),
            'sha256': hashlib.sha256(got).hexdigest()})
    # Confirm every unplanned byte stayed unchanged, including calibration/NV.
    for region in plan['preserved_regions']:
        start, size = region['offset'], region['size']
        got = read_flash(session, FLASH_BASE + start, size, f'核对保留区 0x{start:x}')
        if got != before[start:start + size]:
            raise ProtocolError(f'保留区 0x{start:x} 内容改变；停止并保留备份')


def parser():
    p = argparse.ArgumentParser(description='NT26F6D0 / F6D_A Linux 烧录器')
    p.add_argument('--version', action='version', version=__version__)
    sub = p.add_subparsers(dest='command', required=True)
    sub.add_parser('devices', help='只读枚举 USB 串口')
    inspect = sub.add_parser('inspect', help='离线校验固件并输出烧录计划')
    inspect.add_argument('package', type=Path)
    inspect.add_argument('--mode', choices=('full', 'app'), default='full')
    probe = sub.add_parser('probe', help='只读 AT / 版本查询')
    probe.add_argument('--at-port')
    for cmd in ('diagnose', 'flash'):
        q = sub.add_parser(cmd, help='RAM 引导与只读诊断' if cmd == 'diagnose' else '备份、烧录、逐区回读校验')
        q.add_argument('--port', help='明确指定 17d1:0001 下载串口')
        q.add_argument('--at-port', help='明确指定 3505:0003 AT 串口')
        q.add_argument('--enter-rom', action='store_true', help='显式请求 AT 复位到下载模式')
        q.add_argument('--agent', type=Path, help='原厂 EC718PM USB agentboot.bin（须匹配已审核 SHA256）')
        if cmd == 'diagnose':
            q.add_argument('--report', type=Path)
        else:
            q.add_argument('package', type=Path)
            q.add_argument('--mode', choices=('full', 'app'), default='full')
            q.add_argument('--confirm-sha256', required=True, help='明确确认待写入固件包的完整 SHA256')
            q.add_argument('--backup-dir', required=True, type=Path, help='新的备份/记录目录，已有目录会拒绝')
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == 'devices':
            emit([d.to_dict() for d in enumerate_devices() if d.role != 'other'])
        elif args.command == 'inspect':
            emit(make_plan(parse_package(args.package), args.mode))
        elif args.command == 'probe':
            emit(probe_at(select_device(enumerate_devices(), 'runtime', port=args.at_port)))
        elif args.command == 'diagnose':
            if args.report and args.report.exists():
                raise ValueError('报告文件已存在，请指定新路径')
            with connected(args) as (session, result):
                try:
                    sample = session.read_memory(FLASH_BASE + 0x3000, 240)
                    result.update(read_test_bytes=len(sample), read_test_sha256=hashlib.sha256(sample).hexdigest(),
                                  flash_written=False)
                finally:
                    session.reset()
                result['reset_acknowledged'] = True
            if args.report:
                write_json(args.report, result)
            emit(result)
        else:
            package = parse_package(args.package)
            plan = make_plan(package, args.mode)
            if args.confirm_sha256.lower() != package.sha256:
                raise ValueError('确认的 SHA256 与当前固件文件不一致；未连接设备')
            load_agent_file(args.agent)  # All file validation precedes mode change.
            args.backup_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
            write_json(args.backup_dir / 'plan.json', plan)
            with connected(args) as (session, result):
                try:
                    result.update(timestamp=datetime.now(timezone.utc).isoformat(), package_sha256=package.sha256)
                    write_json(args.backup_dir / 'device.json', result)
                    before = backup_flash(session, args.backup_dir)
                    if plan['mode'] == 'app':
                        verify_installed_base(package, before)
                except BaseException:
                    try:
                        session.reset()
                    except Exception as reset_error:
                        notice(f'写入前取消，恢复复位未确认：{reset_error}；可短按 RESET。')
                    raise
                flash_images(session, package, plan, args.backup_dir, before)
                session.reset()
            result.update(success=True, readback_verified=True, generated_headers_verified=True, preserved_regions_verified=True,
                          backup_dir=str(args.backup_dir.resolve()), reset_acknowledged=True)
            write_json(args.backup_dir / 'success.json', result)
            emit(result)
        return 0
    except (OSError, ValueError, RuntimeError, ImportError) as exc:
        notice(f'错误：{exc}')
        return 1
    except KeyboardInterrupt:
        notice('已中断。若处于下载模式可短按 RESET；若已开始擦写，请保留备份并重新完整烧录。')
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
