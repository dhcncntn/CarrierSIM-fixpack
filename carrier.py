#!/usr/bin/env python3
"""Vodafone HU для всех обнаруженных SIM по полному IMSI."""
from __future__ import annotations
import argparse
import asyncio
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import stat
import struct
import sys
import time
import zipfile

ROOT = Path(__file__).resolve().parent

PARENT = '/var/mobile/Library/Carrier Bundles'
TARGET = PARENT + '/iPhone'
PAYLOAD_PATH = 'q0/q1/q2/q3/q4/payload'
BUNDLE = 'Vodafone_hu.bundle'
MAX_BYTES = 64 * 1024 * 1024
MAX_NODES = 4000
BOOK_FILES = ('Books/Books.plist', 'Books/Sync/Books.plist', 'Books/Sync/Upload.plist',
              'Books/Sync/Database/OutstandingAssets_4.sqlite',
              'Books/Sync/Database/OutstandingAssets_4.sqlite-shm',
              'Books/Sync/Database/OutstandingAssets_4.sqlite-wal')
BOOK_DIRS = ('Books', 'Books/Sync', 'Books/Sync/Database')

# Derived Books state changes on the phone at any moment while iOS holds it
# open: sqlite sidecars AND the sqlite databases themselves (WAL checkpointing
# rewrites bytes), lock files, sync-queue stores under Sync/ and MetadataStore/.
# Their bytes are never stable across two reads, so exact comparison is
# meaningless: presence + type is checked, content is ignored. User documents
# match none of these patterns and are always compared byte-for-byte.
def is_volatile_book_node(name):
    return (name.endswith(('.sqlite-shm', '.sqlite-wal', '.lock'))
            or (name.endswith('.sqlite')
                and (name.startswith('Sync/') or name.startswith('MetadataStore/'))))


def books_match(a, b):
    # Tolerant: b must contain every node of a with matching type, and every
    # non-volatile file must match byte-for-byte. Volatile nodes and extra
    # nodes in b (iOS-created caches/locks, or files added mid-operation) are
    # tolerated: none of them can make a restore invalid.
    for name, (kind, data) in a.items():
        if name not in b:
            return False
        other_kind, other_data = b[name]
        if kind != other_kind:
            return False
        if kind == 'f' and is_volatile_book_node(name):
            continue
        if data != other_data:
            return False
    return True



def require(ok, message):
    if not ok:
        raise RuntimeError(message)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def save_json(path, value):
    tmp = path.with_suffix(path.suffix + '.tmp')
    with tmp.open('w', encoding='utf-8') as f:
        json.dump(value, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    tmp.replace(path)

def safe_name(name):
    require(bool(name) and not name.startswith('/') and '\\' not in name and
            all(p not in ('', '.', '..') for p in name.split('/')), 'Unsafe tree path: ' + name)
    return name


def validate_tree(tree):
    require(len(tree) <= MAX_NODES, 'Too many tree nodes')
    require(sum(len(v[1]) for v in tree.values()) <= MAX_BYTES, 'Tree too large')
    for name, (kind, data) in tree.items():
        safe_name(name)
        require(kind in ('d', 'f', 'l'), 'Unknown node type')
        for parent in PurePosixPath(name).parents:
            if str(parent) != '.':
                require(tree.get(str(parent), (None,))[0] == 'd', 'Missing or non-directory parent')
        if kind == 'l':
            require(b'\x00' not in data and len(data) <= 4096, 'Invalid symlink')

def tree_hash(tree):
    return digest(json.dumps({n: [k, digest(b)] for n, (k, b) in sorted(tree.items())},
                             sort_keys=True).encode())

def zi(name, kind, streaming=False):
    mode = {'f': stat.S_IFREG | 0o644, 'd': stat.S_IFDIR | 0o755,
            'l': stat.S_IFLNK | 0o777}[kind]
    z = zipfile.ZipInfo(name + ('/' if kind == 'd' and not name.endswith('/') else ''),
                        (2026, 9, 24, 0, 0, 0))
    z.create_system = 3
    z.external_attr = mode << 16
    if streaming:
        z.extra = struct.pack('<HHH', 0x5A53, 2, mode)
    return z

def write_tree_zip(path, tree):
    validate_tree(tree)
    with zipfile.ZipFile(path, 'x') as z:
        for name, (kind, data) in sorted(tree.items()):
            z.writestr(zi(name, kind), data)

def read_tree_zip(path):
    tree = {}
    with zipfile.ZipFile(path) as z:
        require(len(z.infolist()) <= MAX_NODES and sum(i.file_size for i in z.infolist()) <= MAX_BYTES,
                'Archive too large')
        for i in z.infolist():
            name = safe_name(i.filename.rstrip('/'))
            require(name not in tree, 'Duplicate archive entry')
            mode = stat.S_IFMT(i.external_attr >> 16)
            require(mode in (0, stat.S_IFDIR, stat.S_IFREG, stat.S_IFLNK), 'Unsupported archive type')
            tree[name] = ('d' if i.is_dir() else 'l' if mode == stat.S_IFLNK else 'f', z.read(i))
    validate_tree(tree)
    return tree

def bundle_info(tree, name=BUNDLE):
    prefix = name + '/'
    def pl(file):
        value = tree.get(prefix + file)
        require(value is not None and value[0] == 'f', 'Missing ' + prefix + file)
        return plistlib.loads(value[1])
    info, carrier = pl('Info.plist'), pl('carrier.plist')
    require(any(n.startswith(prefix + 'signatures/') and k == 'f' for n, (k, _) in tree.items()),
            'No signature files (presence is not cryptographic verification)')
    return info, carrier

def staging_archive(payload=None):
    # Six staging levels keep system links inside the ZIP while unpacking.
    # After placement the same six '..' components resolve from /private/var/mobile/... to /.
    tree = {'META-INF': ('d', b''), 'META-INF/com.apple.ZipMetadata.plist':
            ('f', plistlib.dumps({'Version': 2}, fmt=plistlib.FMT_BINARY)),
            'p0': ('d', b''), 'p0/p1': ('d', b''), 'p0/p1/p2': ('d', b''),
            'p0/p1/p2/link': ('l', ('../../../' + PARENT[1:]).encode())}
    def directories(path):
        cursor = ''
        for part in path.split('/'):
            cursor += ('/' if cursor else '') + part
            tree[cursor] = ('d', b'')
    directories(PARENT[1:])
    if payload is not None:
        directories(PAYLOAD_PATH)
        system_names = set(TARGET_BUNDLES)
        for kind, data in payload.values():
            if kind == 'l' and data.startswith(SYSTEM_PREFIX.encode()):
                name = data.decode().removeprefix(SYSTEM_PREFIX)
                require(re.fullmatch(r'[A-Za-z0-9_]+\.bundle', name), 'Неожиданная системная ссылка')
                system_names.add(name)
        for name in system_names:
            directories('System/Library/Carrier Bundles/iPhone/'+name)
        tree.update({PAYLOAD_PATH+'/'+n:v for n,v in payload.items()})
    b = io.BytesIO()
    with zipfile.ZipFile(b, 'w', allowZip64=False) as z:
        for name, (kind, data) in sorted(tree.items()):
            z.writestr(zi(name, kind, streaming=True), data)
    return b.getvalue()

async def exists(afc, path):
    from pymobiledevice3.exceptions import AfcFileNotFoundError
    try:
        return await afc.stat(path)
    except AfcFileNotFoundError:
        return None

async def remote_tree(afc, root):
    # iOS rewrites Books state while it is read (caches, sidecars, mtimes),
    # which shows up as transient "changed during read" errors. Re-read the
    # whole tree a couple of times before giving up: the last attempt sees a
    # quiescent tree in practice.
    for attempt in range(3):
        try:
            return await _remote_tree_once(afc, root)
        except RuntimeError as error:
            if attempt == 2 or not any(t in str(error) for t in (
                    'changed during read', 'Remote directory changed', 'Remote size mismatch')):
                raise
            await asyncio.sleep(1)

async def _remote_tree_once(afc, root):
    tree = {}
    total = 0
    async def visit(path, name='', depth=0):
        nonlocal total
        require(depth < 32 and len(tree) < MAX_NODES, 'Remote tree limit')
        before = await afc.stat(path)
        kind = before['st_ifmt']
        if kind == 'S_IFDIR':
            if name:
                tree[name] = ('d', b'')
            children = sorted(await afc.listdir(path))
            for child in children:
                require(child not in ('', '.', '..') and '/' not in child, 'Invalid remote name')
                await visit(path + '/' + child, name + '/' + child if name else child, depth + 1)
            require(children == sorted(await afc.listdir(path)), 'Remote directory changed')
        elif kind == 'S_IFLNK':
            require(name, 'Root is a symlink')
            tree[name] = ('l', before['LinkTarget'].encode())
        elif kind == 'S_IFREG':
            require(name and before['st_size'] <= MAX_BYTES, 'Remote file limit')
            data = await afc.get_file_contents(path)
            total += len(data)
            require(total <= MAX_BYTES and len(data) == before['st_size'], 'Remote size mismatch')
            tree[name] = ('f', data)
        else:
            raise RuntimeError('Unsupported remote node: ' + path)
        after = await afc.stat(path)
        if kind == 'S_IFDIR':
            # iOS touches directory mtimes (Books/Managed) while we read; the
            # double listdir above already proves the listing is stable. Only
            # the node kind must not change mid-walk.
            require(after['st_ifmt'] == 'S_IFDIR', 'Remote file changed during read: ' + path)
        else:
            require(before == after, 'Remote file changed during read: ' + path)
    require((await afc.stat(root))['st_ifmt'] == 'S_IFDIR', 'Carrier root is not a directory')
    await visit(root)
    validate_tree(tree)
    return tree

async def books_snapshot(afc, run):
    # Preserve the entire Books tree; restore_books below returns it fully.
    node = await exists(afc, 'Books')
    tree = await remote_tree(afc, 'Books') if node else {}
    write_tree_zip(run / 'books.zip', tree)
    state = {'existed': bool(node), 'hash': tree_hash(tree)}
    save_json(run / 'books.json', state)
    require(books_match(tree, (await remote_tree(afc, 'Books') if node else {})),
            'Books changed before staging')
    for path in BOOK_FILES:
        rel = path.removeprefix('Books/')
        require(rel not in tree or tree[rel][0] == 'f', 'Unexpected Books sync artifact')
    for path in BOOK_DIRS[1:]:
        rel = path.removeprefix('Books/')
        require(rel not in tree or tree[rel][0] == 'd', 'Unexpected Books directory')
    return tree, bool(node)

async def restore_books(afc, tree, existed):
    # Full-tree restore: AirTraffic on iOS 27 deletes purchased EPUBs from
    # Books during sync, so restoring only BOOK_FILES always fails the final
    # check with "Books state differs". Restore everything: missing dirs and
    # files, conflicting files, and derived extras. iOS rewrites caches under
    # Books while this runs, so up to three reconcile passes are made before
    # the state is accepted as truly diverged.
    validate_tree(tree)
    for name, (kind, _data) in tree.items():
        require(kind in ('d', 'f'),
                f'Неожиданный тип узла Books в резервной копии: {name} ({kind})')
    after = {}
    for attempt in range(3):
        await _reconcile_books(afc, tree, existed)
        after = await remote_tree(afc, 'Books') if await exists(afc, 'Books') else {}
        if books_match(after, tree):
            return
        if attempt < 2:
            await asyncio.sleep(1.5)
    missing = [n for n in tree if n not in after]
    changed = [n for n in tree if n in after and tree[n] != after[n]
               and not (tree[n][0] == 'f' and is_volatile_book_node(n))]
    extra = [n for n in after if n not in tree]
    raise RuntimeError(
        'Books state differs; backups retained, inspect before retry '
        f'(missing={len(missing)} changed={changed[:10]} extra={extra[:10]})')

async def _reconcile_books(afc, tree, existed):
    current = await remote_tree(afc, 'Books') if await exists(afc, 'Books') else {}
    if books_match(current, tree):
        return
    # 1. Delete derived extras, deepest first (files before their parent dirs).
    #    Anything that could be user content (non-volatile, outside Sync/) is
    #    kept: a book added during the operation must never be lost. Known
    #    lock files are NOT deleted here: step 4 removes them only if
    #    they are empty regular files, otherwise it stops and keeps the backup.
    skip_extra = ('Managed/.Managed.plist.lock', 'Sync/.bookSync.lock')
    for name in sorted(set(current) - set(tree),
                       key=lambda n: (n.count('/'), n), reverse=True):
        if name in skip_extra:
            continue
        kind, _data = current[name]
        path = 'Books/' + name
        if kind == 'd':
            node = await exists(afc, path)
            if node is None:
                continue
            require(node['st_ifmt'] == 'S_IFDIR',
                    f'Тип узла Books изменился во время восстановления: {path}')
            if await afc.listdir(path):
                continue  # children not removed yet; final check will report
            await afc.rm_single(path)
        elif kind == 'f':
            if not is_volatile_book_node(name) and not name.startswith('Sync/'):
                continue  # could be user content; keep it
            if await exists(afc, path) is not None:
                await afc.rm_single(path)
        else:
            raise RuntimeError(f'Неожиданный тип узла Books на телефоне: {path} ({kind})')
    # 2. Create missing dirs, shallowest first so parents exist.
    for name in sorted(set(tree) - set(current),
                       key=lambda n: (n.count('/'), n)):
        if tree[name][0] == 'd' and await exists(afc, 'Books/' + name) is None:
            await afc.makedirs('Books/' + name)
    # 3. Write missing files and overwrite conflicting ones.
    for name, (kind, data) in sorted(tree.items(),
                                     key=lambda item: (item[0].count('/'), item[0])):
        if kind != 'f':
            continue
        if current.get(name) == ('f', data):
            continue
        if is_volatile_book_node(name) and current.get(name, (None,))[0] == 'f':
            continue  # sidecar/db exists; its bytes are ephemeral, no rewrite needed
        path = 'Books/' + name
        node = await exists(afc, path)
        require(node is None or node['st_ifmt'] == 'S_IFREG',
                f'Вместо файла Books обнаружен каталог/ссылка; сохраняю копию: {path}')
        await afc.makedirs(str(PurePosixPath(path).parent))
        await afc.set_file_contents(path, data)
        require(await afc.get_file_contents(path) == data,
                f'Books restore mismatch: {path}')
    # 4. Remove generated empty lock files that were not in the backup.
    # Never delete a pre-existing lock or one with unexpected contents/type.
    for rel in ('Managed/.Managed.plist.lock', 'Sync/.bookSync.lock'):
        if rel not in tree:
            path = 'Books/' + rel
            node = await exists(afc, path)
            if node is not None:
                require(node['st_ifmt'] == 'S_IFREG' and node['st_size'] == 0,
                        'Unexpected generated Books lock; retain backup')
                await afc.rm_single(path)
    # 5. Remove newly created empty sync dirs if Books did not have them.
    for path in reversed(BOOK_DIRS):
        was_present = existed if path == 'Books' else path.removeprefix('Books/') in tree
        if not was_present and await exists(afc, path) and not await afc.listdir(path):
            await afc.rm_single(path)

async def clean_outstanding(afc):
    # iOS tracks Book sync assets by Persistent ID in the OutstandingAssets
    # store (Books/Sync/Database/OutstandingAssets_*.sqlite; the numeric suffix
    # varies across iOS versions). Path-based assets keep one row per
    # identifier, so after an interrupted session the stale row makes iOS
    # silently drop that asset from every later manifest (observed as
    # "2 of 3 confirmed" on iOS 27). Real book assets never use relative
    # paths, so removing path-like rows only touches sync-tool leftovers and
    # is safe for the user's library. Best effort: never raises.
    import sqlite3, shutil, tempfile
    try:
        names = [n for n in await afc.listdir('Books/Sync/Database')
                 if n.startswith('OutstandingAssets_') and n.endswith('.sqlite')]
    except Exception:
        return
    tmp = Path(tempfile.mkdtemp())
    try:
        for name in names:
            base = 'Books/Sync/Database/' + name
            try:
                (tmp / name).write_bytes(await afc.get_file_contents(base))
            except Exception:
                continue
            for suffix in ('-wal', '-shm'):
                try:
                    (tmp / (name + suffix)).write_bytes(await afc.get_file_contents(base + suffix))
                except Exception:
                    pass
            try:
                db = sqlite3.connect(tmp / name)
                dropped = 0
                for table in ('ZBCOUTSTANDINGASSET', 'ZBCINSTALLEDASSET'):
                    try:
                        cols = {r[1] for r in db.execute(f'pragma table_info({table})')}
                        if 'ZPERSISTENTID' in cols:
                            dropped += db.execute(
                                f"delete from {table} where ZPERSISTENTID LIKE '../%'").rowcount
                    except Exception:
                        pass
                db.commit(); db.close()
            except Exception:
                continue
            if not dropped:
                continue
            try:
                await afc.set_file_contents(base, (tmp / name).read_bytes())
                for suffix in ('-wal', '-shm'):
                    try: await afc.rm_single(base + suffix)
                    except Exception: pass
                print(f'Очистил зависшие записи синхронизации AirTraffic: {dropped}.', flush=True)
            except Exception as e:
                print(f'Не удалось обновить {name}: {e}', flush=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


async def transfer(device, run, payload=None, expected=None, recovery=False):
    from pymobiledevice3.services.afc import AfcService
    run.mkdir(parents=True, exist_ok=False)
    token = os.urandom(10).hex()
    source, link, exported = ('airlift-' + t + '-' + token for t in ('src', 'link', 'saved'))
    final_source = source + '/' + PAYLOAD_PATH if payload is not None else exported
    assets = [(f'../../{source}/p0/p1/p2/link', link),
              ('../../../' + TARGET.removeprefix('/var/mobile/'), exported),
              ('../../' + final_source, link + '/iPhone')]
    journal = {'schema': 1, 'udid_hash': digest(device.udid.encode()), 'target': TARGET,
               'source': source, 'link': link, 'exported': exported,
               'complete': False, 'phase': 'created', 'payload_hash': tree_hash(payload) if payload is not None else None}
    def phase(name, **values):
        journal.update(phase=name, **values)
        save_json(run / 'journal.json', journal)
    phase('created')
    snapshot = None
    async with AfcService(device) as afc:
        for path in (source, link, exported):
            require(await exists(afc, path) is None, 'Staging path collision')
        books, books_existed = await books_snapshot(afc, run)
        await clean_outstanding(afc)
        mutated = False
        try:
            raw = staging_archive(payload)
            (run / 'staging.zip').write_bytes(raw)
            if payload is not None:
                write_tree_zip(run / 'desired.zip', payload)
            phase('staging', requires_recovery=True)
            mutated = True
            service = await device.start_lockdown_service('com.apple.streaming_zip_conduit')
            try:
                await service.send_plist({'MediaSubdir': source}, fmt=plistlib.FMT_BINARY)
                await service.sendall(raw)
                reply = await asyncio.wait_for(service.recv_plist(), 30)
                require(reply.get('Status') == 'DataComplete', 'Streaming ZIP was rejected')
            finally:
                await service.close()
            node = await afc.stat(source + '/p0/p1/p2/link')
            require(node['st_ifmt'] == 'S_IFLNK' and node.get('LinkTarget') == '../../../' + PARENT[1:],
                    'Staged link mismatch')
            if payload is not None:
                require(await remote_tree(afc, source + '/' + PAYLOAD_PATH) == payload, 'Staged carrier tree mismatch')
            await afc.makedirs('Books/Sync')
            # Item IDs must be unique per sync: iOS dedupes outstanding Book
            # assets against earlier syncs with the same (DSID, Item ID), and a
            # colliding ID silently drops that asset from the next manifest
            # (observed as "2 of 3 assets confirmed" on iOS 27).
            item_base = int(time.time() * 1000) % 1_000_000_000
            metadata = plistlib.dumps({'Books': [{'Persistent ID': a, 'Item ID': str(item_base + i),
                                                  'DSID': '1'}
                                      for i, (a, _) in enumerate(assets, 1)]}, fmt=plistlib.FMT_BINARY)
            await afc.set_file_contents('Books/Sync/Books.plist', metadata)
            require(await afc.get_file_contents('Books/Sync/Books.plist') == metadata, 'Books staging mismatch')
            async def pause():
                nonlocal snapshot
                phase('export-check')
                # FileComplete is asynchronous: wait for the directory to appear.
                # After a reboot / heavy Books reindexing iOS can take well over
                # 4s to materialize the export, so poll up to ~90 seconds.
                for _ in range(150):
                    if await exists(afc, exported):
                        break
                    await asyncio.sleep(0.6)
                node = await exists(afc, exported)
                if node is None and recovery and payload is not None:
                    phase('recovery-final-authorized')
                    return
                require(node and node['st_ifmt'] == 'S_IFDIR',
                        'No exported catalog. Do not retry blindly; inspect journal and original paths.')
                phase('original-exported')
                snapshot = await remote_tree(afc, exported)
                write_tree_zip(run / 'original.zip', snapshot)
                phase('backup-saved', original_hash=tree_hash(snapshot))
                if expected is not None:
                    require(snapshot == expected, 'Carrier catalog changed since snapshot; recover this run')
                require(await remote_tree(afc, exported) == snapshot, 'Export changed after backup')
                phase('final-authorized')
            phase('host-started')
            await host_session(device.udid, assets, pause, run)
            for _ in range(30):
                if await exists(afc, final_source) is None:
                    break
                await asyncio.sleep(0.1)
            require(await exists(afc, final_source) is None, 'Final source not consumed; operation unconfirmed')
            phase('placement-observed', complete=True, requires_recovery=False)
        except BaseException as error:
            journal['operation_error'] = str(error)
            save_json(run / 'journal.json', journal)
            raise
        finally:
            if mutated:
                try:
                    await restore_books(afc, books, books_existed)
                    journal['books_restored'] = True
                except Exception as e:
                    journal['books_restored'] = False
                    journal['books_restore_error'] = str(e)
                    save_json(run / 'journal.json', journal)
                    raise
                await clean_outstanding(afc)
                save_json(run / 'journal.json', journal)
    # Remote originals and staging identifiers are intentionally retained for recovery.
    return snapshot

async def connect(udid):
    from pymobiledevice3.lockdown import create_using_usbmux
    return await asyncio.wait_for(create_using_usbmux(serial=udid, autopair=False, connection_type='USB'), 15)

async def device_info(device):
    result = {k: await device.get_value(key=k) for k in
              ('ProductType', 'HardwareModel', 'ProductVersion', 'BuildVersion', 'ActivationState')}
    rows = await device.get_value(key='CarrierBundleInfoArray') or []
    result['carriers'] = [{k: r[k] for k in ('MCC', 'MNC', 'Slot', 'CFBundleIdentifier', 'CFBundleVersion') if k in r}
                          for r in rows]
    return result

def check_trigger(path, sims):
    require(path.suffix == '.ipcc', 'Trigger must be an IPCC')
    tree = read_tree_zip(path)
    bundles = {n.split('/')[1] for n in tree if n.startswith('Payload/') and len(n.split('/')) > 1
               and n.split('/')[1].endswith('.bundle')}
    require(len(bundles) == 1, 'Trigger must contain exactly one bundle')
    name = bundles.pop()
    inner = {n.removeprefix('Payload/'): v for n, v in tree.items() if n.startswith('Payload/')}
    info, carrier = bundle_info(inner, name)
    require(name != BUNDLE and info.get('CFBundleIdentifier') != 'com.apple.Viva_kw', 'Viva is not an independent trigger')
    identifiers = carrier.get('SupportedSIMs', [])
    require(identifiers and all(isinstance(s, str) and re.fullmatch(r'\d{5,6}(?:_.*)?', s) for s in identifiers),
            'Unknown SupportedSIMs format in trigger')
    affected = set(identifiers)
    for n, (k, data) in tree.items():
        if k == 'l':
            leaf = n.split('/')[-1]
            require(re.fullmatch(r'\d{5,6}(?:_.*)?', leaf), 'Unexpected trigger symlink')
            affected.add(leaf)
    require(not any(a == s or a.startswith(s + '_') for a in affected for s in sims),
            'Trigger overlaps an installed SIM; select a different carrier')
    return {'bundle': name, 'version': info.get('CFBundleVersion'), 'sha256': digest(path.read_bytes())}

async def install_trigger(device, path, run):
    from pymobiledevice3.services.installation_proxy import InstallationProxyService
    from pymobiledevice3.services.syslog import SyslogService
    from pymobiledevice3.exceptions import ConnectionTerminatedError
    # Override upstream extraction to preserve raw bytes without creating local symlinks.
    class Installer(InstallationProxyService):
        async def _upload_ipcc(self, file_stream, afc_client, dst):
            with zipfile.ZipFile(file_stream) as z:
                for entry in z.infolist():
                    target = dst + '/' + entry.filename
                    await afc_client.makedirs(target if entry.is_dir() else target.rsplit('/', 1)[0])
                    if not entry.is_dir():
                        await afc_client.set_file_contents(target, z.read(entry))
    ready = asyncio.Event()
    status = {'ipcc_installation_completed': False, 'log_error': None, 'nr_data_verified': False}
    async def watch():
        try:
            async with SyslogService(device) as log:
                ready.set()
                size = 0
                with (run / 'commcenter.log').open('w', encoding='utf-8') as f:
                    async for row in log.watch():
                        line = row.decode(errors='replace') if isinstance(row, bytes) else row
                        if 'CommCenter' in line:
                            size += len(line)
                            require(size < 16 * 1024 * 1024, 'Log limit reached')
                            f.write(line + '\n')
                            f.flush()
        except asyncio.CancelledError:
            raise
        except Exception as error:
            status['log_error'] = type(error).__name__ + ': ' + str(error)
            ready.set()
    watcher = asyncio.create_task(watch())
    try:
        await asyncio.wait_for(ready.wait(), 10)
        async with Installer(device) as installer:
            await asyncio.wait_for(installer.install_from_local(path), 90)
        status['ipcc_installation_completed'] = True
        save_json(run / 'installation.json', status)
        await asyncio.sleep(8)
    except BaseException as error:
        status['installation_error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        watcher.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await watcher
        save_json(run / 'installation.json', status)
    return status

# AirTraffic protocol follows the MIT-licensed AirLift host sequence.
# Native Apple calls run in a disposable subprocess: a blocked DLL cannot hang recovery.
import ctypes as C
import subprocess
import uuid
from datetime import datetime

APPLE_DIRS = []
ASSET_SHA256 = '6de1ea0be81a29c145ef414f24bc21d1dcb8a4eb737b22b1f956e9a6f0c2098b'

class AppleHost:
    def __init__(self, directories=()):
        self.handles = []
        self.pool = None
        if sys.platform == 'darwin':
            self.cf = C.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
            self.at = C.CDLL('/System/Library/PrivateFrameworks/AirTrafficHost.framework/AirTrafficHost')
            self.objc = C.CDLL('/usr/lib/libobjc.A.dylib')
            self.objc.objc_autoreleasePoolPush.restype = C.c_void_p
            self.objc.objc_autoreleasePoolPush.argtypes = []
            self.objc.objc_autoreleasePoolPop.argtypes = [C.c_void_p]
            self.objc.objc_autoreleasePoolPop.restype = None
            self.pool = self.objc.objc_autoreleasePoolPush()
        elif sys.platform == 'win32':
            require(C.sizeof(C.c_void_p) == 8, 'Нужен 64-битный Python и 64-битные компоненты Apple.')
            def add_dir(path):
                try: self.handles.append(os.add_dll_directory(str(path)))
                except OSError: pass
            paths = [Path(p).resolve() for p in directories]
            for key in ('CommonProgramW6432', 'CommonProgramFiles'):
                base = os.environ.get(key)
                if base:
                    apple = Path(base)/'Apple'
                    paths += [apple/'Mobile Device Support', apple/'Apple Application Support', apple]
            for key in ('ProgramW6432', 'ProgramFiles'):
                base = os.environ.get(key)
                if base:
                    b = Path(base)
                    paths += [b/'iTunes', b/'Common Files'/'Apple', b/'Apple', b/'Apple Devices']
            # Папки x86 сознательно пропускаем: 32-битные DLL нельзя загрузить в 64-битный процесс.
            paths = list(dict.fromkeys(p for p in paths if p.is_dir()))
            for p in paths: add_dir(p)
            def find_on_disk(name):
                # Целевой авто-поиск: папки с apple/itunes в имени в стандартных
                # программных каталогах, три уровня вглубь. Без обхода всего диска.
                bases = []
                for key in ('ProgramW6432', 'ProgramFiles', 'ProgramData', 'LOCALAPPDATA', 'APPDATA'):
                    base = os.environ.get(key)
                    if base: bases.append(Path(base))
                bases += [Path('C:/Program Files'), Path('C:/Program Files (x86)')]
                seen = set(); hits = []
                for base in bases:
                    if not base.is_dir(): continue
                    try: children = list(base.iterdir())
                    except OSError: continue
                    for child in children:
                        low = child.name.lower()
                        if (not child.is_dir() or ('apple' not in low and 'itunes' not in low)
                                or str(child) in seen):
                            continue
                        seen.add(str(child))
                        level = [child]
                        for _ in range(3):
                            nxt = []
                            for d in level:
                                try: entries = list(d.iterdir())
                                except OSError: continue
                                for e in entries:
                                    if not e.is_dir() or str(e) in seen: continue
                                    seen.add(str(e))
                                    if (e/name).is_file(): hits.append(e)
                                    nxt.append(e)
                            level = nxt
                return hits
            def load(name):
                candidates = [p/name for p in paths if (p/name).is_file()]
                if not candidates and not directories:
                    print('В стандартных папках Apple нет ' + name + '; ищу в программных каталогах…', flush=True)
                    for hit in find_on_disk(name):
                        paths.append(hit); add_dir(hit)
                    candidates = [p/name for p in paths if (p/name).is_file()]
                if candidates:
                    for p in {str(c.parent) for c in candidates}: add_dir(Path(p))
                require(candidates, 'Не найдена ' + name + '. Искал в: '
                        + ('; '.join(str(p) for p in paths[:10]) + (' …' if len(paths) > 10 else ''))
                        + '. Установите iTunes x64 с сайта apple.com (не из Microsoft Store) и повторите, '
                        'либо укажите папку с DLL: --apple-dir "C:\\путь\\к\\папке". '
                        'Найти DLL на своём ПК: where /r "C:\\Program Files" ' + name)
                return C.CDLL(str(candidates[0]), winmode=0x1100)
            self.cf = load('CoreFoundation.dll')
            self.at = load('AirTrafficHost.dll')
        else:
            raise RuntimeError('Поддерживаются macOS и Windows.')
        P, I, U = C.c_void_p, C.c_ssize_t, C.c_size_t
        def bind(lib, name, result, args):
            f = getattr(lib, name); f.restype = result; f.argtypes = args
        for name, result, args in [
            ('CFDataCreate', P, [P,P,I]), ('CFDataGetLength', I, [P]),
            ('CFDataGetBytePtr', P, [P]), ('CFRelease', None, [P]),
            ('CFPropertyListCreateWithData', P, [P,P,U,P,P]),
            ('CFPropertyListCreateData', P, [P,P,I,U,P])]:
            bind(self.cf, name, result, args)
        for name, result, args in [
            ('ATHostConnectionCreate', P, [P]), ('ATHostConnectionRelease', None, [P]),
            ('ATHostConnectionReadMessage', P, [P]),
            ('ATHostConnectionSendHostInfo', None, [P,P]),
            ('ATHostConnectionSendSyncRequest', None, [P,P,P,P]),
            ('ATHostConnectionSendMetadataSyncFinished', None, [P,P,P]),
            ('ATHostConnectionSendAssetCompleted', None, [P,P,P,P]),
            ('ATCFMessageGetName', P, [P]), ('ATCFMessageGetParam', P, [P,P])]:
            bind(self.at, name, result, args)

    def encode(self, value):
        raw = plistlib.dumps(value, fmt=plistlib.FMT_BINARY)
        buf = C.create_string_buffer(raw)
        data = self.cf.CFDataCreate(None, buf, len(raw))
        require(data, 'CFDataCreate failed')
        try:
            result = self.cf.CFPropertyListCreateWithData(None, data, 0, None, None)
            require(result, 'CFPropertyListCreateWithData failed')
            return result
        finally:
            self.cf.CFRelease(data)

    def decode(self, value):
        require(value, 'Пустое сообщение Apple')
        data = self.cf.CFPropertyListCreateData(None, value, 200, 0, None)
        require(data, 'CFPropertyListCreateData failed')
        try:
            size = self.cf.CFDataGetLength(data)
            require(0 <= size <= MAX_BYTES, 'Слишком большое сообщение Apple')
            return plistlib.loads(C.string_at(self.cf.CFDataGetBytePtr(data), size))
        finally:
            self.cf.CFRelease(data)

    def call(self, name, connection, *values):
        refs = []
        try:
            for v in values: refs.append(self.encode(v))
            return getattr(self.at, name)(connection, *refs)
        finally:
            for ref in refs: self.cf.CFRelease(ref)

    def close(self):
        if self.pool:
            self.objc.objc_autoreleasePoolPop(self.pool); self.pool = None


def framed(value):
    print('CARRIER_SWAP_JSON:' + json.dumps(value), flush=True)


def native_host(udid, assets, directories):
    host = AppleHost(directories)
    connection = None
    try:
        sample = {'test': ['Book', 1, False]}
        ref = host.encode(sample)
        try: require(host.decode(ref) == sample, 'Ошибка обмена с CoreFoundation')
        finally: host.cf.CFRelease(ref)
        if udid is None:
            framed({'ok': True, 'deviceConnections': 0}); return
        ref = host.encode(udid)
        try: connection = host.at.ATHostConnectionCreate(ref)
        finally: host.cf.CFRelease(ref)
        require(connection, 'Не удалось открыть AirTraffic. Закройте синхронизацию iTunes/Finder.')
        def until(wanted, limit):
            for _ in range(limit):
                msg = host.at.ATHostConnectionReadMessage(connection)
                if not msg: continue
                try:
                    name = host.decode(host.at.ATCFMessageGetName(msg))
                    if name == wanted:
                        if name != 'AssetManifest': return True
                        key = host.encode('AssetManifest')
                        try: return host.decode(host.at.ATCFMessageGetParam(msg, key))
                        finally: host.cf.CFRelease(key)
                    require(name not in ('SyncFailed','SyncFinished'), 'Синхронизация закончилась преждевременно')
                finally: host.cf.CFRelease(msg)
            raise RuntimeError('Не получено сообщение ' + wanted)
        until('SyncAllowed', 8)
        info = {'Type':'iTunes', 'Version':'13.7.0.161', 'SyncHostName':'CarrierSIM',
                'LibraryID':str(uuid.uuid4()), 'SyncedDataclasses':['Book'],
                'SyncedAssetTypes':['Book'], 'Wakeable':False}
        if sys.platform == 'darwin':
            import platform
            info['MacOSVersion'] = platform.mac_ver()[0]
        host.call('ATHostConnectionSendHostInfo', connection, info)
        time.sleep(.2)
        host.call('ATHostConnectionSendSyncRequest', connection, ['Book'], {}, info)
        until('ReadyForSync', 12)
        host.call('ATHostConnectionSendMetadataSyncFinished', connection, {'Book':1}, {})
        # Accept only assets explicitly requested for download by iOS.
        # Capture aggregate diagnostics without exposing SIM/device identifiers.
        manifest = until('AssetManifest', 20)
        require(isinstance(manifest, dict), 'Неверный манифест AirTraffic')
        wanted = {asset_id for asset_id, _ in assets}
        records = [r for r in manifest.get('Book', []) if isinstance(r, dict)]
        downloadable = {r.get('AssetID') for r in records if r.get('IsDownload')}
        all_ids = {r.get('AssetID') for r in records}
        framed({'event': 'manifest-diagnostic', 'requested_count': len(wanted),
                'book_record_count': len(records), 'matched_count': len(wanted & downloadable),
                'downloadable_count': len(downloadable), 'id_count': len(wanted & all_ids),
                'missing_count': len(wanted - downloadable),
                'missing': sorted(x for x in (wanted - downloadable) if isinstance(x, str))})
        require(wanted <= downloadable,
                'AirTraffic не подтвердил нужные объекты (подтверждено {0} из {1})'.format(
                    len(wanted & downloadable), len(wanted)))
        for i,(identifier,destination) in enumerate(assets):
            if i == 2:
                framed({'event':'before-final-asset'})
                require(sys.stdin.readline().strip() == 'CONTINUE', 'Резервная копия не подтверждена')
            host.call('ATHostConnectionSendAssetCompleted', connection, identifier, 'Book', destination)
            if i+1 < len(assets): time.sleep(.9)
        time.sleep(2)
        framed({'ok':True})
    finally:
        if connection: host.at.ATHostConnectionRelease(connection)
        host.close()


def host_command():
    return [sys.executable, str(Path(__file__).resolve()), '--_host']


async def host_session(udid, assets, callback, run):
    config = run/'host-input.json'
    save_json(config, {'udid':udid, 'assets':assets, 'directories':APPLE_DIRS})
    proc = await asyncio.create_subprocess_exec(*host_command(), str(config),
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    async def stderr():
        with (run/'host.stderr').open('wb') as f:
            while data := await proc.stderr.read(4096): f.write(data)
    task = asyncio.create_task(stderr())
    paused = False; result = None
    try:
        with (run/'host.jsonl').open('wb') as log:
            async with asyncio.timeout(170):
                while line := await proc.stdout.readline():
                    log.write(line); log.flush()
                    if not line.startswith(b'CARRIER_SWAP_JSON:'): continue
                    row = json.loads(line[len(b'CARRIER_SWAP_JSON:'):])
                    if row.get('event') == 'before-final-asset':
                        require(not paused, 'Повторная пауза AirTraffic')
                        await callback(); paused = True
                        proc.stdin.write(b'CONTINUE\n'); await proc.stdin.drain()
                    else: result = row
                code = await proc.wait()
        detail = result.get('error') if isinstance(result, dict) else None
        require(code == 0 and paused and result and result.get('ok'),
                'Сбой AirTraffic; сохраните каталог операции для --recover' +
                ((': ' + detail) if detail else ''))
    finally:
        if proc.returncode is None:
            proc.kill(); await proc.wait()
        await task
        config.unlink(missing_ok=True)

TARGET_BUNDLES = ('Vodafone_hu.bundle',)
SYSTEM_PREFIX = '../../../../../../System/Library/Carrier Bundles/iPhone/'
MODELS = {'iPhone14,7': {'name': 'iPhone 14', 'boards': ['D27AP']}, 'iPhone14,8': {'name': 'iPhone 14 Plus', 'boards': ['D28AP']}, 'iPhone15,2': {'name': 'iPhone 14 Pro', 'boards': ['D73AP']}, 'iPhone15,3': {'name': 'iPhone 14 Pro Max', 'boards': ['D74AP']}, 'iPhone15,4': {'name': 'iPhone 15', 'boards': ['D37AP']}, 'iPhone15,5': {'name': 'iPhone 15 Plus', 'boards': ['D38AP']}, 'iPhone16,1': {'name': 'iPhone 15 Pro', 'boards': ['D83AP']}, 'iPhone16,2': {'name': 'iPhone 15 Pro Max', 'boards': ['D84AP']}, 'iPhone17,4': {'name': 'iPhone 16 Plus', 'boards': ['D48AP']}, 'iPhone17,2': {'name': 'iPhone 16 Pro Max', 'boards': ['D94AP']}, 'iPhone17,3': {'name': 'iPhone 16', 'boards': ['D47AP']}, 'iPhone17,1': {'name': 'iPhone 16 Pro', 'boards': ['D93AP']}, 'iPhone17,5': {'name': 'iPhone 16e', 'boards': ['V59AP']}, 'iPhone18,1': {'name': 'iPhone 17 Pro', 'boards': ['V53AP']}, 'iPhone18,2': {'name': 'iPhone 17 Pro Max', 'boards': ['V54AP']}, 'iPhone18,4': {'name': 'iPhone Air', 'boards': ['D23AP']}, 'iPhone18,3': {'name': 'iPhone 17', 'boards': ['V57AP']}, 'iPhone18,5': {'name': 'iPhone 17e', 'boards': ['V159AP']}, 'iPhone19,7': {'name': 'iPhone 18 Pro Max', 'boards': ['V64SAP']}, 'iPhone19,3': {'name': 'iPhone 18 Pro Max (U.S.)', 'boards': ['V64AP']}, 'iPhone19,2': {'name': 'iPhone 18 Pro', 'boards': ['V63AP']}}


def load_assets():
    path = ROOT/'assets.zip'
    require(digest(path.read_bytes()) == ASSET_SHA256, 'Архив assets.zip повреждён или заменён.')
    tree = read_tree_zip(path)
    targets = {name: ('l', (SYSTEM_PREFIX+name).encode()) for name in TARGET_BUNDLES}
    return targets, tree


def select_sims(rows):
    selected = []; seen_slots = set(); seen_imsi = set()
    for row in rows:
        mcc, mnc = str(row.get('MCC','')), str(row.get('MNC',''))
        slot, imsi = row.get('Slot'), row.get('InternationalMobileSubscriberIdentity')
        require(slot in ('kOne','kTwo') and slot not in seen_slots, 'Неоднозначные слоты SIM; запись отменена.')
        require(re.fullmatch(r'\d{3}',mcc) and re.fullmatch(r'\d{2,3}',mnc) and isinstance(imsi,str) and
                re.fullmatch(r'\d{15}',imsi) and imsi.startswith(mcc+mnc),
                'iPhone не сообщил полный IMSI для SIM '+mcc+mnc+'. Включите линию и разблокируйте телефон.')
        require(imsi not in seen_imsi, 'Один IMSI указан в двух слотах; запись отменена.')
        seen_slots.add(slot); seen_imsi.add(imsi)
        selected.append({'slot':slot,'plmn':mcc+mnc,'imsi':imsi,'bundle':BUNDLE})
    require(selected, 'Телефон не сообщил ни одной SIM с доступным IMSI.')
    return selected


def make_plan(original, sims, targets):
    desired = dict(original)
    # Signed system bundles match the phone's own firmware; only exact IMSI aliases change.
    for sim in sims:
        n = sim['imsi']
        require(n not in original or original[n][0]=='l', 'Вместо ссылки IMSI обнаружен файл или каталог.')
        desired[n] = targets[sim['bundle']]
    validate_tree(desired)
    return desired


def remove_imsi_links(original):
    # This installer creates root-level, 15-digit IMSI aliases, never directories.
    result = {n:v for n,v in original.items()
              if not (v[0]=='l' and re.fullmatch(r'\d{15}',n))}
    validate_tree(result)
    return result


def check_phone(info):
    model = MODELS.get(info['ProductType'])
    if (not model or str(info['HardwareModel']).upper() not in model['boards']
            or info['ProductVersion'] != '27.0'
            or info['BuildVersion'] not in ('24A435', '24A437')):
        print('Предупреждение: модель, плата или версия iOS не проверена. '
              'Скрипт МОЖЕТ не работать. Продолжаю без ограничения совместимости.', flush=True)
    require(info['ActivationState']=='Activated','iPhone не активирован.')


async def choose_device(udid, wait_seconds=180):
    from pymobiledevice3.usbmux import list_devices
    from pymobiledevice3.exceptions import ConnectionFailedToUsbmuxdError, NoDeviceConnectedError
    deadline=time.monotonic()+wait_seconds
    announced=False
    while True:
        try:
            devices=[d.serial for d in await list_devices() if d.connection_type=='USB']
        except (OSError, ConnectionError, ConnectionFailedToUsbmuxdError, NoDeviceConnectedError):devices=[]
        if udid and udid in devices:return udid
        if not udid and len(devices)==1:return devices[0]
        require(udid or len(devices)<2,'Подключено несколько iPhone. Укажите --udid.')
        if not announced:
            print('Ожидаю подключения iPhone по USB. Подключите и разблокируйте телефон…',flush=True)
            announced=True
        require(time.monotonic()<deadline,'Время ожидания подключения истекло. Проверьте кабель и повторите.')
        await asyncio.sleep(min(2,max(0,deadline-time.monotonic())))


async def ready_device(udid, wait_seconds):
    from pymobiledevice3 import exceptions as errors
    deadline=time.monotonic()+wait_seconds
    last=None
    while True:
        await choose_device(udid,max(0,deadline-time.monotonic()))
        try:return await connect(udid)
        except (OSError, errors.ConnectionTerminatedError, errors.PasswordRequiredError,
                errors.NotPairedError, errors.PairingDialogResponsePendingError,
                errors.ConnectionFailedError, errors.InvalidConnectionError) as error:
            if last is None:print('Ожидаю разблокировки, доверия и готовности USB-соединения…',flush=True)
            last=error
            if time.monotonic()>=deadline:raise RuntimeError('iPhone не готов: разблокируйте и подтвердите доверие.') from error
            await asyncio.sleep(2)


def transient_error(error):
    from pymobiledevice3 import exceptions as errors
    if isinstance(error,(ConnectionError,TimeoutError,errors.ConnectionTerminatedError,
                         errors.ConnectionFailedError,errors.InvalidConnectionError)):
        return True
    if isinstance(error,OSError) and error.errno in (32,54,60,104,110):return True
    return isinstance(error,RuntimeError) and any(t in str(error) for t in
        ('Сбой AirTraffic','Final source not consumed'))


async def execute_with_retry(args,bundles,assets):
    # Once selected, reconnect only to this exact phone, even if a different phone appears.
    args.udid=await choose_device(args.udid,args.wait_seconds)
    for attempt in range(1,args.attempts+1):
        print(f'Попытка {attempt} из {args.attempts}',flush=True)
        try:return await execute(args,bundles,assets)
        except Exception as error:
            if not transient_error(error):raise
            failed=pending(args.runs,args.udid)
            if failed:
                print('Связь прервалась. Сначала восстанавливаю незавершённые этапы…',flush=True)
                device=await ready_device(args.udid,args.wait_seconds)
                recovery=args.runs/(datetime.now().strftime('%Y%m%d-%H%M%S-')+'auto-recovery-'+uuid.uuid4().hex[:6])
                recovery.mkdir(mode=0o700)
                try:
                    for i,stage in enumerate(failed):
                        await recover_stage(device,stage,recovery if i==0 else recovery/f'batch-{i}')
                except BaseException:
                    print('Автовосстановление не завершено. Новая запись отменена. Журнал:',recovery,flush=True)
                    raise
                finally:await device.close()
            if attempt==args.attempts:raise
            print('Временный сбой соединения. Повторю после восстановления связи…',flush=True)
            await asyncio.sleep(2)


def report_log(path, sims):
    results = {s['slot']:{'slot':s['slot'],'plmn':s['plmn'],'expected':s['bundle'],
                         'selected':None,'verified':False} for s in sims}
    if path.exists():
        for block in path.read_text(encoding='utf-8',errors='replace').split('----------Bundle File----------'):
            resolved = re.findall(r'Resolved path\s*:\s*([^\r\n]+)',block)
            linked = re.findall(r'Linking Path\s*:\s*([^\r\n]+)',block)
            verified = re.findall(r'Verification Result\s*:\s*([^\r\n]+)',block)
            if len(resolved)!=1 or len(linked)!=1: continue
            for slot,index in (('kOne',1),('kTwo',2)):
                if slot in results and linked[0].strip().endswith(f'/Carrier{index}Bundle.bundle'):
                    results[slot].update(selected=resolved[0].strip().rsplit('/',1)[-1],
                                         verified=verified==['Success'])
    return list(results.values())


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8'))


def pending(runs, udid):
    return [p.parent for p in runs.glob('*/*/journal.json')
            if (j:=read_json(p)).get('udid_hash')==digest(udid.encode())
            and (j.get('requires_recovery') or j.get('books_restored') is False) and not j.get('recovered_by')]


@contextlib.contextmanager
def operation_lock(runs):
    runs.mkdir(parents=True,exist_ok=True)
    with (runs/'.lock').open('a+b') as f:
        f.seek(0); f.write(b'0'); f.flush(); f.seek(0)
        if sys.platform=='win32':
            import msvcrt
            msvcrt.locking(f.fileno(),msvcrt.LK_NBLCK,1)
        else:
            import fcntl
            fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
        try: yield
        finally:
            if sys.platform=='win32':
                f.seek(0); msvcrt.locking(f.fileno(),msvcrt.LK_UNLCK,1)


def bound(record,device):
    require(record.get('target')==TARGET and record.get('udid_hash')==digest(device.udid.encode()),
            'Копия относится к другому телефону или каталогу.')


async def recover_stage(device, failed, run):
    from pymobiledevice3.services.afc import AfcService
    record = read_json(failed/'journal.json'); bound(record,device)
    remote = record.get('exported','')
    require(re.fullmatch(r'airlift-saved-[a-f0-9]{20}',remote),'Неверный путь восстановления.')
    books = read_tree_zip(failed/'books.zip'); state=read_json(failed/'books.json')
    require(tree_hash(books)==state['hash'],'Копия Books повреждена.')
    desired = None
    async with AfcService(device) as afc:
        if await exists(afc,remote):
            desired = await remote_tree(afc,remote)
            if record.get('original_hash'):
                require(tree_hash(desired)==record['original_hash'],'Удалённая копия изменилась.')
        elif (failed/'original.zip').exists():
            desired = read_tree_zip(failed/'original.zip')
            require(tree_hash(desired)==record.get('original_hash'),'Локальная копия повреждена.')
        else:
            require(record.get('phase') in ('created','staging','host-started','export-check'),
                    'Нет проверенной копии. Сохраните runs; восстановление остановлено.')
        await restore_books(afc,books,state['existed'])
    if desired is not None:
        write_tree_zip(run/'recovery-original.zip',desired)
        await transfer(device,run/'recover',payload=desired,recovery=True)
        observed=await transfer(device,run/'readback')
        require(observed==desired,'Восстановленный каталог не совпадает с копией.')
    else:
        # Before the controller saved a backup, final placement was never authorised.
        # Export and return the still-live catalog; do not guess a replacement.
        await transfer(device,run/'recover-live')
    record['recovered_by']=str(run);record['requires_recovery']=False
    save_json(failed/'journal.json',record)


def check_trigger_hardware(path, hardware):
    tree = read_tree_zip(path)
    board = hardware.upper().removesuffix('AP')
    for name,(kind,data) in tree.items():
        leaf = name.rsplit('/',1)[-1]
        if kind!='f' or '/signatures/' in name or not leaf.startswith('overrides_') or not leaf.endswith('.plist'):
            continue
        boards = leaf.removeprefix('overrides_').removesuffix('.plist').upper().split('_')
        if board in boards:
            signature = name.rsplit('/',1)[0]+'/signatures/'+leaf
            if signature in tree:
                return True
            break
    print('Предупреждение: в IPCC нет настроек с подписью для платы '+hardware+
          '. Пересканирование МОЖЕТ не работать; продолжаю.', flush=True)
    return False



async def execute(args,bundles,assets):
    udid=args.udid
    device=await ready_device(udid,args.wait_seconds)
    run=None
    try:
        info=await device_info(device); check_phone(info)
        rows=await device.get_value(key='CarrierBundleInfoArray') or []
        sims=select_sims(rows) if not (args.restore or args.restore_backup or args.recover) else []
        if args.restore:
            sims=[{'slot':r['Slot'],'plmn':str(r.get('MCC',''))+str(r.get('MNC','')),'bundle':None}
                  for r in rows if r.get('Slot') in ('kOne','kTwo')]
        print(f"\n  {MODELS.get(info['ProductType'], {}).get('name', info['ProductType'])} · iOS {info['ProductVersion']} ({info['BuildVersion']})",flush=True)
        for s in sims:
            label = {'kOne':'SIM 1', 'kTwo':'SIM 2'}[s['slot']]
            target='штатный профиль' if args.restore else 'Vodafone HU (по IMSI)'
            print(f"  {label}  ·  {s['plmn']}  →  {target}",flush=True)
        print(flush=True)
        if args.status: return
        if args.trigger:
            check_trigger(args.trigger,{str(r.get('MCC',''))+str(r.get('MNC','')) for r in rows})
            check_trigger_hardware(args.trigger,info['HardwareModel'])
        unresolved=pending(args.runs,udid)
        recover_all=args.recover==Path('AUTO')
        if recover_all and not unresolved:
            print('Незавершённых операций для этого iPhone нет.');return 0
        if unresolved:
            if recover_all:
                args.recover=unresolved[0]
            else:
                require(args.recover is not None,
                        'Сначала выполните --recover для этапа: '+str(unresolved[0]))
                require(args.recover.resolve() in {p.resolve() for p in unresolved},
                        'Сначала выполните --recover для этапа: '+str(unresolved[0]))
        run=args.runs/(datetime.now().strftime('%Y%m%d-%H%M%S-')+uuid.uuid4().hex[:6])
        run.mkdir(mode=0o700)
        print('Копии и журнал:',run,flush=True)
        print('Идёт установка или восстановление, ожидайте… Не отключайте iPhone.',flush=True)
        save_json(run/'device.json',{**info,'udid_hash':digest(udid.encode())})
        trigger=None
        plmns={str(r.get('MCC',''))+str(r.get('MNC','')) for r in rows}
        for name in (() if args.trigger else ('AVEA_tr.ipcc','Swisscom_ch.ipcc','O2_Germany.ipcc')):
            candidate=run/name;candidate.write_bytes(assets['triggers/'+name][1])
            try:
                check_trigger(candidate,plmns)
                check_trigger_hardware(candidate,info['HardwareModel'])
                trigger=candidate;break
            except RuntimeError:candidate.unlink()
        if args.trigger:
            trigger=run/'custom-trigger.ipcc';trigger.write_bytes(args.trigger.read_bytes())
            check_trigger(trigger,plmns);check_trigger_hardware(trigger,info['HardwareModel'])
        require(trigger is not None,'Не найден независимый триггер для этих SIM.')
        if args.recover:
            # AUTO recovers every pending stage, not just the first one.
            stages=[p.resolve() for p in unresolved] if recover_all else [args.recover.resolve()]
            for i,stage in enumerate(stages):
                await recover_stage(device,stage,run if i==0 else run/f'batch-{i}')
        elif args.restore:
            print('[1/4] Подготавливаю пересканирование…',flush=True)
            init=run/'initialize';init.mkdir();await install_trigger(device,trigger,init)
            print('[2/4] Сохраняю текущие настройки…',flush=True)
            original=await transfer(device,run/'snapshot')
            desired=remove_imsi_links(original)
            removed=len(original)-len(desired)
            save_json(run/'plan.json',{'action':'remove-imsi','removed':removed,'before':tree_hash(original),'after':tree_hash(desired)})
            print(f'[3/4] Удаляю ссылки по IMSI: {removed}. Проверяю результат…',flush=True)
            await transfer(device,run/'restore',payload=desired,expected=original)
            require(await transfer(device,run/'readback')==desired,'Обратное чтение не совпало.')
        elif args.restore_backup:
            failed=args.restore_backup.resolve()/'snapshot'
            record=read_json(failed/'journal.json');bound(record,device)
            desired=read_tree_zip(failed/'original.zip')
            require(tree_hash(desired)==record.get('original_hash'),'Копия повреждена.')
            await transfer(device,run/'restore',payload=desired,recovery=True)
            require(await transfer(device,run/'readback')==desired,'Обратное чтение не совпало.')
        else:
            # A non-overlapping trigger also creates the user catalog on a clean phone.
            init=run/'initialize';init.mkdir()
            print('[1/4] Подготавливаю пересканирование…',flush=True)
            await install_trigger(device,trigger,init)
            print('[2/4] Сохраняю исходные настройки…',flush=True)
            original=await transfer(device,run/'snapshot')
            require(original is not None,'Не удалось сохранить исходный каталог.')
            current=select_sims(await device.get_value(key='CarrierBundleInfoArray') or [])
            require(current==sims,'SIM изменились во время операции; запись отменена.')
            desired=make_plan(original,sims,bundles)
            save_json(run/'plan.json',{'slots':[{k:v for k,v in s.items() if k!='imsi'} for s in sims],
                                      'before':tree_hash(original),'after':tree_hash(desired)})
            print('[3/4] Записываю ссылки по IMSI и проверяю результат…',flush=True)
            await transfer(device,run/'apply',payload=desired,expected=original)
            # AirTraffic readback right after a successful apply is flaky on
            # iOS 27; retry it, and if the transport still fails, let the
            # authoritative CommCenter rescan below decide the outcome.
            observed=None;readback_failed=False
            for attempt in range(3):
                stage=run/'readback' if attempt==0 else run/f'readback-{attempt+1}'
                try:
                    observed=await transfer(device,stage);break
                except RuntimeError as error:
                    if not transient_error(error) or attempt==2:
                        readback_failed=transient_error(error)
                        if readback_failed:
                            print('Предупреждение: контрольное чтение не прошло из-за AirTraffic; '
                                  'проверяю выбор профиля по журналу CommCenter.',flush=True)
                        else: raise
                    else:
                        print(f'Повторяю контрольное чтение ({attempt+2}/3)…',flush=True)
                        await asyncio.sleep(5)
            if observed is not None:
                require(observed==desired,'Обратное чтение не совпало.')
        print('[4/4] Ожидаю применения профиля и проверки подписей…',flush=True)
        rescan=run/'rescan';rescan.mkdir()
        installation=await install_trigger(device,trigger,rescan)
        result=report_log(rescan/'commcenter.log',sims)
        save_json(run/'result.json',{'catalog_verified':True,'installation':installation,'slots':result})
        unconfirmed=False
        for s in result:
            ok=s['verified'] and (args.restore or s['selected']==s['expected']);unconfirmed |= not ok
            print(f"{dict(kOne='SIM 1', kTwo='SIM 2')[s['slot']]} ({s['plmn']}): "+(s['selected']+' — подпись принята' if ok else
                  'выбор нужного пакета не подтверждён; см. журнал'),flush=True)
        if args.restore:print('Все ссылки по IMSI удалены. Обычные ссылки операторов сохранены.',flush=True)
        if unconfirmed:return 2
        print('Готово. Включите авиарежим на 15 секунд и проверьте связь. Работа 5G не проверялась.')
        return 0
    except BaseException as error:
        if run:
            save_json(run/'error.json',{'error':type(error).__name__+': '+str(error)})
            print('Операция остановлена. Журнал:',run,file=sys.stderr)
            for p in pending(args.runs,udid):print('Для восстановления: --recover "'+str(p)+'"',file=sys.stderr)
        raise
    finally:await device.close()


def main():
    if len(sys.argv)>1 and sys.argv[1]=='--_host':
        try:
            value=json.loads(sys.stdin.readline()) if sys.argv[2]=='check' else read_json(Path(sys.argv[2]))
            native_host(value.get('udid'),value.get('assets',[]),value.get('directories',[]))
            return 0
        except Exception as e:framed({'ok':False,'error':str(e)});return 1
    print('Исследование, разработка и тесты — Vladimir B / vlw (vlwwwwww@gmail.com).',flush=True)
    parser=argparse.ArgumentParser(description='Vodafone_hu для всех SIM независимо от страны. '
        'Без флагов: установить по IMSI на SIM, сообщённые iPhone. Без ограничений по модели iPhone и версии iOS; совместимость не гарантируется.',
        add_help=False)
    parser.add_argument('-h','--help',action='help',help='показать эту справку')
    group=parser.add_mutually_exclusive_group()
    group.add_argument('--check',action='store_true',help='проверить файлы и библиотеки Apple, без подключения к телефону')
    group.add_argument('--status',action='store_true',help='показать найденные SIM и план, ничего не записывать')
    group.add_argument('--restore',action='store_true',help='удалить все ссылки по IMSI и включить штатный выбор профилей; путь не нужен')
    group.add_argument('--restore-backup',type=Path,metavar='КАТАЛОГ',help='дополнительно: вернуть каталог из конкретной резервной копии')
    group.add_argument('--recover',type=Path,nargs='?',const=Path('AUTO'),metavar='ЭТАП',help='восстановиться после сбоя автоматически; путь к этапу необязателен')
    parser.add_argument('--trigger',type=Path,metavar='IPCC',help='свой подписанный IPCC вместо комплектного; плата и SIM проверяются')
    parser.add_argument('--attempts',type=int,default=3,metavar='N',help='попытки при временном сбое связи (по умолчанию 3)')
    parser.add_argument('--wait-seconds',type=int,default=180,metavar='СЕК',help='ожидать подключение и разблокировку (по умолчанию 180 секунд)')
    parser.add_argument('--udid',metavar='ID',help='выбрать iPhone, если по USB подключено несколько')
    parser.add_argument('--apple-dir',action='append',default=[],metavar='ПАПКА',help='Windows: папка DLL Apple; можно указать несколько раз')
    parser.add_argument('--runs',type=Path,default=ROOT/'runs',metavar='ПАПКА',help='куда сохранять копии и журналы (по умолчанию runs рядом со скриптом)')
    parser._optionals.title='Параметры'
    args=parser.parse_args()
    require(1 <= args.attempts <= 10, 'Число попыток должно быть от 1 до 10.')
    require(0 <= args.wait_seconds <= 3600, 'Ожидание должно быть от 0 до 3600 секунд.')
    os.umask(0o077)
    require(sys.version_info >= (3,11), 'Нужен Python 3.11 или новее.')
    from importlib.metadata import version, PackageNotFoundError
    try: installed=version('pymobiledevice3')
    except PackageNotFoundError: raise RuntimeError('Установите зависимости: python -m pip install -r requirements.txt')
    require(installed=='11.12.5', 'Нужен pymobiledevice3 11.12.5: python -m pip install -r requirements.txt')
    bundles,assets=load_assets()
    global APPLE_DIRS
    APPLE_DIRS=[str(Path(p).resolve()) for p in args.apple_dir]
    # No shell, no compiler, no native executable bundled with the archive.
    check=subprocess.run(host_command()+['check'],input=json.dumps({'directories':APPLE_DIRS}),
                         capture_output=True,text=True,encoding='utf-8',timeout=20)
    frames=[json.loads(l.split(':',1)[1]) for l in check.stdout.splitlines() if l.startswith('CARRIER_SWAP_JSON:')]
    require(check.returncode==0 and frames and frames[-1].get('ok'),
            'Библиотеки Apple недоступны: '+str(frames[-1].get('error') if frames else check.stderr.strip()))
    if args.check:
        print('Триггеры целы, библиотеки Apple доступны; пакеты будут взяты из системы iPhone. Подключений к телефону не было.');return 0
    args.runs=args.runs.resolve()
    print('Разблокируйте iPhone и подтвердите доверие компьютеру. Закройте синхронизацию Finder/iTunes.',flush=True)
    with operation_lock(args.runs):return asyncio.run(execute_with_retry(args,bundles,assets)) or 0


if __name__=='__main__':
    try:sys.exit(main())
    except KeyboardInterrupt:
        print('Прервано. Сохраните runs; используйте --recover для незавершённого этапа.',file=sys.stderr);sys.exit(130)
    except Exception as e:
        print('Ошибка:',str(e),file=sys.stderr);sys.exit(1)
