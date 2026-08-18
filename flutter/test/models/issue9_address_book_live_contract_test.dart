import 'dart:convert';
import 'dart:io';

import 'package:flutter_hbb/models/ab_model.dart';
import 'package:flutter_hbb/models/peer_model.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:get/get.dart';

const _fixtureRoot =
    String.fromEnvironment('ISSUE9_FIXTURE_ROOT', defaultValue: '');
const _maxResponseBytes = 16 * 1024 * 1024;

void _require(bool condition, String message) {
  if (!condition) {
    throw StateError(message);
  }
}

class _LiveInput {
  final Uri apiBase;
  final String username;
  final String password;

  _LiveInput(this.apiBase, this.username, this.password);

  static Future<_LiveInput> readAndDelete(Directory root) async {
    final file =
        File('${root.path}${Platform.pathSeparator}flutter-input.json');
    final raw = await file.readAsString();
    await file.delete();
    final value = jsonDecode(raw);
    _require(value is Map<String, dynamic>, 'Flutter 输入不是对象');
    final map = value as Map<String, dynamic>;
    _require(map['schema'] == 1, 'Flutter 输入 schema 无效');
    _require(map['api_base'] is String, 'Flutter 输入缺少 API 地址');
    _require(map['recipient_username'] is String, 'Flutter 输入缺少用户名');
    _require(map['recipient_password'] is String, 'Flutter 输入缺少密码');
    final base = Uri.parse(map['api_base'] as String);
    _require(base.scheme == 'http' && base.host == '127.0.0.1',
        'Flutter 输入不是 loopback HTTP');
    return _LiveInput(
      base,
      map['recipient_username'] as String,
      map['recipient_password'] as String,
    );
  }
}

class _HttpResult {
  final int status;
  final String? contentType;
  final String body;

  _HttpResult(this.status, this.contentType, this.body);
}

class _PrivateTransport {
  final Uri _base;
  final HttpClient _client = HttpClient();
  String? _token;

  _PrivateTransport(this._base) {
    _client.autoUncompress = false;
    _client.connectionTimeout = const Duration(seconds: 10);
  }

  Uri _endpoint(String suffix, [Map<String, String>? query]) {
    final prefix = _base.path.replaceFirst(RegExp(r'/+$'), '');
    return _base.replace(
      path: '$prefix/${suffix.replaceFirst(RegExp(r'^/+'), '')}',
      queryParameters: query,
      fragment: '',
    );
  }

  Future<void> login(String username, String password) async {
    final result = await _send(
      'POST',
      _endpoint('api/login'),
      body: jsonEncode({
        'username': username,
        'password': password,
        'type': 'account',
        'autoLogin': true,
      }),
      authenticated: false,
    );
    _require(result.status == HttpStatus.ok, 'Flutter 真实登录状态无效');
    _require(result.contentType?.split(';').first.trim() == 'application/json',
        'Flutter 真实登录 MIME 无效');
    final value = jsonDecode(result.body);
    _require(value is Map<String, dynamic>, 'Flutter 登录响应不是对象');
    final map = value as Map<String, dynamic>;
    _require(map['type'] == 'access_token', 'Flutter 登录响应类型无效');
    _require(map['access_token'] is String, 'Flutter 登录响应缺少 token');
    final token = map['access_token'] as String;
    _require(token.isNotEmpty, 'Flutter 登录 token 为空');
    _token = token;
  }

  Future<Issue9DeltaPage> pullDelta(int cursor) async {
    final result = await _send(
      'GET',
      _endpoint('api/ab', {
        'ab_ver': cursor.toString(),
        'page_size': '50',
      }),
    );
    _require(result.status == HttpStatus.ok, 'Flutter v2 delta 状态无效');
    _require(result.contentType?.split(';').first.trim() == 'application/json',
        'Flutter v2 delta MIME 无效');
    final value = jsonDecode(result.body);
    _require(value is Map<String, dynamic>, 'Flutter v2 delta 不是对象');
    return Issue9DeltaPage.fromJson(value, cursor);
  }

  Future<_HttpResult> _send(
    String method,
    Uri uri, {
    String? body,
    bool authenticated = true,
  }) async {
    final request = await _client.openUrl(method, uri);
    request.followRedirects = false;
    request.maxRedirects = 0;
    if (authenticated) {
      final token = _token;
      _require(token != null && token.isNotEmpty, 'Flutter transport 尚未登录');
      request.headers.set(HttpHeaders.authorizationHeader, 'Bearer $token');
    }
    if (body != null) {
      request.headers.contentType = ContentType.json;
      request.write(body);
    }
    final response = await request.close();
    _require(response.statusCode < 300 || response.statusCode >= 400,
        'Flutter transport 禁止重定向');
    final bytes = <int>[];
    await for (final chunk in response) {
      bytes.addAll(chunk);
      _require(bytes.length <= _maxResponseBytes, 'Flutter HTTP 响应过大');
    }
    return _HttpResult(
      response.statusCode,
      response.headers.value(HttpHeaders.contentTypeHeader),
      utf8.decode(bytes),
    );
  }

  void close() {
    _token = null;
    _client.close(force: true);
  }
}

class _TypedBridgeSpy {
  int cursor = 0;
  final List<Map<String, dynamic>> calls = [];

  bool completeAddressBookPull(
      {required int expected, required int target, required bool allowReset}) {
    if (cursor != expected || (!allowReset && target < expected)) {
      return false;
    }
    calls.add({
      'expected': expected,
      'target': target,
      'allow_reset': allowReset,
    });
    cursor = target;
    return true;
  }
}

Future<Map<String, dynamic>> _readEvent(
    Directory root, String fileName, String phase) async {
  final file = File('${root.path}${Platform.pathSeparator}$fileName');
  final deadline = DateTime.now().add(const Duration(seconds: 180));
  while (!await file.exists()) {
    _require(DateTime.now().isBefore(deadline), '等待 $phase event 超时');
    await Future<void>.delayed(const Duration(milliseconds: 50));
  }
  final raw = await file.readAsString();
  await file.delete();
  final value = jsonDecode(raw);
  _require(value is Map<String, dynamic>, '$phase event 不是对象');
  final event = value as Map<String, dynamic>;
  final keys = event.keys.toList()..sort();
  final expectedKeys = <String>[
    'name',
    'requested_ab_ver',
    'reset_required',
    'session_epoch',
    'session_nonce',
    'source',
    'target_ab_ver',
  ]..sort();
  _require(keys.join('\u0000') == expectedKeys.join('\u0000'),
      '$phase event schema 漂移');
  _require(event['name'] == 'address_book_updated', '$phase event 名称无效');
  _require(event['source'] == 'address_book_probe', '$phase event 来源无效');
  _require(event['session_epoch'] is int, '$phase event epoch 无效');
  _require(
      event['session_nonce'] is String &&
          RegExp(r'^[0-9a-f]{32}$').hasMatch(event['session_nonce'] as String),
      '$phase event nonce 无效');
  _require(event['reset_required'] is bool, '$phase event reset 标记无效');
  return event;
}

Future<void> _writePrivateAck(
    Directory root, String fileName, Map<String, dynamic> value) async {
  final file = File('${root.path}${Platform.pathSeparator}$fileName');
  final temporary =
      File('${file.path}.$pid.${DateTime.now().microsecondsSinceEpoch}.tmp');
  try {
    await temporary.writeAsString(jsonEncode(value), flush: true);
    if (!Platform.isWindows) {
      final result = await Process.run('chmod', ['600', temporary.path]);
      _require(result.exitCode == 0, '无法收紧 Flutter ACK 文件权限');
    }
    await temporary.rename(file.path);
  } finally {
    if (await temporary.exists()) {
      await temporary.delete();
    }
  }
}

void main() {
  test(
    'Issue 9 真实 HTTP event 到模型 Rx 与 typed ACK 双阶段契约',
    () async {
      _require(_fixtureRoot.isNotEmpty, '缺少 ISSUE9_FIXTURE_ROOT');
      final root = Directory(_fixtureRoot);
      _require(await root.exists(), '私有 fixture 根不存在');
      final input = await _LiveInput.readAndDelete(root);
      final transport = _PrivateTransport(input.apiBase);
      final bridge = _TypedBridgeSpy();
      final RxList<Peer> peers = <Peer>[].obs;
      try {
        await transport.login(input.username, input.password);

        final acceptEvent =
            await _readEvent(root, 'accept-event.json', 'accept');
        _require(acceptEvent['requested_ab_ver'] == bridge.cursor,
            'accept event cursor 与 typed bridge 不一致');
        final acceptDelta = await transport.pullDelta(bridge.cursor);
        _require(acceptEvent['target_ab_ver'] == acceptDelta.abVer,
            'accept event target 与真实响应不一致');
        peers.assignAll(Issue9AddressBookState.applyDelta(peers, acceptDelta));
        _require(peers.length == 1, 'accept 后模型未出现共享 peer');
        final accepted = peers.single;
        _require(accepted.addressBookSource == 'shared', 'accept 后 source 无效');
        _require(accepted.addressBookPermission == 'view_only',
            'accept 后 permission 无效');
        _require(
            accepted.addressBookInstanceId != null &&
                RegExp(r'^[0-9a-f]{64}$')
                    .hasMatch(accepted.addressBookInstanceId!),
            'accept 后 instance 无效');
        _require(
          bridge.completeAddressBookPull(
            expected: 0,
            target: acceptDelta.abVer,
            allowReset: acceptDelta.resetRequired,
          ),
          'accept typed ACK 被 CAS 拒绝',
        );
        await _writePrivateAck(root, 'accept-ack.json', {
          'schema': 1,
          'phase': 'accept',
          'expected_cursor': 0,
          'target_cursor': bridge.cursor,
          'observed_count': peers.length,
          'device_id': accepted.id,
          'instance_id': accepted.addressBookInstanceId,
          'source': accepted.addressBookSource,
          'permission': accepted.addressBookPermission,
        });

        final cancelEvent =
            await _readEvent(root, 'cancel-event.json', 'cancel');
        _require(cancelEvent['requested_ab_ver'] == bridge.cursor,
            'cancel event cursor 与 typed bridge 不一致');
        final cancelDelta = await transport.pullDelta(bridge.cursor);
        _require(cancelEvent['target_ab_ver'] == cancelDelta.abVer,
            'cancel event target 与真实响应不一致');
        peers.assignAll(Issue9AddressBookState.applyDelta(peers, cancelDelta));
        _require(peers.isEmpty, 'cancel 后模型仍保留共享 peer');
        _require(
          bridge.completeAddressBookPull(
            expected: 1,
            target: cancelDelta.abVer,
            allowReset: cancelDelta.resetRequired,
          ),
          'cancel typed ACK 被 CAS 拒绝',
        );
        _require(bridge.calls.length == 2, 'typed bridge ACK 次数无效');
        await _writePrivateAck(root, 'cancel-ack.json', {
          'schema': 1,
          'phase': 'cancel',
          'expected_cursor': 1,
          'target_cursor': bridge.cursor,
          'observed_count': peers.length,
          'device_id': null,
          'instance_id': null,
          'source': null,
          'permission': null,
        });
      } finally {
        transport.close();
      }
    },
    timeout: const Timeout(Duration(minutes: 4)),
  );
}
