import 'dart:async';
import 'dart:convert';

const int _maxNativeAuthAttemptBytes = 8 * 1024;

/// native 登录尝试是不透明能力，Dart 只能原样保存和回传。
///
/// 不解析、不规范化、不重新序列化；所有权威校验由 native 完成。
String nativeAuthAttemptOpaqueFromValue(dynamic value) {
  if (value is! String ||
      value.isEmpty ||
      utf8.encode(value).length > _maxNativeAuthAttemptBytes) {
    throw const FormatException('原生登录尝试能力无效');
  }
  return value;
}

bool nativeAuthAttemptsMatch(String first, String second) =>
    first.isNotEmpty && first == second;

/// Widget 仍持有自己的 attempt，但进程级 start ticket 已被另一入口夺走时，
/// 必须立即 exact cancel 本地 A；等待 B begin 成功再隐式清理会在 B begin 失败时
/// 留下无人轮询/ACK 的 A。
bool nativeAttemptNeedsExactRetirement({
  required bool localOwner,
  required bool globalOwner,
  required bool hasAttempt,
}) =>
    localOwner && hasAttempt && !globalOwner;

String requireOwnedNativeAuthResultAttempt(
  Map<String, dynamic> result,
  String ownerAttempt,
) {
  final origin = nativeAuthAttemptOpaqueFromValue(result['native_attempt']);
  if (!nativeAuthAttemptsMatch(ownerAttempt, origin)) {
    throw const FormatException('原生登录结果不属于当前界面');
  }
  return origin;
}

bool? authChallengeUsesEmail(String? type, String? tfaType) {
  final normalizedType = type?.toLowerCase();
  final normalizedTfaType = tfaType?.toLowerCase();
  // 服务端可能保留外层 email_check，同时用 tfa_type 指明真实挑战。
  // 显式子类型必须优先，否则 TFA 会被误当成邮箱验证码。
  if (normalizedTfaType == 'tfa_check' ||
      normalizedTfaType == 'tfa' ||
      normalizedTfaType == 'totp') {
    return false;
  }
  if (normalizedTfaType == 'email_check' || normalizedTfaType == 'email') {
    return true;
  }
  if (normalizedType == 'tfa_check' ||
      normalizedType == 'tfa' ||
      normalizedType == 'totp') {
    return false;
  }
  if (normalizedType == 'email_check') return true;
  return null;
}

/// committed 登录从可取消 attempt 到全局可见用户的线性化交接。
///
/// ACK 成功前仍可按界面 owner 与完整 generation 拒绝；ACK 成功即表示 native
/// 会话已被应用接纳，此后即使对话框关闭，也必须尝试发布全局 Rx。发布阶段只能由
/// native generation 门禁拒绝，不能再读取局部 Widget/Dialog owner。
class NativeCommittedHandoff {
  bool _acknowledged = false;

  bool get acknowledged => _acknowledged;

  Future<bool> run({
    required FutureOr<bool> Function() validateBeforeAck,
    required Future<bool> Function() acknowledge,
    required void Function() onAcknowledged,
    required Future<void> Function() publishVisible,
    required FutureOr<bool> Function() isVisibleCurrent,
  }) async {
    if (!await validateBeforeAck()) return false;
    if (!await acknowledge()) return false;

    _acknowledged = true;
    onAcknowledged();

    // 从这里开始不再执行局部 owner 检查；publishVisible 自身只校验 native
    // generation，因此关闭 A 对话框不会留下“native 已登录但 Rx 未更新”。
    await publishVisible();
    return await isVisibleCurrent();
  }
}

/// 一次进程级登录 start 的同步所有权票据。
class NativeAuthStartTicket {
  final int _revision;

  const NativeAuthStartTicket._(this._revision);
}

/// 串行化普通登录与 OIDC 的 native begin。
///
/// 新操作先同步 [claim] 夺权，再排入 [run]。若 B 在 A 的 native begin
/// 等待期间后发，A 返回后必须先精确取消自己的能力，队列才允许 B begin，
/// 避免 bridge 调度乱序使迟到的 A 反向覆盖 B。
class NativeAuthStartGate {
  int _revision = 0;
  Future<void> _tail = Future<void>.value();

  NativeAuthStartTicket claim() => NativeAuthStartTicket._(++_revision);

  bool owns(NativeAuthStartTicket ticket) => ticket._revision == _revision;

  void release(NativeAuthStartTicket ticket) {
    if (owns(ticket)) {
      _revision += 1;
    }
  }

  Future<T?> run<T>({
    required NativeAuthStartTicket ticket,
    required Future<T> Function() begin,
    required FutureOr<void> Function(T value) cancel,
  }) async {
    final predecessor = _tail;
    final completed = Completer<void>();
    _tail = completed.future;
    try {
      await predecessor;
      if (!owns(ticket)) return null;

      final value = await begin();
      if (owns(ticket)) return value;

      try {
        await cancel(value);
      } catch (_) {
        // 精确取消失败不能永久阻塞后续登录；native begin 仍会再次换代。
      }
      return null;
    } finally {
      completed.complete();
    }
  }
}

/// native 严格请求句柄中用于隔离账号、服务端与登录代际的完整身份。
class AuthRequestGeneration {
  final String normalizedApiBase;
  final String namespace;
  final String cursorKey;
  final int sessionEpoch;
  final String sessionNonce;

  const AuthRequestGeneration({
    required this.normalizedApiBase,
    required this.namespace,
    required this.cursorKey,
    required this.sessionEpoch,
    required this.sessionNonce,
  });

  factory AuthRequestGeneration.fromHandleJson(String handleJson) {
    final decoded = jsonDecode(handleJson);
    if (decoded is! Map<String, dynamic>) {
      throw const FormatException('认证请求句柄字段无效');
    }
    return AuthRequestGeneration.fromMap(decoded);
  }

  factory AuthRequestGeneration.fromMap(Map<String, dynamic> value) {
    if (value['normalized_api_base'] is! String ||
        value['namespace'] is! String ||
        value['cursor_key'] is! String ||
        value['session_epoch'] is! int ||
        value['session_nonce'] is! String) {
      throw const FormatException('认证代际字段无效');
    }
    final generation = AuthRequestGeneration(
      normalizedApiBase: value['normalized_api_base'] as String,
      namespace: value['namespace'] as String,
      cursorKey: value['cursor_key'] as String,
      sessionEpoch: value['session_epoch'] as int,
      sessionNonce: value['session_nonce'] as String,
    );
    if (generation.normalizedApiBase.isEmpty ||
        generation.namespace.isEmpty ||
        generation.cursorKey.isEmpty ||
        generation.sessionEpoch < 0 ||
        generation.sessionNonce.isEmpty) {
      throw const FormatException('认证代际字段无效');
    }
    return generation;
  }

  bool sameAs(AuthRequestGeneration other) =>
      normalizedApiBase == other.normalizedApiBase &&
      namespace == other.namespace &&
      cursorKey == other.cursorKey &&
      sessionEpoch == other.sessionEpoch &&
      sessionNonce == other.sessionNonce;

  String get key => [
        normalizedApiBase,
        namespace,
        cursorKey,
        sessionEpoch,
        sessionNonce,
      ].join('\u0000');
}

AuthRequestGeneration? authGenerationFromSnapshot(dynamic snapshot) {
  if (snapshot is! Map<String, dynamic>) return null;
  final session = snapshot['session'];
  if (session is! Map<String, dynamic>) return null;
  try {
    return AuthRequestGeneration.fromMap(session);
  } catch (_) {
    return null;
  }
}

/// 一次本地可见状态提交的所有权凭据。
///
/// 调用方在异步 helper 返回后、发出 load event 等同步副作用前，应再次用
/// [GenerationCommitCoordinator.owns] 检查，避免 reset 已先执行但旧 Future
/// 续体随后恢复。
class GenerationCommitReceipt {
  final int _revision;
  final Object _owner;

  const GenerationCommitReceipt._(this._revision, this._owner);
}

/// 将 native 完整认证代际与 Dart 本地模型提交绑定。
///
/// 每次提交在 native 复验前后都检查完整 generation，同时用 revision/owner
/// 防止已经被 reset 或新账号提交取代的旧续体继续发布。提交后复验失败时只
/// 回滚仍由本次 receipt 拥有的状态，绝不清理后来的账号状态。
class GenerationCommitCoordinator {
  int _revision = 0;
  Object? _owner;

  int get revision => _revision;

  void invalidate() {
    _revision += 1;
    _owner = null;
  }

  bool owns(GenerationCommitReceipt? receipt) =>
      receipt != null &&
      receipt._revision == _revision &&
      identical(receipt._owner, _owner);

  GenerationCommitReceipt replaceLocal<T>(
    T payload,
    void Function(T payload) apply,
  ) {
    final owner = Object();
    final receipt = GenerationCommitReceipt._(++_revision, owner);
    _owner = owner;
    apply(payload);
    return receipt;
  }

  Future<GenerationCommitReceipt?> commit<T>({
    required AuthRequestGeneration generation,
    required Future<bool> Function(AuthRequestGeneration generation)
        isGenerationCurrent,
    required T payload,
    required FutureOr<void> Function(T payload) apply,
    required FutureOr<void> Function(bool Function() stillOwned) rollback,
  }) async {
    final entryRevision = _revision;
    if (!await isGenerationCurrent(generation) || _revision != entryRevision) {
      return null;
    }

    final owner = Object();
    final receipt = GenerationCommitReceipt._(++_revision, owner);
    _owner = owner;
    try {
      await apply(payload);
    } catch (_) {
      if (owns(receipt)) {
        await rollback(() => owns(receipt));
        if (owns(receipt)) {
          invalidate();
        }
      }
      rethrow;
    }

    final generationCurrent = await isGenerationCurrent(generation);
    if (generationCurrent && owns(receipt)) {
      return receipt;
    }
    if (owns(receipt)) {
      await rollback(() => owns(receipt));
      if (owns(receipt)) {
        invalidate();
      }
    }
    return null;
  }
}

/// reset 只能清理入口处记住的旧 namespace；没有旧身份时必须保留磁盘缓存。
String? cacheNamespaceForConditionalClear({
  required String? rememberedNamespace,
  required String? generationHandleJson,
}) {
  if (rememberedNamespace != null && rememberedNamespace.isNotEmpty) {
    return rememberedNamespace;
  }
  if (generationHandleJson == null || generationHandleJson.isEmpty) {
    return null;
  }
  try {
    return AuthRequestGeneration.fromHandleJson(generationHandleJson).cursorKey;
  } catch (_) {
    return null;
  }
}

/// 只允许清理由当前界面仍在展示的同一登录代际触发。
bool authClearedEventMatchesVisibleGeneration(
  Map<String, dynamic> event, {
  required int? visibleSessionEpoch,
  required String? visibleSessionNonce,
}) {
  final clearedEpoch = event['cleared_session_epoch'];
  final clearedNonce = event['cleared_session_nonce'];
  return visibleSessionEpoch != null &&
      visibleSessionNonce != null &&
      visibleSessionNonce.isNotEmpty &&
      clearedEpoch is int &&
      clearedNonce is String &&
      clearedEpoch == visibleSessionEpoch &&
      clearedNonce == visibleSessionNonce;
}

/// 校验 worker 刷新事件确实来自当前地址簿游标对应的同一会话。
bool addressBookRefreshEventMatchesSession(
  Map<String, dynamic> event,
  Map<String, dynamic> session,
) {
  final cursor = session['cursor'];
  final sessionEpoch = session['session_epoch'];
  final sessionNonce = session['session_nonce'];
  final requested = event['requested_ab_ver'];
  final target = event['target_ab_ver'];
  final resetRequired = event['reset_required'];
  final eventEpoch = event['session_epoch'];
  final eventNonce = event['session_nonce'];
  return cursor is int &&
      cursor >= 0 &&
      sessionEpoch is int &&
      sessionEpoch >= 0 &&
      sessionNonce is String &&
      sessionNonce.isNotEmpty &&
      requested is int &&
      requested >= 0 &&
      requested == cursor &&
      (target == null || (target is int && target >= 0)) &&
      resetRequired is bool &&
      (!resetRequired || target is int) &&
      eventEpoch is int &&
      eventNonce is String &&
      eventNonce.isNotEmpty &&
      eventEpoch == sessionEpoch &&
      eventNonce == sessionNonce;
}

/// 将异步续体绑定到调用入口处的模型身份与认证代际。
///
/// [_sameState] 必须是同步检查，避免在任何 `await` 之前读取到下一账号的
/// 模型；[_sameGeneration] 负责向 native 复验完整认证请求句柄。
class StateGenerationGuard {
  final bool Function() _sameState;
  final Future<bool> Function() _sameGeneration;

  const StateGenerationGuard({
    required bool Function() sameState,
    required Future<bool> Function() sameGeneration,
  })  : _sameState = sameState,
        _sameGeneration = sameGeneration;

  /// 在异步代际检查的前后都复验模型身份。
  Future<bool> isCurrent() async {
    if (!_sameState()) return false;
    if (!await _sameGeneration()) return false;
    return _sameState();
  }

  /// 只提交入口处已经冻结的 payload，并在写入前后复验。
  ///
  /// native 保存接口仍需在“句柄校验 + 落盘”同一临界区内实现原子门禁；
  /// 此处的双重检查用于阻止 Dart 异步续体跨账号复用模型或 payload。
  Future<bool> commitFrozen<T>(
    T payload,
    Future<void> Function(T payload) writer,
  ) async {
    if (!await isCurrent()) return false;
    await writer(payload);
    return await isCurrent();
  }
}
