import 'dart:async';

import 'package:flutter_hbb/models/state_generation_guard.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  AuthRequestGeneration generation(String nonce,
          {String cursor = 'cursor-a'}) =>
      AuthRequestGeneration(
        normalizedApiBase: 'https://api.example.com',
        namespace: 'user:alice',
        cursorKey: cursor,
        sessionEpoch: 7,
        sessionNonce: nonce,
      );

  String attemptJson(int id, String nonce) => '''
    {
      "attempt_id": $id,
      "nonce": "$nonce",
      "normalized_api_base": "https://api.example.com",
      "logout_generation": 3
    }
  ''';

  test('原生登录尝试只能作为 opaque String 原样回传', () {
    final first = attemptJson(1, 'nonce-a');
    final byteIdentical = first;
    final semanticallySame =
        '{"attempt_id":1,"nonce":"nonce-a","normalized_api_base":"https://api.example.com","logout_generation":3}';
    final next = attemptJson(2, 'nonce-b');

    expect(nativeAuthAttemptOpaqueFromValue(first), same(first));
    expect(nativeAuthAttemptsMatch(first, byteIdentical), isTrue);
    expect(nativeAuthAttemptsMatch(first, semanticallySame), isFalse);
    expect(nativeAuthAttemptsMatch(first, next), isFalse);
    expect(() => nativeAuthAttemptOpaqueFromValue(null), throwsFormatException);
    expect(() => nativeAuthAttemptOpaqueFromValue(''), throwsFormatException);
    expect(
      () => nativeAuthAttemptOpaqueFromValue('x' * (8 * 1024 + 1)),
      throwsFormatException,
    );
  });

  test('轮询结果必须先匹配 Widget 持有的 origin attempt', () {
    const ownerA = 'opaque-attempt-a';
    const ownerB = 'opaque-attempt-b';
    expect(
      requireOwnedNativeAuthResultAttempt(
        <String, dynamic>{
          'native_attempt': ownerA,
          'failed_msg': 'A 的错误',
        },
        ownerA,
      ),
      same(ownerA),
    );
    expect(
      () => requireOwnedNativeAuthResultAttempt(
        <String, dynamic>{
          'native_attempt': ownerA,
          'auth_body': <String, dynamic>{'type': 'access_token'},
        },
        ownerB,
      ),
      throwsFormatException,
    );
  });

  test('email 与 TFA challenge 都保持兼容且不视为 committed', () {
    expect(authChallengeUsesEmail('email_check', 'email'), isTrue);
    expect(authChallengeUsesEmail('email_check', null), isTrue);
    expect(authChallengeUsesEmail('email_check', 'tfa_check'), isFalse);
    expect(authChallengeUsesEmail('email_check', 'totp'), isFalse);
    expect(authChallengeUsesEmail('tfa', 'totp'), isFalse);
    expect(authChallengeUsesEmail('tfa_check', 'tfa'), isFalse);
    expect(authChallengeUsesEmail('access_token', null), isNull);
    expect(authChallengeUsesEmail('unknown', 'sms'), isNull);
  });

  test('ACK 成功后局部 owner 失效也必须完成全局可见提交', () async {
    final publishStarted = Completer<void>();
    final publishRelease = Completer<void>();
    var localOwnerCurrent = true;
    var visiblePublished = false;
    final handoff = NativeCommittedHandoff();

    final pending = handoff.run(
      validateBeforeAck: () => localOwnerCurrent,
      acknowledge: () async => true,
      onAcknowledged: () {
        // 模拟 ACK 返回同一时刻对话框被 dispose/dismiss。
        localOwnerCurrent = false;
      },
      publishVisible: () async {
        publishStarted.complete();
        await publishRelease.future;
        // 模拟 acceptNativeCommittedLogin 内部 snapshot await 后写 Rx。
        visiblePublished = true;
      },
      isVisibleCurrent: () => visiblePublished,
    );

    await publishStarted.future;
    expect(handoff.acknowledged, isTrue);
    expect(localOwnerCurrent, isFalse);
    expect(visiblePublished, isFalse);

    publishRelease.complete();
    expect(await pending, isTrue);
    expect(visiblePublished, isTrue);
  });

  test('B 仅 claim 后 begin 失败时，Widget A 仍只 exact cancel 自己一次', () {
    var localA = true;
    var globalA = true;
    var retiredA = false;
    var cancelA = 0;
    var cancelB = 0;

    void observeAOwnerBoundary() {
      if (retiredA ||
          !nativeAttemptNeedsExactRetirement(
            localOwner: localA,
            globalOwner: globalA,
            hasAttempt: true,
          )) {
        return;
      }
      retiredA = true;
      cancelA += 1;
    }

    observeAOwnerBoundary();
    expect(cancelA, 0);

    // B 先夺取全局 start ticket，但在 native begin/cancel-all 前失败。
    globalA = false;
    observeAOwnerBoundary();
    observeAOwnerBoundary(); // 模拟 timer 与 late future 先后观察同一失权。

    expect(localA, isTrue);
    expect(retiredA, isTrue);
    expect(cancelA, 1);
    expect(cancelB, 0);
  });

  test('密码 A 在 B claim 后收到可恢复错误也必须精确退休', () {
    var localPasswordA = true;
    var globalPasswordA = true;
    var passwordInProgress = true;
    var sharedCurrentOp = 'oidc-b';
    var cancelA = 0;
    var cancelB = 0;

    void observePasswordError() {
      if (!nativeAttemptNeedsExactRetirement(
        localOwner: localPasswordA,
        globalOwner: globalPasswordA,
        hasAttempt: true,
      )) {
        return;
      }
      localPasswordA = false;
      passwordInProgress = false;
      cancelA += 1;
      // sharedCurrentOp 属于后发 B，A 的退休不得修改它。
    }

    // B 先 claim，但 native begin 在 cancel-all 之前失败。
    globalPasswordA = false;
    observePasswordError(); // A 的 recoverable RequestException 恢复。
    observePasswordError(); // finally/其他 late continuation 不得重复取消。

    expect(localPasswordA, isFalse);
    expect(passwordInProgress, isFalse);
    expect(cancelA, 1);
    expect(cancelB, 0);
    expect(sharedCurrentOp, 'oidc-b');
  });

  test('密码 A 失权后的 stale 和 callback false 都仅复位 A UI', () {
    for (final lateResult in ['stale', 'callback-false']) {
      var localPasswordA = true;
      const globalPasswordA = false;
      var passwordInProgress = true;
      var sharedCurrentOp = 'oidc-b';
      var cancelA = 0;
      var closeB = 0;

      void retireBeforeClearingLocalOwner() {
        if (!nativeAttemptNeedsExactRetirement(
          localOwner: localPasswordA,
          globalOwner: globalPasswordA,
          hasAttempt: true,
        )) {
          return;
        }
        localPasswordA = false;
        passwordInProgress = false;
        cancelA += 1;
      }

      // B begin 失败不会替 A 做 cancel；A 的 late branch 必须在
      // finishPasswordAttempt 清 local owner 前先观察失权。
      expect(lateResult, anyOf('stale', 'callback-false'));
      retireBeforeClearingLocalOwner();

      expect(localPasswordA, isFalse);
      expect(passwordInProgress, isFalse);
      expect(cancelA, 1);
      expect(sharedCurrentOp, 'oidc-b');
      expect(closeB, 0);
    }
  });

  test('A begin 延迟时后发 B 先夺权且必须等 A 精确取消后再 begin', () async {
    final gate = NativeAuthStartGate();
    final aTicket = gate.claim();
    final aBeginRelease = Completer<void>();
    final aBeginStarted = Completer<void>();
    final aCancelled = Completer<void>();
    final order = <String>[];

    final pendingA = gate.run<String>(
      ticket: aTicket,
      begin: () async {
        order.add('a-begin');
        aBeginStarted.complete();
        await aBeginRelease.future;
        order.add('a-return');
        return attemptJson(1, 'nonce-a');
      },
      cancel: (attempt) {
        order.add('a-cancel');
        expect(attempt, contains('nonce-a'));
        aCancelled.complete();
      },
    );

    await aBeginStarted.future;
    final bTicket = gate.claim();
    final pendingB = gate.run<String>(
      ticket: bTicket,
      begin: () async {
        order.add('b-begin');
        return attemptJson(2, 'nonce-b');
      },
      cancel: (_) => order.add('b-cancel'),
    );

    await Future<void>.delayed(Duration.zero);
    expect(order, ['a-begin']);
    aBeginRelease.complete();
    await aCancelled.future;

    expect(await pendingA, isNull);
    expect(await pendingB, contains('nonce-b'));
    expect(order, ['a-begin', 'a-return', 'a-cancel', 'b-begin']);
    expect(gate.owns(aTicket), isFalse);
    expect(gate.owns(bTicket), isTrue);
  });

  test('完整请求代际包含 cursor key 与登录随机数', () {
    String handle(String cursorKey, String nonce) => '''
      {
        "normalized_api_base": "https://api.example.com",
        "namespace": "user:alice",
        "cursor_key": "$cursorKey",
        "session_epoch": 7,
        "session_nonce": "$nonce"
      }
    ''';

    final first = AuthRequestGeneration.fromHandleJson(handle('cursor-a', 'a'));
    final nextCursor =
        AuthRequestGeneration.fromHandleJson(handle('cursor-b', 'a'));
    final nextLogin =
        AuthRequestGeneration.fromHandleJson(handle('cursor-a', 'b'));

    expect(first.cursorKey, 'cursor-a');
    expect(first.key, isNot(nextCursor.key));
    expect(first.key, isNot(nextLogin.key));
    expect(
      () => AuthRequestGeneration.fromHandleJson('''
        {
          "normalized_api_base": "https://api.example.com",
          "namespace": "user:alice",
          "session_epoch": 7,
          "session_nonce": "a"
        }
      '''),
      throwsFormatException,
    );
    expect(
      cacheNamespaceForConditionalClear(
        rememberedNamespace: null,
        generationHandleJson: handle('cursor-a', 'a'),
      ),
      'cursor-a',
    );
    expect(
      cacheNamespaceForConditionalClear(
        rememberedNamespace: 'remembered',
        generationHandleJson: handle('cursor-a', 'a'),
      ),
      'remembered',
    );
    expect(
      cacheNamespaceForConditionalClear(
        rememberedNamespace: null,
        generationHandleJson: null,
      ),
      isNull,
    );
  });

  test('认证清理事件只匹配当前界面代际', () {
    final current = <String, dynamic>{
      'name': 'native_auth_cleared',
      'cleared_session_epoch': 7,
      'cleared_session_nonce': 'nonce-a',
      'reason': 'unauthorized',
    };
    expect(
      authClearedEventMatchesVisibleGeneration(
        current,
        visibleSessionEpoch: 7,
        visibleSessionNonce: 'nonce-a',
      ),
      isTrue,
    );
    expect(
      authClearedEventMatchesVisibleGeneration(
        current,
        visibleSessionEpoch: 8,
        visibleSessionNonce: 'nonce-b',
      ),
      isFalse,
    );
    expect(
      authClearedEventMatchesVisibleGeneration(
        <String, dynamic>{
          'cleared_session_epoch': 7,
          'cleared_session_nonce': 'nonce-b',
        },
        visibleSessionEpoch: 7,
        visibleSessionNonce: 'nonce-a',
      ),
      isFalse,
    );
  });

  test('地址簿刷新事件必须绑定当前游标与会话', () {
    final session = <String, dynamic>{
      'cursor': 12,
      'session_epoch': 7,
      'session_nonce': 'nonce-a',
    };
    final event = <String, dynamic>{
      'requested_ab_ver': 12,
      'target_ab_ver': 13,
      'reset_required': false,
      'session_epoch': 7,
      'session_nonce': 'nonce-a',
    };
    expect(addressBookRefreshEventMatchesSession(event, session), isTrue);
    expect(
      addressBookRefreshEventMatchesSession(
        {...event, 'requested_ab_ver': 11},
        session,
      ),
      isFalse,
    );
    expect(
      addressBookRefreshEventMatchesSession(
        {...event, 'reset_required': 'false'},
        session,
      ),
      isFalse,
    );
    expect(
      addressBookRefreshEventMatchesSession(
        {...event, 'reset_required': true, 'target_ab_ver': null},
        session,
      ),
      isFalse,
    );
    expect(
      addressBookRefreshEventMatchesSession(
        Map<String, dynamic>.from(event)
          ..remove('session_epoch')
          ..remove('session_nonce'),
        Map<String, dynamic>.from(session)
          ..remove('session_epoch')
          ..remove('session_nonce'),
      ),
      isFalse,
    );
    expect(
      addressBookRefreshEventMatchesSession(
        {...event, 'session_epoch': '7'},
        session,
      ),
      isFalse,
    );
    expect(
      addressBookRefreshEventMatchesSession(
        {...event, 'session_nonce': ''},
        session,
      ),
      isFalse,
    );
  });

  test('代际在异步复验期间变化时拒绝续体', () async {
    var state = 'account-a';
    final checked = Completer<bool>();
    final guard = StateGenerationGuard(
      sameState: () => state == 'account-a',
      sameGeneration: () => checked.future,
    );

    final pending = guard.isCurrent();
    state = 'account-b';
    checked.complete(true);

    expect(await pending, isFalse);
  });

  test('缓存写入使用入口处冻结的 payload', () async {
    var current = true;
    final mutable = <String>['account-a'];
    final frozen = List<String>.unmodifiable(mutable);
    final writes = <List<String>>[];
    final guard = StateGenerationGuard(
      sameState: () => current,
      sameGeneration: () async => current,
    );

    mutable[0] = 'account-b';
    final committed = await guard.commitFrozen<List<String>>(
      frozen,
      (payload) async => writes.add(payload),
    );

    expect(committed, isTrue);
    expect(writes, [
      ['account-a']
    ]);
  });

  test('写入前已换代时不调用 writer', () async {
    var current = false;
    var writes = 0;
    final guard = StateGenerationGuard(
      sameState: () => current,
      sameGeneration: () async => current,
    );

    final committed = await guard.commitFrozen<String>(
      'account-a',
      (_) async => writes += 1,
    );

    expect(committed, isFalse);
    expect(writes, 0);
  });

  test('同一认证代际内模型实例已替换时也拒绝写入', () async {
    final capturedModel = Object();
    var visibleModel = capturedModel;
    var writes = 0;
    final guard = StateGenerationGuard(
      sameState: () => identical(visibleModel, capturedModel),
      sameGeneration: () async => true,
    );

    visibleModel = Object();
    final committed = await guard.commitFrozen<String>(
      'old-model',
      (_) async => writes += 1,
    );

    expect(committed, isFalse);
    expect(writes, 0);
  });

  test('写入期间换代时最终结果失败', () async {
    var current = true;
    final guard = StateGenerationGuard(
      sameState: () => current,
      sameGeneration: () async => current,
    );

    final committed = await guard.commitFrozen<String>(
      'account-a',
      (_) async => current = false,
    );

    expect(committed, isFalse);
  });

  test('安全快照必须按完整五元组匹配', () {
    final current = generation('nonce-a');
    final snapshot = <String, dynamic>{
      'session': <String, dynamic>{
        'normalized_api_base': current.normalizedApiBase,
        'namespace': current.namespace,
        'cursor_key': current.cursorKey,
        'session_epoch': current.sessionEpoch,
        'session_nonce': current.sessionNonce,
      },
    };

    expect(authGenerationFromSnapshot(snapshot)?.sameAs(current), isTrue);
    expect(
      authGenerationFromSnapshot({
        'session': {
          ...snapshot['session'] as Map<String, dynamic>,
          'cursor_key': 'cursor-b',
        },
      })?.sameAs(current),
      isFalse,
    );
    expect(authGenerationFromSnapshot({'session': null}), isNull);
  });

  test('clear事件在提交前复验期间先执行时旧续体不能复活A', () async {
    final coordinator = GenerationCommitCoordinator();
    final checked = Completer<bool>();
    var visible = 'account-a';
    var writes = 0;

    final pending = coordinator.commit<String>(
      generation: generation('nonce-a'),
      isGenerationCurrent: (_) => checked.future,
      payload: 'late-account-a',
      apply: (value) {
        writes += 1;
        visible = value;
      },
      rollback: (_) => visible = '',
    );

    coordinator.invalidate();
    visible = '';
    checked.complete(true);

    expect(await pending, isNull);
    expect(writes, 0);
    expect(visible, isEmpty);
  });

  test('native已换代但clear事件缺失时提交后复验会回滚A', () async {
    final coordinator = GenerationCommitCoordinator();
    final postcheck = Completer<bool>();
    final applied = Completer<void>();
    var checks = 0;
    var visible = '';

    final pending = coordinator.commit<String>(
      generation: generation('nonce-a'),
      isGenerationCurrent: (_) {
        checks += 1;
        return checks == 1 ? Future.value(true) : postcheck.future;
      },
      payload: 'account-a',
      apply: (value) {
        visible = value;
        applied.complete();
      },
      rollback: (stillOwned) {
        if (stillOwned()) visible = '';
      },
    );

    await applied.future;
    postcheck.complete(false);

    expect(await pending, isNull);
    expect(visible, isEmpty);
  });

  test('A回滚等待期间B接管owner后A不能继续清B', () async {
    final coordinator = GenerationCommitCoordinator();
    final aPostcheck = Completer<bool>();
    final aApplied = Completer<void>();
    final rollbackStarted = Completer<void>();
    final rollbackRelease = Completer<void>();
    var aChecks = 0;
    var visible = '';
    var lateRollbackRan = false;

    final pendingA = coordinator.commit<String>(
      generation: generation('nonce-a'),
      isGenerationCurrent: (_) {
        aChecks += 1;
        return aChecks == 1 ? Future.value(true) : aPostcheck.future;
      },
      payload: 'account-a',
      apply: (value) {
        visible = value;
        aApplied.complete();
      },
      rollback: (stillOwned) async {
        if (!stillOwned()) return;
        visible = '';
        rollbackStarted.complete();
        await rollbackRelease.future;
        if (stillOwned()) {
          lateRollbackRan = true;
          visible = '';
        }
      },
    );

    await aApplied.future;
    aPostcheck.complete(false);
    await rollbackStarted.future;

    final receiptB = await coordinator.commit<String>(
      generation: generation('nonce-b'),
      isGenerationCurrent: (_) async => true,
      payload: 'account-b',
      apply: (value) => visible = value,
      rollback: (stillOwned) {
        if (stillOwned()) visible = '';
      },
    );
    expect(coordinator.owns(receiptB), isTrue);

    rollbackRelease.complete();
    expect(await pendingA, isNull);
    expect(lateRollbackRan, isFalse);
    expect(visible, 'account-b');
    expect(coordinator.owns(receiptB), isTrue);
  });

  test('postcheck返回后clear事件先恢复时receipt也必须失效', () async {
    final coordinator = GenerationCommitCoordinator();
    final postcheck = Completer<bool>();
    final applied = Completer<void>();
    var checks = 0;
    var visible = '';

    final pending = coordinator.commit<String>(
      generation: generation('nonce-a'),
      isGenerationCurrent: (_) {
        checks += 1;
        return checks == 1 ? Future.value(true) : postcheck.future;
      },
      payload: 'account-a',
      apply: (value) {
        visible = value;
        applied.complete();
      },
      rollback: (stillOwned) {
        if (stillOwned()) visible = '';
      },
    );

    await applied.future;
    postcheck.complete(true);
    coordinator.invalidate();
    visible = '';

    expect(await pending, isNull);
    expect(visible, isEmpty);
  });
}
