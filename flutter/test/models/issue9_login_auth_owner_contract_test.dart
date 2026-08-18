import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  late String loginSource;
  late String userModelSource;
  late String hbbsSource;
  late String webBridgeSource;

  setUpAll(() {
    loginSource = File('lib/common/widgets/login.dart').readAsStringSync();
    userModelSource = File('lib/models/user_model.dart').readAsStringSync();
    hbbsSource = File('lib/common/hbbs/hbbs.dart').readAsStringSync();
    webBridgeSource = File('lib/web/bridge.dart').readAsStringSync();
  });

  test('WidgetOP 轮询和取消都使用自己的 opaque attempt', () {
    expect(
      loginSource,
      contains('mainAccountAuthResult(attemptJson: attemptJson)'),
    );
    expect(
      loginSource,
      contains('cancelNativeAttempt(attemptJson)'),
    );
    expect(loginSource, isNot(contains('mainAccountAuthCancel()')));
    expect(loginSource, contains('identical(_owner, owner)'));
    expect(loginSource, contains('identical(owner.timer, timer)'));
  });

  test('Widget A 仅失去全局 ticket 时立即退休并 exact cancel 自己', () {
    final ensure = loginSource.indexOf('_ensureAttemptOwnerOrRetire(');
    final timer = loginSource.indexOf('Timer.periodic', ensure);
    expect(ensure, greaterThanOrEqualTo(0));
    expect(timer, greaterThan(ensure));
    final ensureBody = loginSource.substring(ensure, timer);
    expect(ensureBody, contains('nativeAttemptNeedsExactRetirement('));
    expect(ensureBody, contains('localOwner: _isLocalOwner(owner)'));
    expect(ensureBody, contains('clearCurrentOp: false'));
    expect(ensureBody, contains('cancelNative: true'));
    expect(
      loginSource.substring(timer, timer + 420),
      contains('_ensureAttemptOwnerOrRetire(owner)'),
    );
  });

  test('所有 OIDC 结果先验 provenance 再读取业务字段', () {
    final provenance =
        loginSource.indexOf('requireOwnedNativeAuthResultAttempt(');
    final authBody = loginSource.indexOf("decoded['auth_body']", provenance);
    expect(provenance, greaterThanOrEqualTo(0));
    expect(authBody, greaterThan(provenance));
    expect(
      'requireOwnedNativeAuthResultAttempt('.allMatches(loginSource).length,
      greaterThanOrEqualTo(2),
      reason: '顶层结果和 nested auth_body 都必须绑定同一 owner',
    );
  });

  test('committed 与 challenge 分别使用 generation 和 attempt 门禁', () {
    expect(loginSource, contains('if (isCommitted)'));
    expect(loginSource, contains('_generationIsCurrent(owner, generation)'));
    expect(loginSource, contains('_attemptIsCurrent(owner)'));
    expect(
      loginSource,
      contains('isVisibleLoginResponseCurrent(response)'),
    );
  });

  test('committed 必须先 ACK exact attempt 再提交 Rx 可见用户', () {
    final committedBranch = loginSource.indexOf('if (isCommitted)');
    final generationCheck = loginSource.indexOf(
        '_generationIsCurrent(owner, generation)', committedBranch);
    final ack =
        loginSource.indexOf('ackNativeAttempt(attemptJson)', generationCheck);
    final visibleCommit =
        loginSource.indexOf('acceptNativeCommittedLogin(response)', ack);
    final visibleCheck = loginSource.indexOf(
        'isVisibleLoginResponseCurrent(response)', visibleCommit);

    expect(generationCheck, greaterThan(committedBranch));
    expect(ack, greaterThan(generationCheck));
    expect(visibleCommit, greaterThan(ack));
    expect(visibleCheck, greaterThan(visibleCommit));
    expect(
        userModelSource, contains('mainAuthAckAttempt(attemptJson: opaque)'));
    final parserStart =
        userModelSource.indexOf('getLoginResponseFromAuthBody(');
    final acceptStart =
        userModelSource.indexOf('acceptNativeCommittedLogin(', parserStart);
    expect(parserStart, greaterThanOrEqualTo(0));
    expect(acceptStart, greaterThan(parserStart));
    expect(
      userModelSource.substring(parserStart, acceptStart),
      isNot(contains('_commitVisibleUser(')),
    );
    expect(
      'NativeCommittedHandoff()'.allMatches(loginSource).length,
      3,
      reason: 'OIDC、密码和验证码三条 committed 路径必须共用 ACK 交接',
    );
    expect(
      loginSource,
      contains('ACK 后界面可以消失，但全局 Rx 已保证提交'),
    );
  });

  test('验证码 follow-up 复用原 attempt 且取消时精确回传', () {
    expect(
      loginSource,
      contains('nativeAttemptJson: resp.nativeAttemptJson'),
    );
    expect(
      loginSource,
      contains('nativeAttemptJson: nativeAttemptJson'),
    );
    expect(
      loginSource,
      contains('cancelNativeAttempt(nativeAttemptJson)'),
    );
    expect(loginSource, contains('callbackOwnsAttempt'));
    expect(loginSource, contains('if (!callbackOwnsAttempt)'));
    final requestStart = hbbsSource.indexOf('class LoginRequest');
    final responseStart = hbbsSource.indexOf('class LoginResponse');
    final requestJson = hbbsSource.substring(requestStart, responseStart);
    expect(requestJson, contains('String? nativeAttemptJson'));
    expect(requestJson, isNot(contains("data['native_attempt']")));
  });

  test('Dart 不解析或重新序列化 native attempt', () {
    expect(userModelSource, isNot(contains('NativeAuthAttempt.fromJson')));
    expect(
      userModelSource,
      contains('nativeAuthAttemptOpaqueFromValue(attemptJson)'),
    );
    expect(
      userModelSource,
      contains('nativeAuthAttemptsMatch(attemptJson, responseAttempt)'),
    );
  });

  test('普通登录 begin 不携带 Dart 侧旧 apiBase', () {
    final begin = userModelSource.indexOf('Future<String?> beginNativeLogin(');
    final oidc =
        userModelSource.indexOf('Future<String?> beginNativeOidc(', begin);
    expect(begin, greaterThanOrEqualTo(0));
    expect(oidc, greaterThan(begin));
    final beginBody = userModelSource.substring(begin, oidc);
    expect(beginBody, contains('bind.mainAuthBeginLogin()'));
    expect(beginBody, isNot(contains('mainGetApiServer')));
    expect(webBridgeSource, contains('mainAuthBeginLogin({dynamic hint})'));
  });

  test('不可恢复错误终结 exact attempt，可恢复错误保留原 attempt', () {
    expect(loginSource, contains('if (!err.recoverable)'));
    expect(loginSource, contains('cancelNative: true'));
    expect(loginSource, contains('existingAttempt != null'));
    expect(loginSource, contains('attemptJson = existingAttempt'));
  });

  test('密码 A 失去全局 ticket 后 exact 退休且不清 B curOP', () {
    final helper = loginSource.indexOf(
      'bool retirePasswordAttemptIfStartLost(',
    );
    final requestCatch = loginSource.indexOf(
      '} on RequestException catch (err)',
      helper,
    );
    final helperEnd = loginSource.indexOf(
      'void stopPasswordUiIfOwned(',
      helper,
    );
    final nonrecoverable = loginSource.indexOf(
      'if (!isWeb && !err.recoverable && errorMatchesAttempt)',
      requestCatch,
    );
    final genericCatch = loginSource.indexOf('} catch (_)', nonrecoverable);
    final submitEnd = loginSource.indexOf('thirdAuthWidget()', genericCatch);
    expect(helper, greaterThanOrEqualTo(0));
    expect(helperEnd, greaterThan(helper));
    expect(requestCatch, greaterThan(helper));
    expect(genericCatch, greaterThan(requestCatch));
    expect(submitEnd, greaterThan(genericCatch));

    final helperBody = loginSource.substring(helper, helperEnd);
    expect(helperBody, contains('isLocalPasswordAttempt(ticket, attemptJson)'));
    expect(helperBody, contains('ownsNativeAuthStart(ticket)'));
    expect(helperBody, contains('cancelNative: true'));
    expect(helperBody, contains('setState(() => isInProgress = false)'));
    expect(helperBody, isNot(contains("curOP.value = ''")));

    final errorClosure = loginSource.substring(requestCatch, submitEnd);
    expect(
      'retirePasswordAttemptIfStartLost(ownerTicket, attemptJson)'
          .allMatches(errorClosure)
          .length,
      greaterThanOrEqualTo(3),
      reason: '可恢复错误、异常和最终收口都必须观察失权',
    );

    final unhandled = loginSource.indexOf('if (!handled && !isWeb)', helper);
    final stale = loginSource.indexOf(
      '} on StaleAuthGenerationException',
      unhandled,
    );
    expect(unhandled, greaterThan(helper));
    expect(stale, greaterThan(unhandled));
    final unhandledBody = loginSource.substring(unhandled, stale);
    final unhandledRetire = unhandledBody.indexOf(
      'retirePasswordAttemptIfStartLost(ownerTicket, attemptJson)',
    );
    final unhandledFinish = unhandledBody.indexOf('finishPasswordAttempt(');
    expect(unhandledRetire, greaterThanOrEqualTo(0));
    expect(unhandledFinish, greaterThan(unhandledRetire),
        reason: 'callback false 必须在清 local owner 前先复位失权 A');
    final staleBody = loginSource.substring(stale, requestCatch);
    final staleRetire = staleBody.indexOf(
      'retirePasswordAttemptIfStartLost(ownerTicket, attemptJson)',
    );
    final staleFinish = staleBody.indexOf('finishPasswordAttempt(');
    expect(staleRetire, greaterThanOrEqualTo(0));
    expect(staleFinish, greaterThan(staleRetire),
        reason: 'stale 必须在清 local owner 前先复位失权 A');
  });

  test('外部 dismiss 也会收回仍由本层持有的 exact attempt', () {
    expect(loginSource, contains('Future<void> finalizePasswordOwner()'));
    expect(loginSource, contains('await finalizePasswordOwner();'));
    expect(loginSource, contains('loginDialogActive = false;'));
    expect(loginSource, contains('verificationDialogActive = false;'));
    expect(loginSource, contains('void transferPasswordOwner('));
    expect(
      loginSource.indexOf('transferPasswordOwner(ownerTicket,'),
      lessThan(loginSource.indexOf('verificationCodeDialog(')),
    );
    expect(
      loginSource,
      contains('if (nativeAttemptJson != null && !attemptAcknowledged)'),
    );
    expect(
      loginSource,
      contains('await gFFI.userModel.cancelNativeAttempt(nativeAttemptJson)'),
    );
  });

  test('普通登录和验证码提交都使用同步 in-flight 门禁', () {
    expect(
      RegExp(r'\|\| isInProgress\) return;').allMatches(loginSource).length,
      greaterThanOrEqualTo(2),
    );
    expect(loginSource, contains('onPressed: !isInProgress &&'));
    expect(
      loginSource,
      contains('codeField.isReady && !isInProgress ? onVerify : null'),
    );
  });

  test('Web OIDC 保留旧 JS 调用并用本地 opaque owner 精确隔离', () {
    expect(webBridgeSource, contains("'web-oidc:"));
    expect(webBridgeSource, contains('_ownsWebOidcAttempt(attemptJson)'));
    expect(
      webBridgeSource,
      contains("decoded['native_attempt'] = attemptJson"),
    );
    expect(
      webBridgeSource,
      contains("authBody['native_attempt'] = attemptJson"),
    );
    final resultMethod = webBridgeSource.indexOf(
      'Future<String> mainAccountAuthResult(',
    );
    expect(resultMethod, greaterThanOrEqualTo(0));
    expect(
      webBridgeSource.substring(resultMethod, resultMethod + 180),
      contains('required String attemptJson'),
    );
    expect(userModelSource, contains('if (isWeb) {'));
    expect(
      userModelSource,
      contains('if (!_nativeAuthStartGate.owns(ticket))'),
    );

    final cancelStart = webBridgeSource.indexOf('_cancelWebOidcAttempt(');
    final cancelEnd = webBridgeSource.indexOf('mainAuthSnapshot(', cancelStart);
    final cancelBody = webBridgeSource.substring(cancelStart, cancelEnd);
    expect(cancelBody, contains("['account_auth_cancel']"));
    expect(cancelBody, isNot(contains('await Future')));
    expect(
      cancelBody.indexOf("['account_auth_cancel']"),
      lessThan(cancelBody.indexOf('_webOidcAttempt = null')),
      reason: '旧 A 的全局 JS cancel 必须在线性化点同步完成，不能迟到取消 B',
    );

    final webBegin = webBridgeSource.indexOf('Future<String> mainAccountAuth(');
    final webBeginEnd = webBridgeSource.indexOf(
        'Future<bool> mainAccountAuthCancel(', webBegin);
    final beginBody = webBridgeSource.substring(webBegin, webBeginEnd);
    expect(
      beginBody.indexOf("['account_auth_cancel']"),
      lessThan(beginBody.indexOf("'web-oidc:")),
      reason: 'Web B 必须先同步终结旧 JS A，再发布自己的 opaque owner',
    );
  });

  test('Web ACK 后全局 Rx 与持久化不再受 dialog owner 截断', () {
    final directAck =
        loginSource.indexOf('ackNativeAttempt(resp.nativeAttemptJson)');
    final directAccept =
        loginSource.indexOf('acceptWebLoginResponse(', directAck);
    final directUiGuard =
        loginSource.indexOf('final mayCloseDialog', directAck);
    expect(directAck, greaterThanOrEqualTo(0));
    expect(directAccept, greaterThan(directAck));
    expect(directUiGuard, greaterThan(directAccept));
    expect(
      loginSource.substring(directAck, directUiGuard),
      isNot(contains('context.mounted')),
    );

    final verificationAck =
        loginSource.indexOf('ackNativeAttempt(nativeAttemptJson)');
    final verificationAccept =
        loginSource.indexOf('acceptWebLoginResponse(', verificationAck);
    final verificationUiGuard =
        loginSource.indexOf('if (!ownsTicket()) return;', verificationAccept);
    expect(verificationAck, greaterThanOrEqualTo(0));
    expect(verificationAccept, greaterThan(verificationAck));
    expect(verificationUiGuard, greaterThan(verificationAccept));
    expect(
      userModelSource,
      contains("key: 'access_token', value: response.access_token!"),
    );
    expect(
      userModelSource,
      contains("key: 'user_info', value: jsonEncode(response.user!)"),
    );
    final webAccept = userModelSource.indexOf('acceptWebLoginResponse(');
    final userInfoWrite =
        userModelSource.indexOf("key: 'user_info'", webAccept);
    final tokenWrite =
        userModelSource.indexOf("key: 'access_token'", webAccept);
    final rxApply = userModelSource.indexOf('_parseAndUpdateUser(', webAccept);
    expect(userInfoWrite, greaterThan(webAccept));
    expect(tokenWrite, greaterThan(userInfoWrite));
    expect(rxApply, greaterThan(tokenWrite));
  });
}
