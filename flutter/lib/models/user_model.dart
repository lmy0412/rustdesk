import 'dart:async';
import 'dart:convert';

import 'package:bot_toast/bot_toast.dart';
import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/hbbs/hbbs.dart';
import 'package:flutter_hbb/models/ab_model.dart';
import 'package:flutter_hbb/models/state_generation_guard.dart';
import 'package:get/get.dart';

import '../common.dart';
import '../utils/http_service.dart' as http;
import 'model.dart';
import 'platform_model.dart';

bool refreshingUser = false;

class StaleAuthGenerationException implements Exception {
  const StaleAuthGenerationException();

  @override
  String toString() => '认证结果已失效';
}

class UserModel {
  static final NativeAuthStartGate _nativeAuthStartGate = NativeAuthStartGate();

  final RxString userName = ''.obs;
  final RxString displayName = ''.obs;
  final RxString avatar = ''.obs;
  final RxBool isAdmin = false.obs;
  final RxString networkError = ''.obs;
  final GenerationCommitCoordinator _visibleCommit =
      GenerationCommitCoordinator();
  AuthRequestGeneration? _visibleGeneration;
  bool get isLogin => userName.isNotEmpty;
  String get displayNameOrUserName =>
      displayName.value.trim().isEmpty ? userName.value : displayName.value;
  String get accountLabelWithHandle {
    final username = userName.value.trim();
    if (username.isEmpty) {
      return '';
    }
    final preferred = displayName.value.trim();
    if (preferred.isEmpty || preferred == username) {
      return username;
    }
    return '$preferred (@$username)';
  }

  WeakReference<FFI> parent;

  NativeAuthStartTicket claimNativeAuthStart() => _nativeAuthStartGate.claim();

  bool ownsNativeAuthStart(NativeAuthStartTicket ticket) =>
      _nativeAuthStartGate.owns(ticket);

  void releaseNativeAuthStart(NativeAuthStartTicket ticket) =>
      _nativeAuthStartGate.release(ticket);

  Future<String?> beginNativeLogin(NativeAuthStartTicket ticket) {
    return _nativeAuthStartGate.run<String>(
      ticket: ticket,
      begin: () => bind.mainAuthBeginLogin(),
      cancel: (attemptJson) =>
          bind.mainAuthCancelAttempt(attemptJson: attemptJson),
    );
  }

  Future<String?> beginNativeOidc(
    NativeAuthStartTicket ticket, {
    required String op,
    required bool rememberMe,
  }) {
    if (isWeb) {
      if (!_nativeAuthStartGate.owns(ticket)) {
        return Future<String?>.value();
      }
      // Safari 要求弹窗仍处于原始手势栈内，因此 Web 必须同步调用旧 JS
      // account_auth；结果返回后仍以同一 gate ticket 做迟到检查。
      final pending = bind.mainAccountAuth(op: op, rememberMe: rememberMe);
      return pending.then((attemptJson) async {
        if (_nativeAuthStartGate.owns(ticket)) return attemptJson;
        await bind.mainAuthCancelAttempt(attemptJson: attemptJson);
        return null;
      });
    }
    return _nativeAuthStartGate.run<String>(
      ticket: ticket,
      begin: () => bind.mainAccountAuth(op: op, rememberMe: rememberMe),
      cancel: (attemptJson) =>
          bind.mainAuthCancelAttempt(attemptJson: attemptJson),
    );
  }

  Future<bool> isNativeAttemptCurrent(String? attemptJson) async {
    if (attemptJson == null || attemptJson.isEmpty) return false;
    try {
      final opaque = nativeAuthAttemptOpaqueFromValue(attemptJson);
      return await bind.mainAuthAttemptIsCurrent(attemptJson: opaque);
    } catch (_) {
      return false;
    }
  }

  Future<bool> cancelNativeAttempt(String? attemptJson) async {
    if (attemptJson == null || attemptJson.isEmpty) return false;
    try {
      final opaque = nativeAuthAttemptOpaqueFromValue(attemptJson);
      return await bind.mainAuthCancelAttempt(attemptJson: opaque);
    } catch (_) {
      return false;
    }
  }

  Future<bool> ackNativeAttempt(String? attemptJson) async {
    if (attemptJson == null || attemptJson.isEmpty) return false;
    try {
      final opaque = nativeAuthAttemptOpaqueFromValue(attemptJson);
      return await bind.mainAuthAckAttempt(attemptJson: opaque);
    } catch (_) {
      return false;
    }
  }

  UserModel(this.parent) {
    userName.listen((p0) {
      // When user name becomes empty, show login button
      // When user name becomes non-empty:
      //  For _updateLocalUserInfo, network error will be set later
      //  For login success, should clear network error
      networkError.value = '';
    });
    if (!isWeb && desktopType == DesktopType.main) {
      platformFFI.registerEventHandler(
        'native_auth_cleared',
        'user_auth_generation',
        (event) async {
          if (!authClearedEventMatchesVisibleGeneration(
            event,
            visibleSessionEpoch: _visibleGeneration?.sessionEpoch,
            visibleSessionNonce: _visibleGeneration?.sessionNonce,
          )) {
            return;
          }
          await _clearVisibleUser(resetOther: true);
        },
      );
    }
  }

  void refreshCurrentUser() async {
    if (bind.isDisableAccount()) return;
    if (isWeb) {
      networkError.value = '';
      await _refreshCurrentWebUser();
      return;
    }
    if (refreshingUser) return;
    String? requestHandle;
    AuthRequestGeneration? requestGeneration;
    try {
      refreshingUser = true;
      final snapshot = await _nativeAuthSnapshot();
      final session = snapshot?['session'];
      if (session is! Map<String, dynamic>) {
        await _clearVisibleUser(resetOther: true);
        return;
      }
      final snapshotGeneration = authGenerationFromSnapshot(snapshot);
      if (snapshotGeneration == null) {
        await _clearVisibleUser(resetOther: true);
        return;
      }
      requestGeneration = snapshotGeneration;
      final safeUser = session['safe_user'];
      if (safeUser is! Map<String, dynamic>) {
        await _clearVisibleUser(resetOther: true);
        return;
      }
      final url = (session['normalized_api_base'] ?? '').toString();
      if (url.isEmpty) {
        await _clearVisibleUser(resetOther: true);
        return;
      }
      final uri = Uri.parse('$url/api/currentUser');
      requestHandle = await http.beginCredentialedRequest(uri);
      final handleGeneration =
          AuthRequestGeneration.fromHandleJson(requestHandle);
      if (!handleGeneration.sameAs(snapshotGeneration)) {
        await _clearVisibleGenerationIfOwned(snapshotGeneration);
        return;
      }
      requestGeneration = handleGeneration;
      final safeUserReceipt = await _commitVisibleUser(
        requestGeneration,
        UserPayload.fromJson(safeUser),
        resetOtherOnApply: false,
      );
      if (!_visibleCommit.owns(safeUserReceipt)) return;
      final id = await bind.mainGetMyId();
      final uuid = await bind.mainGetUuid();
      final body =
          id.isNotEmpty && uuid.isNotEmpty ? {'id': id, 'uuid': uuid} : {};
      final result = await http.postCredentialed(
        uri,
        handleJson: requestHandle,
        headers: {'Content-Type': 'application/json'},
        body: json.encode(body),
      );
      final response = result.response;
      final status = response.statusCode;
      if (status == 401) {
        final latest = await _nativeAuthSnapshot();
        if (latest?['session'] == null) {
          await _clearVisibleUser(resetOther: true);
        }
        return;
      }
      if (!await result.isCurrent()) return;
      if (status == 400) {
        throw RequestException(status, '请求参数无效');
      }
      final data = json.decode(decode_http_response(response));
      final error = data['error'];
      if (error != null) {
        throw error;
      }

      final user = UserPayload.fromJson(data);
      final userReceipt = await _commitVisibleUser(
        requestGeneration,
        user,
        resetOtherOnApply: false,
      );
      if (!_visibleCommit.owns(userReceipt)) return;
    } catch (e) {
      final generation = requestGeneration;
      if (generation == null) return;
      final errorReceipt = await _commitNetworkError(generation, e.toString());
      if (_visibleCommit.owns(errorReceipt)) {
        debugPrint('Failed to refreshCurrentUser: $e');
      }
    } finally {
      refreshingUser = false;
      final generation = requestGeneration;
      if (requestHandle != null &&
          generation != null &&
          await _isGenerationCurrent(generation) &&
          _visibleGeneration?.sameAs(generation) == true) {
        await updateOtherModels();
      }
    }
  }

  Future<Map<String, dynamic>?> _nativeAuthSnapshot() async {
    try {
      final decoded = jsonDecode(await bind.mainAuthSnapshot());
      return decoded is Map<String, dynamic> ? decoded : null;
    } catch (error) {
      debugPrint('读取 native 认证快照失败: $error');
      return null;
    }
  }

  Future<bool> _isGenerationCurrent(AuthRequestGeneration generation) async {
    final snapshot = await _nativeAuthSnapshot();
    final current = authGenerationFromSnapshot(snapshot);
    return current != null && current.sameAs(generation);
  }

  Future<bool> isNativeGenerationCurrent(
          AuthRequestGeneration generation) async =>
      _isGenerationCurrent(generation);

  Future<GenerationCommitReceipt?> _commitVisibleUser(
    AuthRequestGeneration generation,
    UserPayload user, {
    required bool resetOtherOnApply,
  }) async {
    final receipt = await _visibleCommit.commit<UserPayload>(
      generation: generation,
      isGenerationCurrent: _isGenerationCurrent,
      payload: user,
      apply: (payload) async {
        _visibleGeneration = generation;
        networkError.value = '';
        _parseAndUpdateUser(payload);
        if (resetOtherOnApply) {
          await Future.wait([
            gFFI.abModel.reset(),
            gFFI.groupModel.reset(),
          ]);
        }
      },
      rollback: (stillOwned) async {
        if (!stillOwned()) return;
        _clearVisibleUserFields();
        await gFFI.abModel.reset();
        if (!stillOwned()) return;
        await gFFI.groupModel.reset();
      },
    );
    if (receipt == null) {
      await _clearVisibleGenerationIfOwned(generation);
    }
    return receipt;
  }

  Future<GenerationCommitReceipt?> _commitNetworkError(
    AuthRequestGeneration generation,
    String error,
  ) async {
    final receipt = await _visibleCommit.commit<String>(
      generation: generation,
      isGenerationCurrent: _isGenerationCurrent,
      payload: error,
      apply: (value) => networkError.value = value,
      rollback: (stillOwned) {
        if (stillOwned()) {
          networkError.value = '';
        }
      },
    );
    if (receipt == null) {
      await _clearVisibleGenerationIfOwned(generation);
    }
    return receipt;
  }

  Future<void> _clearVisibleGenerationIfOwned(
      AuthRequestGeneration generation) async {
    if (_visibleGeneration?.sameAs(generation) != true) return;
    _visibleCommit.invalidate();
    _clearVisibleUserFields();
    final abReset = gFFI.abModel.reset();
    final groupReset = gFFI.groupModel.reset();
    await Future.wait([abReset, groupReset]);
  }

  Future<void> _refreshCurrentWebUser() async {
    final token = bind.mainGetLocalOption(key: 'access_token');
    if (token.isEmpty) {
      await updateOtherModels();
      return;
    }
    _updateLocalUserInfo();
    final url = await bind.mainGetApiServer();
    try {
      final response = await http.post(Uri.parse('$url/api/currentUser'),
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer $token'
          },
          body: jsonEncode({
            'id': await bind.mainGetMyId(),
            'uuid': await bind.mainGetUuid()
          }));
      if (response.statusCode == 401) {
        await reset(resetOther: true);
        return;
      }
      if (response.statusCode != 200) {
        throw RequestException(response.statusCode, '');
      }
      _parseAndUpdateUser(
          UserPayload.fromJson(jsonDecode(decode_http_response(response))));
    } catch (error) {
      networkError.value = error.toString();
      debugPrint('刷新 Web 用户失败: $error');
    } finally {
      await updateOtherModels();
    }
  }

  static Map<String, dynamic>? getLocalUserInfo() {
    if (!isWeb) {
      return null;
    }
    final userInfo = bind.mainGetLocalOption(key: 'user_info');
    if (userInfo == '') {
      return null;
    }
    try {
      return json.decode(userInfo);
    } catch (e) {
      debugPrint('Failed to get local user info "$userInfo": $e');
    }
    return null;
  }

  _updateLocalUserInfo() {
    final userInfo = getLocalUserInfo();
    if (userInfo != null) {
      userName.value = (userInfo['name'] ?? '').toString();
      displayName.value = (userInfo['display_name'] ?? '').toString();
      avatar.value = (userInfo['avatar'] ?? '').toString();
    }
  }

  Future<void> reset({bool resetOther = false}) async {
    if (isWeb) {
      await bind.mainSetLocalOption(key: 'access_token', value: '');
      await bind.mainSetLocalOption(key: 'user_info', value: '');
    }
    await _clearVisibleUser(resetOther: resetOther);
  }

  Future<void> _clearVisibleUser({required bool resetOther}) async {
    _visibleCommit.invalidate();
    _clearVisibleUserFields();
    if (resetOther) {
      final abReset = gFFI.abModel.reset();
      final groupReset = gFFI.groupModel.reset();
      await Future.wait([abReset, groupReset]);
    }
  }

  void _clearVisibleUserFields() {
    _visibleGeneration = null;
    networkError.value = '';
    userName.value = '';
    displayName.value = '';
    avatar.value = '';
    isAdmin.value = false;
  }

  _parseAndUpdateUser(UserPayload user, {bool persistWeb = true}) {
    userName.value = user.name;
    displayName.value = user.displayName;
    avatar.value = user.avatar;
    isAdmin.value = user.isAdmin;
    if (isWeb && persistWeb) {
      bind.mainSetLocalOption(key: 'user_info', value: jsonEncode(user));
      // ugly here, tmp solution
      bind.mainSetLocalOption(key: 'verifier', value: user.verifier ?? '');
    }
  }

  // update ab and group status
  static Future<void> updateOtherModels() async {
    await Future.wait([
      gFFI.abModel.pullAb(force: ForcePullAb.listAndCurrent, quiet: false),
      gFFI.groupModel.pull()
    ]);
  }

  Future<void> logOut({String? apiServer}) async {
    final tag = gFFI.dialogManager.showLoading(translate('Waiting'));
    try {
      final id = await bind.mainGetMyId();
      final uuid = await bind.mainGetUuid();
      if (isWeb) {
        final url = apiServer ?? await bind.mainGetApiServer();
        final authHeaders = getHttpHeaders();
        authHeaders['Content-Type'] = 'application/json';
        await http
            .post(Uri.parse('$url/api/logout'),
                body: jsonEncode({'id': id, 'uuid': uuid}),
                headers: authHeaders)
            .timeout(const Duration(seconds: 2));
      } else {
        await bind
            .mainAuthLogout(deviceId: id, deviceUuid: uuid)
            .timeout(const Duration(seconds: 10));
      }
    } catch (e) {
      if (isWeb) {
        debugPrint("request /api/logout failed: err=$e");
      } else {
        debugPrint('native 远端注销未完成，将在后台重试');
      }
    } finally {
      if (!isWeb) {
        platformFFI.schedulePendingLogoutRetries();
      }
      await reset(resetOther: true);
      gFFI.dialogManager.dismissByTag(tag);
    }
  }

  /// throw [RequestException]
  Future<LoginResponse> login(
    LoginRequest loginRequest, {
    Future<String?>? nativeAttemptFuture,
  }) async {
    if (!isWeb) {
      var attemptJson = loginRequest.nativeAttemptJson;
      if (attemptJson == null) {
        if (nativeAttemptFuture == null) {
          final ticket = claimNativeAuthStart();
          nativeAttemptFuture = beginNativeLogin(ticket);
        }
        attemptJson = await nativeAttemptFuture;
        if (attemptJson == null) {
          throw const StaleAuthGenerationException();
        }
      }
      attemptJson = nativeAuthAttemptOpaqueFromValue(attemptJson);
      if (!await isNativeAttemptCurrent(attemptJson)) {
        throw const StaleAuthGenerationException();
      }

      try {
        final resultJson = await bind.mainAuthStrictLoginAndCommit(
          attemptJson: attemptJson,
          loginBody: jsonEncode(loginRequest.toJson()),
        );
        final decoded = jsonDecode(resultJson);
        if (decoded is! Map<String, dynamic>) {
          throw const FormatException('登录响应格式无效');
        }
        final responseAttempt =
            nativeAuthAttemptOpaqueFromValue(decoded['native_attempt']);
        if (!nativeAuthAttemptsMatch(attemptJson, responseAttempt)) {
          throw const StaleAuthGenerationException();
        }
        final status = decoded['status'] is int ? decoded['status'] as int : 0;
        switch (decoded['kind']) {
          case 'authenticated':
            final user = decoded['user'];
            if (user is! Map<String, dynamic>) {
              throw const FormatException('登录用户字段无效');
            }
            final payload = UserPayload.fromJson(user);
            final generation = AuthRequestGeneration.fromMap(decoded);
            return LoginResponse(
              type: HttpType.kAuthResTypeToken,
              user: payload,
              committed: true,
              normalizedApiBase: generation.normalizedApiBase,
              namespace: generation.namespace,
              cursorKey: generation.cursorKey,
              sessionEpoch: generation.sessionEpoch,
              sessionNonce: generation.sessionNonce,
              nativeAttemptJson: responseAttempt,
            );
          case 'challenge':
            if (!await isNativeAttemptCurrent(attemptJson)) {
              throw const StaleAuthGenerationException();
            }
            final challengeUser = decoded['user'];
            return LoginResponse(
              type: decoded['challenge_type'] as String?,
              tfa_type: decoded['tfa_type'] as String?,
              secret: decoded['secret'] as String?,
              user: challengeUser is Map<String, dynamic>
                  ? UserPayload.fromJson(challengeUser)
                  : null,
              nativeAttemptJson: responseAttempt,
            );
          default:
            if (!await isNativeAttemptCurrent(attemptJson)) {
              throw const StaleAuthGenerationException();
            }
            final recoverable = decoded['kind'] != 'protocol_error';
            throw RequestException(
              status,
              (decoded['message'] ?? '登录失败').toString(),
              nativeAttemptJson: responseAttempt,
              recoverable: recoverable,
            );
        }
      } on StaleAuthGenerationException {
        rethrow;
      } on RequestException {
        rethrow;
      } catch (_) {
        if (!await isNativeAttemptCurrent(attemptJson)) {
          throw const StaleAuthGenerationException();
        }
        throw RequestException(
          0,
          '登录响应无效，请重试',
          nativeAttemptJson: attemptJson,
          recoverable: false,
        );
      }
    }

    String? webAttemptJson;
    if (loginRequest.nativeAttemptJson != null) {
      webAttemptJson =
          nativeAuthAttemptOpaqueFromValue(loginRequest.nativeAttemptJson);
      if (!await isNativeAttemptCurrent(webAttemptJson)) {
        throw const StaleAuthGenerationException();
      }
    }
    final url = await bind.mainGetApiServer();
    if (webAttemptJson != null &&
        !await isNativeAttemptCurrent(webAttemptJson)) {
      throw const StaleAuthGenerationException();
    }
    final resp = await http.post(Uri.parse('$url/api/login'),
        body: jsonEncode(loginRequest.toJson()));
    if (webAttemptJson != null &&
        !await isNativeAttemptCurrent(webAttemptJson)) {
      throw const StaleAuthGenerationException();
    }

    final Map<String, dynamic> body;
    try {
      body = jsonDecode(decode_http_response(resp));
    } catch (e) {
      debugPrint("login: jsonDecode resp body failed: ${e.toString()}");
      if (resp.statusCode != 200) {
        BotToast.showText(
            contentColor: Colors.red, text: 'HTTP ${resp.statusCode}');
      }
      rethrow;
    }
    if (resp.statusCode != 200) {
      throw RequestException(resp.statusCode, body['error'] ?? '');
    }
    if (body['error'] != null) {
      throw RequestException(0, body['error']);
    }
    if (webAttemptJson != null) {
      body['native_attempt'] = webAttemptJson;
    }

    return await getLoginResponseFromAuthBody(body);
  }

  Future<LoginResponse> getLoginResponseFromAuthBody(
      Map<String, dynamic> body) async {
    final LoginResponse loginResponse;
    try {
      loginResponse = LoginResponse.fromJson(body);
    } catch (e) {
      debugPrint("login: jsonDecode LoginResponse failed: ${e.toString()}");
      rethrow;
    }

    final isLogInDone = loginResponse.type == HttpType.kAuthResTypeToken &&
        (loginResponse.committed || loginResponse.access_token != null);
    if (isLogInDone && loginResponse.user != null) {
      if (isWeb && loginResponse.nativeAttemptJson == null) {
        _parseAndUpdateUser(loginResponse.user!);
      }
    } else if (!isWeb) {
      final attemptJson = loginResponse.nativeAttemptJson;
      if (attemptJson == null || !await isNativeAttemptCurrent(attemptJson)) {
        throw const StaleAuthGenerationException();
      }
    }

    return loginResponse;
  }

  Future<void> acceptWebLoginResponse(
    LoginResponse response, {
    required bool storeAccessToken,
  }) async {
    if (!isWeb || response.access_token == null || response.user == null) {
      throw const StaleAuthGenerationException();
    }
    // 先写用户，再发布 token/Rx；即使存储失败，也不会留下“只有 token”
    // 的半登录状态。旧 Web OIDC 自行保存 token 时同样先补齐 user_info。
    await bind.mainSetLocalOption(
        key: 'user_info', value: jsonEncode(response.user!));
    if (storeAccessToken) {
      await bind.mainSetLocalOption(
          key: 'access_token', value: response.access_token!);
    }
    // durable Web 缓存完成后再同步 Rx；ACK 后即使对话框被移除，
    // 这段全局收口也不会被局部 owner 截断。
    _parseAndUpdateUser(response.user!, persistWeb: false);
  }

  Future<void> acceptNativeCommittedLogin(LoginResponse response) async {
    if (isWeb ||
        !response.committed ||
        response.type != HttpType.kAuthResTypeToken ||
        response.user == null) {
      throw const StaleAuthGenerationException();
    }
    final generation = AuthRequestGeneration(
      normalizedApiBase: response.normalizedApiBase!,
      namespace: response.namespace!,
      cursorKey: response.cursorKey!,
      sessionEpoch: response.sessionEpoch!,
      sessionNonce: response.sessionNonce!,
    );
    final receipt = await _commitVisibleUser(
      generation,
      response.user!,
      resetOtherOnApply: true,
    );
    if (!_visibleCommit.owns(receipt)) {
      throw const StaleAuthGenerationException();
    }
  }

  bool isVisibleLoginResponseCurrent(LoginResponse response) {
    if (isWeb) {
      return response.access_token != null && isLogin;
    }
    try {
      final generation = AuthRequestGeneration(
        normalizedApiBase: response.normalizedApiBase!,
        namespace: response.namespace!,
        cursorKey: response.cursorKey!,
        sessionEpoch: response.sessionEpoch!,
        sessionNonce: response.sessionNonce!,
      );
      return response.committed &&
          isLogin &&
          _visibleGeneration?.sameAs(generation) == true;
    } catch (_) {
      return false;
    }
  }

  static Future<List<dynamic>> queryOidcLoginOptions() async {
    try {
      final url = await bind.mainGetApiServer();
      if (url.trim().isEmpty) return [];
      final resp = await http.get(Uri.parse('$url/api/login-options'));
      final List<String> ops = [];
      for (final item in jsonDecode(resp.body)) {
        ops.add(item as String);
      }
      for (final item in ops) {
        if (item.startsWith('common-oidc/')) {
          return jsonDecode(item.substring('common-oidc/'.length));
        }
      }
      return ops
          .where((item) => item.startsWith('oidc/'))
          .map((item) => {'name': item.substring('oidc/'.length)})
          .toList();
    } catch (e) {
      debugPrint(
          "queryOidcLoginOptions: jsonDecode resp body failed: ${e.toString()}");
      return [];
    }
  }
}
