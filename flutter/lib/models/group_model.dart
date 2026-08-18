import 'package:flutter/widgets.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/hbbs/hbbs.dart';
import 'package:flutter_hbb/common/widgets/peers_view.dart';
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/models/peer_model.dart';
import 'package:flutter_hbb/models/platform_model.dart';
import 'package:flutter_hbb/models/state_generation_guard.dart';
import 'package:get/get.dart';
import 'dart:convert';
import '../utils/http_service.dart' as http;

class _GroupPullRequest {
  final String apiBase;
  String? handleJson;
  AuthRequestGeneration? generation;
  String? generationKey;
  String? authNamespace;
  http.StrictHttpResult? requestContext;
  int statusCode = 200;
  bool stale = false;
  bool unauthorized = false;

  _GroupPullRequest(this.apiBase);

  Future<void> begin() async {
    if (isWeb) return;
    handleJson = await http.beginCredentialedRequest(
        Uri.parse('$apiBase/api/device-group/accessible'));
    generation = AuthRequestGeneration.fromHandleJson(handleJson!);
    authNamespace = generation!.cursorKey;
    generationKey = generation!.key;
  }

  Future<bool> isCurrent() async {
    if (isWeb) return true;
    final handle = handleJson;
    if (handle == null || stale) return false;
    try {
      return await http.isCredentialedRequestCurrent(handle);
    } catch (_) {
      return false;
    }
  }

  Future<http.Response> get(Uri uri) async {
    if (isWeb) {
      return await http.get(uri, headers: getHttpHeaders());
    }
    final http.StrictHttpResult result;
    if (requestContext == null) {
      result = await http.getCredentialed(uri, handleJson: handleJson);
      requestContext = result;
    } else {
      result = await http.getCredentialed(uri, requestContext: requestContext);
    }
    statusCode = result.response.statusCode;
    if (statusCode == 401) {
      unauthorized = true;
      return result.response;
    }
    if (!await result.isCurrent()) {
      stale = true;
      throw StateError('认证请求已失效');
    }
    return result.response;
  }
}

class _GroupVisibleState {
  final AuthRequestGeneration? generation;
  final List<DeviceGroupPayload> deviceGroups;
  final List<UserPayload> users;
  final List<Peer> peers;
  final String currentUserName;
  final Set<String> onlinePeerIds;
  final bool initialized;

  const _GroupVisibleState({
    required this.generation,
    required this.deviceGroups,
    required this.users,
    required this.peers,
    required this.currentUserName,
    required this.onlinePeerIds,
    required this.initialized,
  });
}

class GroupModel {
  final RxBool groupLoading = false.obs;
  final RxString groupLoadError = "".obs;
  final RxList<DeviceGroupPayload> deviceGroups = RxList.empty(growable: true);
  final RxList<UserPayload> users = RxList.empty(growable: true);
  final RxList<Peer> peers = RxList.empty(growable: true);
  final RxBool isSelectedDeviceGroup = false.obs;
  final RxString selectedAccessibleItemName = ''.obs;
  final RxString searchAccessibleItemNameText = ''.obs;
  WeakReference<FFI> parent;
  var initialized = false;
  var _cacheLoadOnceFlag = false;
  var _pulling = false;
  var _stateRevision = 0;
  var _cacheSaveSequence = 0;
  final GenerationCommitCoordinator _visibleCommit =
      GenerationCommitCoordinator();
  AuthRequestGeneration? _visibleGeneration;
  String? _cacheGenerationHandle;
  String? _cacheAuthNamespace;
  final Map<String, VoidCallback> _peerIdUpdateListeners = {};

  bool get emtpy => deviceGroups.isEmpty && users.isEmpty && peers.isEmpty;

  late final Peers peersModel;

  GroupModel(this.parent) {
    peersModel = Peers(
        name: PeersModelName.group,
        getInitPeers: () => peers,
        loadEvent: LoadEvent.group);
  }

  Future<void> pull({force = true, quiet = false}) async {
    if (bind.isDisableGroupPanel()) return;
    if (!gFFI.userModel.isLogin || _pulling) return;
    if (!force && initialized) return;
    _pulling = true;
    try {
      if (!quiet) {
        groupLoading.value = true;
        groupLoadError.value = "";
      }
      final request = _GroupPullRequest(await bind.mainGetApiServer());
      GenerationCommitReceipt? pullReceipt;
      try {
        await request.begin();
        pullReceipt = await _pull(request);
        if (_visibleCommit.owns(pullReceipt) &&
            !request.unauthorized &&
            await request.isCurrent() &&
            _visibleCommit.owns(pullReceipt)) {
          _tryHandlePullError();
        }
      } catch (e) {
        if (await request.isCurrent()) {
          debugPrint("pull accessibles error: $e");
        }
      }
      if (request.unauthorized) {
        if (await _nativeSessionAbsent()) {
          await gFFI.userModel.reset(resetOther: true);
        }
        return;
      }
      if (!_visibleCommit.owns(pullReceipt)) return;
      _cacheGenerationHandle = request.handleJson;
      _cacheAuthNamespace = request.authNamespace;
      platformFFI.tryHandle({'name': LoadEvent.group});
      if (!_visibleCommit.owns(pullReceipt) ||
          !await request.isCurrent() ||
          !_visibleCommit.owns(pullReceipt)) {
        return;
      }
      await _saveCache(request);
    } finally {
      groupLoading.value = false;
      _pulling = false;
    }
  }

  Future<GenerationCommitReceipt?> _pull(_GroupPullRequest request) async {
    List<DeviceGroupPayload> tmpDeviceGroups = List.empty(growable: true);
    if (!await _getDeviceGroups(request, tmpDeviceGroups)) {
      // old hbbs doesn't support this api
      // return;
    }
    if (request.unauthorized || !await request.isCurrent()) return null;
    tmpDeviceGroups.sort((a, b) => a.name.compareTo(b.name));
    List<UserPayload> tmpUsers = List.empty(growable: true);
    if (!await _getUsers(request, tmpUsers)) {
      return null;
    }
    List<Peer> tmpPeers = List.empty(growable: true);
    if (!await _getPeers(request, tmpPeers)) {
      return null;
    }
    final state = _GroupVisibleState(
      generation: request.generation,
      deviceGroups: tmpDeviceGroups,
      users: tmpUsers,
      peers: tmpPeers,
      currentUserName: gFFI.userModel.userName.value,
      onlinePeerIds:
          peers.where((peer) => peer.online).map((peer) => peer.id).toSet(),
      initialized: true,
    );
    if (isWeb) {
      return _visibleCommit.replaceLocal(state, _applyVisibleState);
    }
    final generation = request.generation;
    if (generation == null) return null;
    final receipt = await _visibleCommit.commit<_GroupVisibleState>(
      generation: generation,
      isGenerationCurrent: (expected) async =>
          request.generation?.sameAs(expected) == true &&
          await request.isCurrent(),
      payload: state,
      apply: _applyVisibleState,
      rollback: (stillOwned) {
        if (stillOwned()) {
          _clearVisibleState();
        }
      },
    );
    if (receipt == null) {
      await _clearVisibleGenerationIfOwned(generation);
    }
    return receipt;
  }

  void _applyVisibleState(_GroupVisibleState state) {
    _visibleGeneration = state.generation;
    final nextUsers = state.users.toList(growable: true);
    deviceGroups.value = state.deviceGroups;
    // me first
    final index =
        nextUsers.indexWhere((user) => user.name == state.currentUserName);
    if (index != -1) {
      final user = nextUsers.removeAt(index);
      nextUsers.insert(0, user);
    }
    users.value = nextUsers;
    if (!users.any((u) => u.name == selectedAccessibleItemName.value) &&
        !deviceGroups.any((d) => d.name == selectedAccessibleItemName.value)) {
      selectedAccessibleItemName.value = '';
    }
    // recover online
    peers.value = state.peers;
    peers
        .where((peer) => state.onlinePeerIds.contains(peer.id))
        .map((e) => e.online = true)
        .toList();
    groupLoadError.value = '';
    initialized = state.initialized;
    _stateRevision += 1;
    _cacheGenerationHandle = null;
    _cacheAuthNamespace = null;
    _callbackPeerUpdate();
  }

  void _clearVisibleState() {
    _visibleGeneration = null;
    initialized = false;
    groupLoadError.value = '';
    deviceGroups.clear();
    users.clear();
    peers.clear();
    selectedAccessibleItemName.value = '';
    _cacheGenerationHandle = null;
    _cacheAuthNamespace = null;
    _stateRevision += 1;
  }

  Future<void> _clearVisibleGenerationIfOwned(
      AuthRequestGeneration generation) async {
    if (_visibleGeneration?.sameAs(generation) != true) return;
    await reset();
  }

  Future<GenerationCommitReceipt?> _commitVisibleError(
    _GroupPullRequest request,
    String error,
  ) async {
    if (isWeb) {
      return _visibleCommit.replaceLocal<String>(
        error,
        (value) => groupLoadError.value = value,
      );
    }
    final generation = request.generation;
    if (generation == null) return null;
    final receipt = await _visibleCommit.commit<String>(
      generation: generation,
      isGenerationCurrent: (expected) async =>
          request.generation?.sameAs(expected) == true &&
          await request.isCurrent(),
      payload: error,
      apply: (value) => groupLoadError.value = value,
      rollback: (stillOwned) {
        if (stillOwned()) {
          groupLoadError.value = '';
        }
      },
    );
    if (receipt == null) {
      await _clearVisibleGenerationIfOwned(generation);
    }
    return receipt;
  }

  Future<bool> _getDeviceGroups(_GroupPullRequest request,
      List<DeviceGroupPayload> tmpDeviceGroups) async {
    final api = "${request.apiBase}/api/device-group/accessible";
    try {
      var uri0 = Uri.parse(api);
      final pageSize = 100;
      var total = 0;
      int current = 0;
      do {
        current += 1;
        var uri = Uri(
            scheme: uri0.scheme,
            host: uri0.host,
            path: uri0.path,
            port: uri0.port,
            queryParameters: {
              'current': current.toString(),
              'pageSize': pageSize.toString(),
            });
        final resp = await request.get(uri);
        Map<String, dynamic> json =
            _jsonDecodeResp(decode_http_response(resp), resp.statusCode);
        if (json.containsKey('error')) {
          throw json['error'];
        }
        if (resp.statusCode != 200) {
          throw 'HTTP ${resp.statusCode}';
        }
        if (json.containsKey('total')) {
          if (total == 0) total = json['total'];
          if (json.containsKey('data')) {
            final data = json['data'];
            if (data is List) {
              for (final user in data) {
                final u = DeviceGroupPayload.fromJson(user);
                int index = tmpDeviceGroups.indexWhere((e) => e.name == u.name);
                if (index < 0) {
                  tmpDeviceGroups.add(u);
                } else {
                  tmpDeviceGroups[index] = u;
                }
              }
            }
          }
        }
      } while (current * pageSize < total);
      return true;
    } catch (err) {
      if (!await request.isCurrent() || request.unauthorized) return false;
      debugPrint('get accessible device groups: $err');
      // old hbbs doesn't support this api
      // groupLoadError.value =
      //     '${translate('pull_group_failed_tip')}: ${translate(err.toString())}';
    }
    return false;
  }

  Future<bool> _getUsers(
      _GroupPullRequest request, List<UserPayload> tmpUsers) async {
    final api = "${request.apiBase}/api/users";
    try {
      var uri0 = Uri.parse(api);
      final pageSize = 100;
      var total = 0;
      int current = 0;
      do {
        current += 1;
        var uri = Uri(
            scheme: uri0.scheme,
            host: uri0.host,
            path: uri0.path,
            port: uri0.port,
            queryParameters: {
              'current': current.toString(),
              'pageSize': pageSize.toString(),
              'accessible': '',
              'status': '1',
            });
        final resp = await request.get(uri);
        Map<String, dynamic> json =
            _jsonDecodeResp(decode_http_response(resp), resp.statusCode);
        if (json.containsKey('error')) {
          if (json['error'] == 'Admin required!' ||
              json['error']
                  .toString()
                  .contains('ambiguous column name: status')) {
            throw translate('upgrade_rustdesk_server_pro_to_{1.1.10}_tip');
          } else {
            throw json['error'];
          }
        }
        if (resp.statusCode != 200) {
          throw 'HTTP ${resp.statusCode}';
        }
        if (json.containsKey('total')) {
          if (total == 0) total = json['total'];
          if (json.containsKey('data')) {
            final data = json['data'];
            if (data is List) {
              for (final user in data) {
                final u = UserPayload.fromJson(user);
                int index = tmpUsers.indexWhere((e) => e.name == u.name);
                if (index < 0) {
                  tmpUsers.add(u);
                } else {
                  tmpUsers[index] = u;
                }
              }
            }
          }
        }
      } while (current * pageSize < total);
      return true;
    } catch (err) {
      if (request.unauthorized) return false;
      final receipt = await _commitVisibleError(request,
          '${translate('pull_group_failed_tip')}: ${translate(err.toString())}');
      if (_visibleCommit.owns(receipt)) {
        debugPrint('get accessible users: $err');
      }
    }
    return false;
  }

  Future<bool> _getPeers(_GroupPullRequest request, List<Peer> tmpPeers) async {
    try {
      final api = "${request.apiBase}/api/peers";
      var uri0 = Uri.parse(api);
      final pageSize = 100;
      var total = 0;
      int current = 0;
      do {
        current += 1;
        var queryParameters = {
          'current': current.toString(),
          'pageSize': pageSize.toString(),
          'accessible': '',
          'status': '1',
        };
        var uri = Uri(
            scheme: uri0.scheme,
            host: uri0.host,
            path: uri0.path,
            port: uri0.port,
            queryParameters: queryParameters);
        final resp = await request.get(uri);

        Map<String, dynamic> json =
            _jsonDecodeResp(decode_http_response(resp), resp.statusCode);
        if (json.containsKey('error')) {
          throw json['error'];
        }
        if (resp.statusCode != 200) {
          throw 'HTTP ${resp.statusCode}';
        }
        if (json.containsKey('total')) {
          if (total == 0) total = json['total'];
          if (json.containsKey('data')) {
            final data = json['data'];
            if (data is List) {
              for (final p in data) {
                final peerPayload = PeerPayload.fromJson(p);
                final peer = PeerPayload.toPeer(peerPayload);
                int index = tmpPeers.indexWhere((e) => e.id == peer.id);
                if (index < 0) {
                  tmpPeers.add(peer);
                } else {
                  tmpPeers[index] = peer;
                }
              }
            }
          }
        }
      } while (current * pageSize < total);
      return true;
    } catch (err) {
      if (request.unauthorized) return false;
      final receipt = await _commitVisibleError(request,
          '${translate('pull_group_failed_tip')}: ${translate(err.toString())}');
      if (_visibleCommit.owns(receipt)) {
        debugPrint('get accessible peers: $err');
      }
    }
    return false;
  }

  Future<bool> _nativeSessionAbsent() async {
    if (isWeb) return false;
    try {
      final snapshot = jsonDecode(await bind.mainAuthSnapshot());
      return snapshot is Map<String, dynamic> && snapshot['session'] == null;
    } catch (_) {
      return false;
    }
  }

  Map<String, dynamic> _jsonDecodeResp(String body, int statusCode) {
    try {
      Map<String, dynamic> json = jsonDecode(body);
      return json;
    } catch (e) {
      final err = body.isNotEmpty && body.length < 128 ? body : e.toString();
      if (statusCode != 200) {
        throw 'HTTP $statusCode, $err';
      }
      throw err;
    }
  }

  Future<bool> _saveCache(_GroupPullRequest request) async {
    final saveSequence = ++_cacheSaveSequence;
    final stateRevision = _stateRevision;
    final generationKey = request.generationKey;
    final generationHandle = request.handleJson;
    final entriesJson = jsonEncode(<String, dynamic>{
      "device_groups":
          deviceGroups.map((e) => e.toGroupCacheJson()).toList(growable: false),
      "users": users.map((e) => e.toGroupCacheJson()).toList(growable: false),
      'peers': peers.map((e) => e.toGroupCacheJson()).toList(growable: false),
    });
    try {
      var namespace = request.authNamespace;
      namespace ??= await getAuthCacheNamespace();
      if (namespace == null) return false;
      final frozenEntries = jsonDecode(entriesJson) as Map<String, dynamic>;
      final payload = jsonEncode(<String, dynamic>{
        "auth_namespace": namespace,
        ...frozenEntries,
      });
      final stateGuard = StateGenerationGuard(
        sameState: () =>
            _cacheSaveSequence == saveSequence &&
            _stateRevision == stateRevision &&
            request.generationKey == generationKey &&
            request.handleJson == generationHandle,
        sameGeneration: () async {
          if (isWeb) {
            return await getAuthCacheNamespace() == namespace;
          }
          return generationKey != null &&
              generationHandle != null &&
              await request.isCurrent();
        },
      );
      var nativeSaved = true;
      final committed = await stateGuard.commitFrozen<String>(
        payload,
        (frozen) async {
          if (isWeb) {
            await bind.mainSaveGroup(json: frozen);
          } else {
            nativeSaved = await bind.mainAuthSaveGroupCacheIfCurrent(
              handleJson: generationHandle!,
              payloadJson: frozen,
            );
          }
        },
      );
      if (committed && nativeSaved) {
        _cacheGenerationHandle = generationHandle;
        _cacheAuthNamespace = namespace;
        return true;
      }
      return false;
    } catch (e) {
      debugPrint('group save:$e');
      return false;
    }
  }

  Future<void> loadCache() async {
    try {
      if (_cacheLoadOnceFlag || groupLoading.value || initialized) return;
      _cacheLoadOnceFlag = true;
      _GroupPullRequest? request;
      String? namespace;
      if (isWeb) {
        namespace = await getAuthCacheNamespace();
      } else {
        request = _GroupPullRequest(await bind.mainGetApiServer());
        await request.begin();
        namespace = request.authNamespace;
      }
      if (namespace == null) return;
      final cache = await bind.mainLoadGroup();
      if (groupLoading.value) return;
      final data = jsonDecode(cache);
      if (data is! Map<String, dynamic> ||
          data['auth_namespace'] != namespace) {
        return;
      }
      final nextDeviceGroups = <DeviceGroupPayload>[];
      final nextUsers = <UserPayload>[];
      final nextPeers = <Peer>[];
      if (data['device_groups'] is List) {
        for (var u in data['device_groups']) {
          nextDeviceGroups.add(DeviceGroupPayload.fromJson(u));
        }
      }
      if (data['users'] is List) {
        for (var u in data['users']) {
          nextUsers.add(UserPayload.fromJson(u));
        }
      }
      if (data['peers'] is List) {
        for (final peer in data['peers']) {
          nextPeers.add(Peer.fromJson(peer));
        }
      }
      final state = _GroupVisibleState(
        generation: request?.generation,
        deviceGroups: nextDeviceGroups,
        users: nextUsers,
        peers: nextPeers,
        currentUserName: gFFI.userModel.userName.value,
        onlinePeerIds: const <String>{},
        initialized: false,
      );
      final GenerationCommitReceipt? receipt;
      if (isWeb) {
        receipt = _visibleCommit.replaceLocal(state, _applyVisibleState);
      } else {
        final generation = request?.generation;
        if (request == null || generation == null) return;
        receipt = await _visibleCommit.commit<_GroupVisibleState>(
          generation: generation,
          isGenerationCurrent: (expected) async =>
              request!.generation?.sameAs(expected) == true &&
              await request.isCurrent(),
          payload: state,
          apply: _applyVisibleState,
          rollback: (stillOwned) {
            if (stillOwned()) {
              _clearVisibleState();
            }
          },
        );
        if (receipt == null) {
          await _clearVisibleGenerationIfOwned(generation);
        }
      }
      if (!_visibleCommit.owns(receipt)) return;
      _cacheGenerationHandle = request?.handleJson;
      _cacheAuthNamespace = namespace;
    } catch (e) {
      debugPrint("load group cache: $e");
    }
  }

  Future<void> reset() async {
    final namespaceToClear = cacheNamespaceForConditionalClear(
      rememberedNamespace: _cacheAuthNamespace,
      generationHandleJson: _cacheGenerationHandle,
    );
    _visibleCommit.invalidate();
    _cacheSaveSequence += 1;
    _cacheLoadOnceFlag = false;
    _clearVisibleState();
    if (isWeb) {
      await bind.mainClearGroup();
    } else if (namespaceToClear != null) {
      await bind.mainClearGroupIfNamespace(authNamespace: namespaceToClear);
    }
  }

  void _callbackPeerUpdate() {
    for (var listener in _peerIdUpdateListeners.values) {
      listener();
    }
  }

  void addPeerUpdateListener(String key, VoidCallback listener) {
    _peerIdUpdateListeners[key] = listener;
  }

  void removePeerUpdateListener(String key) {
    _peerIdUpdateListeners.remove(key);
  }

  void _tryHandlePullError() {
    String errorMessage = groupLoadError.value;
    // The error message is "Retrieving accessible devices is disabled."
    if (errorMessage.toLowerCase().contains('disabled')) {
      users.clear();
      peers.clear();
      deviceGroups.clear();
    }
  }
}
