import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/hbbs/hbbs.dart';
import 'package:flutter_hbb/common/widgets/peers_view.dart';
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/models/peer_model.dart';
import 'package:flutter_hbb/models/platform_model.dart';
import 'package:flutter_hbb/models/state_generation_guard.dart';
import 'package:get/get.dart';
import 'package:bot_toast/bot_toast.dart';

import '../utils/http_service.dart' as http;
import '../common.dart';

final syncAbOption = 'sync-ab-with-recent-sessions';
bool shouldSyncAb() {
  return bind.mainGetLocalOption(key: syncAbOption) == 'Y';
}

final sortAbTagsOption = 'sync-ab-tags';
bool shouldSortTags() {
  return bind.mainGetLocalOption(key: sortAbTagsOption) == 'Y';
}

final filterAbTagOption = 'filter-ab-by-intersection';
bool filterAbTagByIntersection() {
  return bind.mainGetLocalOption(key: filterAbTagOption) == 'Y';
}

const _personalAddressBookName = "My address book";
const _legacyAddressBookName = "Legacy address book";
const _issue9AddressBookName = "Server address book";
const _maxSafeInteger = 9007199254740991;

@visibleForTesting
bool shouldProbeIssue9AddressBook(int statusCode) =>
    statusCode == 404 || statusCode == 405;

@visibleForTesting
String parsePersonalAddressBookGuid(dynamic value) {
  if (value is! Map<String, dynamic>) {
    throw const FormatException('Invalid personal address-book response');
  }
  final guid = value['guid'];
  if (guid is! String || guid.trim().isEmpty) {
    throw const FormatException('Invalid personal address-book guid');
  }
  return guid.trim();
}

@visibleForTesting
bool sharedAddressBookCollidesWithPersonal({
  required String name,
  required String guid,
  required String? personalGuid,
}) =>
    name == _personalAddressBookName ||
    (personalGuid != null && guid == personalGuid);

const kUntagged = "Untagged";

int _issue9SafeInt(dynamic value, String field, {int min = 0}) {
  if (value is! int || value < min || value > _maxSafeInteger) {
    throw FormatException('Invalid $field');
  }
  return value;
}

String _issue9String(dynamic value, String field) {
  if (value is! String) {
    throw FormatException('Invalid $field');
  }
  return value;
}

bool _issue9HasControlCharacter(String value) => value.runes.any(
      (codePoint) =>
          codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f),
    );

String _issue9ScalarBoundedString(
  dynamic value,
  String field, {
  required int maxLength,
  bool allowEmpty = true,
}) {
  final result = _issue9String(value, field);
  if ((!allowEmpty && result.isEmpty) ||
      result.runes.length > maxLength ||
      _issue9HasControlCharacter(result)) {
    throw FormatException('Invalid $field');
  }
  return result;
}

String _issue9Utf8BoundedString(
  dynamic value,
  String field, {
  required int maxBytes,
}) {
  final result = _issue9String(value, field);
  if (utf8.encode(result).length > maxBytes ||
      _issue9HasControlCharacter(result)) {
    throw FormatException('Invalid $field');
  }
  return result;
}

String _issue9Platform(String os) {
  switch (os.toLowerCase()) {
    case 'windows':
      return kPeerPlatformWindows;
    case 'linux':
      return kPeerPlatformLinux;
    case 'macos':
      return kPeerPlatformMacOS;
    case 'android':
      return kPeerPlatformAndroid;
    default:
      return os;
  }
}

class Issue9AddressBookItem {
  final String deviceId;
  final String instanceId;
  final String alias;
  final String hostname;
  final String os;
  final String source;
  final String permission;
  final int? shareId;
  final int? sharedByUserId;
  final String? sharedByUsername;

  Issue9AddressBookItem._({
    required this.deviceId,
    required this.instanceId,
    required this.alias,
    required this.hostname,
    required this.os,
    required this.source,
    required this.permission,
    required this.shareId,
    required this.sharedByUserId,
    required this.sharedByUsername,
  });

  factory Issue9AddressBookItem.fromJson(dynamic value) {
    if (value is! Map<String, dynamic>) {
      throw const FormatException('Invalid address-book item');
    }
    final deviceId = _issue9ScalarBoundedString(
      value['device_id'],
      'device_id',
      maxLength: 100,
      allowEmpty: false,
    );
    final instanceId = _issue9String(value['instance_id'], 'instance_id');
    if (!RegExp(r'^[0-9a-f]{64}$').hasMatch(instanceId)) {
      throw const FormatException('Invalid instance_id');
    }
    final source = _issue9String(value['source'], 'source');
    final permission = _issue9String(value['permission'], 'permission');
    final shareId = value['share_id'] == null
        ? null
        : _issue9SafeInt(value['share_id'], 'share_id', min: 1);
    final sharedByUserId = value['shared_by_user_id'] == null
        ? null
        : _issue9SafeInt(value['shared_by_user_id'], 'shared_by_user_id',
            min: 1);
    final sharedByUsername = value['shared_by_username'] == null
        ? null
        : _issue9ScalarBoundedString(
            value['shared_by_username'],
            'shared_by_username',
            maxLength: 100,
            allowEmpty: false,
          );
    if (source == 'owned') {
      if (permission != 'full_control' ||
          shareId != null ||
          sharedByUserId != null ||
          sharedByUsername != null) {
        throw const FormatException('Invalid owned address-book item');
      }
    } else if (source == 'shared') {
      if ((permission != 'view_only' && permission != 'full_control') ||
          shareId == null ||
          sharedByUserId == null ||
          sharedByUsername is! String) {
        throw const FormatException('Invalid shared address-book item');
      }
    } else {
      throw const FormatException('Invalid address-book source');
    }
    return Issue9AddressBookItem._(
      deviceId: deviceId,
      instanceId: instanceId,
      alias: _issue9ScalarBoundedString(
        value['alias'],
        'alias',
        maxLength: 200,
      ),
      hostname: _issue9Utf8BoundedString(
        value['hostname'],
        'hostname',
        maxBytes: 200,
      ),
      os: _issue9Utf8BoundedString(
        value['os'],
        'os',
        maxBytes: 100,
      ),
      source: source,
      permission: permission,
      shareId: shareId,
      sharedByUserId: sharedByUserId,
      sharedByUsername: sharedByUsername,
    );
  }

  String get identity => '$deviceId\u0000$instanceId';

  Peer toPeer([Peer? previous]) {
    final keepLocal = previous?.addressBookInstanceId == instanceId;
    return Peer(
      id: deviceId,
      hash: '',
      password: '',
      username: keepLocal ? previous!.username : '',
      hostname: hostname,
      platform: _issue9Platform(os),
      alias: alias,
      tags: keepLocal ? previous!.tags.toList() : <dynamic>[],
      forceAlwaysRelay: false,
      rdpPort: '',
      rdpUsername: '',
      loginName: '',
      device_group_name: '',
      note: '',
      addressBookInstanceId: instanceId,
      addressBookSource: source,
      addressBookPermission: permission,
      addressBookShareId: shareId,
    );
  }
}

class Issue9FullPage {
  final int abVer;
  final int page;
  final int pageSize;
  final int total;
  final bool hasMore;
  final List<Issue9AddressBookItem> items;

  Issue9FullPage._(this.abVer, this.page, this.pageSize, this.total,
      this.hasMore, this.items);

  factory Issue9FullPage.fromJson(dynamic value) {
    if (value is! Map<String, dynamic> || value['mode'] != 'full') {
      throw const FormatException('Invalid full address-book response');
    }
    final rawItems = value['items'];
    if (rawItems is! List || value['has_more'] is! bool) {
      throw const FormatException('Invalid full address-book response');
    }
    return Issue9FullPage._(
      _issue9SafeInt(value['ab_ver'], 'ab_ver'),
      _issue9SafeInt(value['page'], 'page', min: 1),
      _issue9SafeInt(value['page_size'], 'page_size', min: 1),
      _issue9SafeInt(value['total'], 'total'),
      value['has_more'] as bool,
      rawItems.map(Issue9AddressBookItem.fromJson).toList(growable: false),
    );
  }
}

class Issue9Change {
  final int version;
  final String operation;
  final String deviceId;
  final String instanceId;
  final int? shareId;
  final Issue9AddressBookItem? item;

  Issue9Change._(this.version, this.operation, this.deviceId, this.instanceId,
      this.shareId, this.item);

  factory Issue9Change.fromJson(dynamic value) {
    if (value is! Map<String, dynamic>) {
      throw const FormatException('Invalid address-book change');
    }
    final version = _issue9SafeInt(value['version'], 'version', min: 1);
    final operation = _issue9String(value['operation'], 'operation');
    final deviceId = _issue9ScalarBoundedString(
      value['device_id'],
      'device_id',
      maxLength: 100,
      allowEmpty: false,
    );
    final instanceId = _issue9String(value['instance_id'], 'instance_id');
    if (!RegExp(r'^[0-9a-f]{64}$').hasMatch(instanceId)) {
      throw const FormatException('Invalid change instance_id');
    }
    final shareId = value['share_id'] == null
        ? null
        : _issue9SafeInt(value['share_id'], 'share_id', min: 1);
    if (operation == 'upsert') {
      final item = Issue9AddressBookItem.fromJson(value['item']);
      if (item.deviceId != deviceId ||
          item.instanceId != instanceId ||
          item.shareId != shareId) {
        throw const FormatException('Address-book change identity mismatch');
      }
      return Issue9Change._(
          version, operation, deviceId, instanceId, shareId, item);
    }
    if (operation == 'delete' && value['item'] == null) {
      return Issue9Change._(
          version, operation, deviceId, instanceId, shareId, null);
    }
    throw const FormatException('Invalid address-book change operation');
  }

  String get identity => '$deviceId\u0000$instanceId';
}

class Issue9PullResult {
  final List<Peer> peers;
  final http.StrictHttpResult request;
  final int target;

  const Issue9PullResult(this.peers, this.request, this.target);
}

class Issue9DeltaPage {
  final int abVer;
  final int nextAbVer;
  final int pageSize;
  final bool hasMore;
  final bool resetRequired;
  final List<Issue9Change> changes;

  Issue9DeltaPage._(this.abVer, this.nextAbVer, this.pageSize, this.hasMore,
      this.resetRequired, this.changes);

  factory Issue9DeltaPage.fromJson(dynamic value, int requestedCursor) {
    if (value is! Map<String, dynamic> ||
        value['mode'] != 'delta' ||
        value['has_more'] is! bool ||
        value['reset_required'] is! bool ||
        value['changes'] is! List) {
      throw const FormatException('Invalid delta address-book response');
    }
    final abVer = _issue9SafeInt(value['ab_ver'], 'ab_ver');
    final next = _issue9SafeInt(value['next_ab_ver'], 'next_ab_ver');
    final reset = value['reset_required'] as bool;
    final changes = (value['changes'] as List)
        .map(Issue9Change.fromJson)
        .toList(growable: false);
    var expected = reset ? 1 : requestedCursor + 1;
    for (final change in changes) {
      if (change.version != expected) {
        throw const FormatException('Non-contiguous address-book delta');
      }
      expected += 1;
    }
    if (changes.isNotEmpty && changes.last.version != next) {
      throw const FormatException('Invalid next_ab_ver');
    }
    if (changes.isEmpty && next != abVer) {
      throw const FormatException('Invalid empty delta cursor');
    }
    if (next > abVer || (value['has_more'] as bool) != (next < abVer)) {
      throw const FormatException('Invalid delta pagination');
    }
    return Issue9DeltaPage._(
      abVer,
      next,
      _issue9SafeInt(value['page_size'], 'page_size', min: 1),
      value['has_more'] as bool,
      reset,
      changes,
    );
  }
}

class Issue9AddressBookState {
  static List<Peer> replaceAll(
      Iterable<Issue9AddressBookItem> items, Iterable<Peer> previous) {
    final oldByIdentity = <String, Peer>{
      for (final peer in previous)
        if (peer.addressBookInstanceId != null)
          '${peer.id}\u0000${peer.addressBookInstanceId}': peer,
    };
    final seen = <String>{};
    final next = <Peer>[];
    for (final item in items) {
      if (!seen.add(item.identity)) {
        throw const FormatException('Duplicate address-book identity');
      }
      next.add(item.toPeer(oldByIdentity[item.identity]));
    }
    return next;
  }

  static List<Peer> applyDelta(Iterable<Peer> current, Issue9DeltaPage delta) {
    final byIdentity = <String, Peer>{
      for (final peer in current)
        if (peer.addressBookInstanceId != null)
          '${peer.id}\u0000${peer.addressBookInstanceId}': Peer.copy(peer),
    };
    for (final change in delta.changes) {
      if (change.operation == 'delete') {
        byIdentity.remove(change.identity);
      } else {
        byIdentity[change.identity] =
            change.item!.toPeer(byIdentity[change.identity]);
      }
    }
    final next = byIdentity.values.toList(growable: false);
    next.sort((a, b) {
      final byId = a.id.compareTo(b.id);
      if (byId != 0) return byId;
      return (a.addressBookInstanceId ?? '')
          .compareTo(b.addressBookInstanceId ?? '');
    });
    return next;
  }
}

enum ForcePullAb {
  listAndCurrent,
  current,
}

class AbRequestScope {
  static String? _activeGenerationKey;

  final String apiBase;
  String? handleJson;
  AuthRequestGeneration? generation;
  String? generationKey;
  String? normalizedApiBase;
  String? authNamespace;
  http.StrictHttpResult? requestContext;
  String? personalHashReceipt;
  bool stale = false;
  bool unauthorized = false;

  AbRequestScope._(this.apiBase);

  static Future<AbRequestScope> create(
      {String? apiBase, Uri? initialUri}) async {
    final base = apiBase ?? await bind.mainGetApiServer();
    final scope = AbRequestScope._(base);
    if (!isWeb) {
      scope.handleJson = await http
          .beginCredentialedRequest(initialUri ?? Uri.parse('$base/api/ab'));
      scope.generation =
          AuthRequestGeneration.fromHandleJson(scope.handleJson!);
      scope.generationKey = scope.generation!.key;
      scope.normalizedApiBase = scope.generation!.normalizedApiBase;
      scope.authNamespace = scope.generation!.cursorKey;
    } else {
      scope.normalizedApiBase = base;
    }
    return scope;
  }

  static void invalidateActiveGeneration() {
    _activeGenerationKey = null;
  }

  static bool isActiveGeneration(String? expected) {
    return isWeb ||
        (expected != null &&
            _activeGenerationKey != null &&
            expected == _activeGenerationKey);
  }

  static Future<bool> isHandleCurrent(String? handle) async {
    if (isWeb) return true;
    if (handle == null || handle.isEmpty) return false;
    try {
      return await http.isCredentialedRequestCurrent(handle);
    } catch (_) {
      return false;
    }
  }

  bool matchesGeneration(String? expected) {
    return isWeb ||
        (expected != null &&
            generationKey != null &&
            expected == generationKey);
  }

  Future<bool> isCurrent() async {
    if (isWeb) return true;
    final handle = handleJson;
    if (handle == null || stale || unauthorized) return false;
    return await isHandleCurrent(handle);
  }

  Future<bool> activateGenerationIfCurrent() async {
    if (isWeb) return true;
    if (generationKey == null || !await isCurrent()) return false;
    _activeGenerationKey = generationKey;
    return true;
  }

  Future<bool> confirmCapability(
    String capability, {
    bool forceFullPending = false,
  }) async {
    if (isWeb) return true;
    final handle = handleJson;
    if (handle == null || !await isCurrent()) return false;
    try {
      return await bind.mainAuthSetAddressBookCapability(
        handleJson: handle,
        capability: capability,
        forceFullPending: forceFullPending,
      );
    } catch (_) {
      return false;
    }
  }

  Future<http.Response> send(
    http.HttpMethod method,
    Uri uri, {
    Map<String, String>? headers,
    Object? body,
  }) async {
    if (isWeb) {
      final requestHeaders = <String, String>{
        ...getHttpHeaders(),
        ...?headers,
      };
      switch (method) {
        case http.HttpMethod.get:
          return await http.get(uri, headers: requestHeaders);
        case http.HttpMethod.post:
          return await http.post(uri, headers: requestHeaders, body: body);
        case http.HttpMethod.put:
          return await http.put(uri, headers: requestHeaders, body: body);
        case http.HttpMethod.delete:
          return await http.delete(uri, headers: requestHeaders, body: body);
      }
    }

    final http.StrictHttpResult result;
    if (requestContext == null) {
      switch (method) {
        case http.HttpMethod.get:
          result = await http.getCredentialed(uri,
              headers: headers, handleJson: handleJson);
          break;
        case http.HttpMethod.post:
          result = await http.postCredentialed(uri,
              headers: headers, body: body, handleJson: handleJson);
          break;
        case http.HttpMethod.put:
          result = await http.putCredentialed(uri,
              headers: headers, body: body, handleJson: handleJson);
          break;
        case http.HttpMethod.delete:
          result = await http.deleteCredentialed(uri,
              headers: headers, body: body, handleJson: handleJson);
          break;
      }
      requestContext = result;
    } else {
      switch (method) {
        case http.HttpMethod.get:
          result = await http.getCredentialed(uri,
              headers: headers, requestContext: requestContext);
          break;
        case http.HttpMethod.post:
          result = await http.postCredentialed(uri,
              headers: headers, body: body, requestContext: requestContext);
          break;
        case http.HttpMethod.put:
          result = await http.putCredentialed(uri,
              headers: headers, body: body, requestContext: requestContext);
          break;
        case http.HttpMethod.delete:
          result = await http.deleteCredentialed(uri,
              headers: headers, body: body, requestContext: requestContext);
          break;
      }
    }

    if (result.response.statusCode == 401) {
      unauthorized = true;
      return result.response;
    }
    if (!await result.isCurrent()) {
      stale = true;
      throw StateError('地址簿认证请求已失效');
    }
    if (result.personalHashReceipt != null) {
      personalHashReceipt = result.personalHashReceipt;
    }
    return result.response;
  }

  Future<void> clearVisibleStateIfUnauthorized() async {
    if (!unauthorized || isWeb) return;
    try {
      final snapshot = jsonDecode(await bind.mainAuthSnapshot());
      if (snapshot is Map<String, dynamic> && snapshot['session'] == null) {
        await gFFI.userModel.reset(resetOther: true);
      }
    } catch (_) {}
  }
}

class _AbMutationGuard {
  final AbModel owner;
  final String addressBookName;
  final BaseAb model;
  final String? generationKey;
  final String? generationHandle;

  _AbMutationGuard(this.owner, this.addressBookName, this.model)
      : generationKey = model.stateGenerationKey,
        generationHandle = model.stateGenerationHandle;

  bool get sameState {
    if (!identical(owner.addressbooks[addressBookName], model) ||
        model.stateGenerationKey != generationKey ||
        model.stateGenerationHandle != generationHandle) {
      return false;
    }
    return isWeb ||
        (generationKey != null &&
            generationHandle != null &&
            AbRequestScope.isActiveGeneration(generationKey));
  }

  StateGenerationGuard get stateGuard => StateGenerationGuard(
        sameState: () => sameState,
        sameGeneration: () => AbRequestScope.isHandleCurrent(generationHandle),
      );

  Future<bool> isCurrent() => stateGuard.isCurrent();
}

class _AbCacheCapture {
  final String entriesJson;
  final int stateRevision;
  final String currentName;
  final Map<String, BaseAb> models;
  final String? generationKey;
  final String? generationHandle;
  final String? authNamespace;

  const _AbCacheCapture({
    required this.entriesJson,
    required this.stateRevision,
    required this.currentName,
    required this.models,
    required this.generationKey,
    required this.generationHandle,
    required this.authNamespace,
  });
}

class _AbVisibleListState {
  final AuthRequestGeneration? generation;
  final Map<String, BaseAb> books;
  final String currentName;
  final bool legacyMode;

  const _AbVisibleListState({
    required this.generation,
    required this.books,
    required this.currentName,
    required this.legacyMode,
  });
}

class AbModel {
  final addressbooks = Map<String, BaseAb>.fromEntries([]).obs;
  final RxString _currentName = ''.obs;
  RxString get currentName => _currentName;
  final _dummyAb = DummyAb();
  BaseAb get current => addressbooks[_currentName.value] ?? _dummyAb;

  RxList<Peer> get currentAbPeers => current.peers;
  RxList<String> get currentAbTags => current.tags;
  RxList<String> get selectedTags => current.selectedTags;

  RxBool get currentAbLoading => current.abLoading;
  bool get currentAbEmpty => current.peers.isEmpty && current.tags.isEmpty;
  final _listPullError = ''.obs;
  RxString get abPullError =>
      _listPullError.value.isNotEmpty ? _listPullError : current.pullError;
  RxString get currentAbPushError => current.pushError;
  String? _personalAbGuid;
  bool _issue9Mode = false;
  bool _legacyConfirmed = false;
  Issue9FullPage? _issue9FirstPage;
  http.StrictHttpResult? _issue9FirstResult;
  http.StrictHttpResult? _pendingIssue9Ack;
  int? _pendingIssue9Target;
  RxBool legacyMode = false.obs;

  // Only handles peers add/remove
  final Map<String, VoidCallback> _peerIdUpdateListeners = {};

  final sortTags = shouldSortTags().obs;
  final filterByIntersection = filterAbTagByIntersection().obs;

  var _syncAllFromRecent = true;
  var _syncFromRecentLock = false;
  var _timerCounter = 0;
  int? _addressBookConsumerGeneration;
  bool _addressBookConsumerReadyChecking = false;
  var _cacheLoadOnceFlag = false;
  var _pulledOnce = false;
  var listInitialized = false;
  var _maxPeerOneAb = 0;
  var _issue9RefreshPending = false;
  var _issue9RefreshRunning = false;
  final GenerationCommitCoordinator _visibleCommit =
      GenerationCommitCoordinator();
  AuthRequestGeneration? _visibleGeneration;
  var _stateRevision = 0;
  var _cacheSaveSequence = 0;
  String? _cacheGenerationHandle;
  String? _cacheAuthNamespace;

  late final Peers peersModel;

  WeakReference<FFI> parent;

  AbModel(this.parent) {
    addressbooks.clear();
    peersModel = Peers(
        name: PeersModelName.addressBook,
        getInitPeers: () => currentAbPeers,
        loadEvent: LoadEvent.addressBook);
    if (desktopType == DesktopType.main) {
      platformFFI.registerEventHandler(
          'address_book_updated', 'issue9_address_book', (event) async {
        if (!await _isCurrentIssue9Event(event)) return;
        _issue9RefreshPending = true;
        await _drainIssue9Refresh();
      });
      unawaited(_ensureIssue9ConsumerReady());
      Timer.periodic(Duration(milliseconds: 500), (timer) async {
        if (_timerCounter++ % 6 == 0) {
          await _ensureIssue9ConsumerReady();
          if (!gFFI.userModel.isLogin) return;
          if (!listInitialized) return;
          if (!current.initialized || !current.canWrite()) return;
          _syncFromRecent();
        }
      });
    }
  }

  Future<GenerationCommitReceipt?> _commitVisibleList(
    AbRequestScope request,
    _AbVisibleListState state,
  ) async {
    if (isWeb) {
      return _visibleCommit.replaceLocal(state, _applyVisibleList);
    }
    final generation = request.generation;
    if (generation == null) return null;
    final receipt = await _visibleCommit.commit<_AbVisibleListState>(
      generation: generation,
      isGenerationCurrent: (expected) async =>
          request.generation?.sameAs(expected) == true &&
          await request.isCurrent(),
      payload: state,
      apply: _applyVisibleList,
      rollback: (stillOwned) {
        if (stillOwned()) {
          _clearVisibleListForGenerationRollback();
        }
      },
    );
    if (receipt == null && _visibleGeneration?.sameAs(generation) == true) {
      _visibleCommit.invalidate();
      _clearVisibleListForGenerationRollback();
    }
    return receipt;
  }

  void _applyVisibleList(_AbVisibleListState state) {
    _visibleGeneration = state.generation;
    for (final model in addressbooks.values) {
      model.invalidateVisibleCommit();
    }
    addressbooks.assignAll(state.books);
    final generation = state.generation;
    if (generation != null) {
      for (final model in addressbooks.values) {
        model.bindVisibleGeneration(generation);
      }
    }
    _currentName.value = state.currentName;
    legacyMode.value = state.legacyMode;
    listInitialized = true;
    _stateRevision += 1;
  }

  void _clearVisibleListForGenerationRollback() {
    _visibleGeneration = null;
    AbRequestScope.invalidateActiveGeneration();
    for (final model in addressbooks.values) {
      model.invalidateVisibleCommit();
    }
    addressbooks.clear();
    _currentName.value = '';
    _listPullError.value = '';
    listInitialized = false;
    legacyMode.value = false;
    _issue9Mode = false;
    _legacyConfirmed = false;
    _personalAbGuid = null;
    _issue9FirstPage = null;
    _issue9FirstResult = null;
    _pendingIssue9Ack = null;
    _pendingIssue9Target = null;
    _cacheGenerationHandle = null;
    _cacheAuthNamespace = null;
    _stateRevision += 1;
  }

  Future<void> _ensureIssue9ConsumerReady() async {
    if (_addressBookConsumerReadyChecking) return;
    _addressBookConsumerReadyChecking = true;
    try {
      final registration =
          jsonDecode(await bind.mainGetAddressBookConsumerRegistration());
      if (registration is! Map<String, dynamic> ||
          registration['sink_present'] != true ||
          registration['sink_generation'] is! int) {
        return;
      }
      final generation = registration['sink_generation'] as int;
      if (generation <= 0 || generation == _addressBookConsumerGeneration) {
        return;
      }
      if (await bind.mainAddressBookConsumerReady(sinkGeneration: generation)) {
        _addressBookConsumerGeneration = generation;
      }
    } catch (_) {
    } finally {
      _addressBookConsumerReadyChecking = false;
    }
  }

  Future<bool> _isCurrentIssue9Event(Map<String, dynamic> event) async {
    try {
      final snapshot = jsonDecode(await bind.mainAuthSnapshot());
      final session =
          snapshot is Map<String, dynamic> ? snapshot['session'] : null;
      if (session is! Map<String, dynamic>) return false;
      return addressBookRefreshEventMatchesSession(event, session);
    } catch (_) {
      return false;
    }
  }

  Future<void> _drainIssue9Refresh() async {
    if (_issue9RefreshRunning) return;
    _issue9RefreshRunning = true;
    try {
      while (_issue9RefreshPending) {
        _issue9RefreshPending = false;
        while (_pulling) {
          await Future.delayed(const Duration(milliseconds: 50));
        }
        await pullAb(force: ForcePullAb.listAndCurrent, quiet: true);
      }
    } finally {
      _issue9RefreshRunning = false;
      if (_issue9RefreshPending) {
        await _drainIssue9Refresh();
      }
    }
  }

  Future<bool> _completeIssue9Pull() async {
    final request = _pendingIssue9Ack;
    final target = _pendingIssue9Target;
    if (request == null || target == null) return false;
    _pendingIssue9Ack = null;
    _pendingIssue9Target = null;
    if (!await request.isCurrent()) return false;
    final acknowledged = await request.acknowledgeCursor(
      target,
      allowReset: target < request.cursor,
    );
    if (acknowledged) {
      await bind.mainAuthWakeAddressBookSync();
    }
    return acknowledged;
  }

  void _publishWritableModels(AbRequestScope request) {
    for (final model in addressbooks.values) {
      if (model is Ab) {
        model.confirmFor(request);
      } else if (model is LegacyAb && model is! Issue9Ab) {
        model.writableConfirmed = _legacyConfirmed;
        model.confirmFor(request);
      }
    }
  }

  Future<void> reset() async {
    print("reset ab model");
    final namespaceToClear = cacheNamespaceForConditionalClear(
      rememberedNamespace: _cacheAuthNamespace,
      generationHandleJson:
          _cacheGenerationHandle ?? current.stateGenerationHandle,
    );
    _visibleCommit.invalidate();
    _visibleGeneration = null;
    for (final model in addressbooks.values) {
      model.invalidateVisibleCommit();
    }
    AbRequestScope.invalidateActiveGeneration();
    _stateRevision += 1;
    _cacheSaveSequence += 1;
    addressbooks.clear();
    _currentName.value = '';
    _listPullError.value = '';
    _pulledOnce = false;
    _issue9Mode = false;
    _legacyConfirmed = false;
    legacyMode.value = false;
    _personalAbGuid = null;
    _maxPeerOneAb = 0;
    _issue9FirstPage = null;
    _issue9FirstResult = null;
    _pendingIssue9Ack = null;
    _pendingIssue9Target = null;
    _syncAllFromRecent = true;
    _syncFromRecentLock = false;
    _cacheLoadOnceFlag = false;
    _addressBookConsumerGeneration = null;
    _issue9RefreshPending = false;
    _cacheGenerationHandle = null;
    _cacheAuthNamespace = null;
    listInitialized = false;
    if (isWeb) {
      await bind.mainClearAb();
    } else if (namespaceToClear != null) {
      await bind.mainClearAbIfNamespace(authNamespace: namespaceToClear);
    }
  }

  void clearPullErrors() {
    _listPullError.value = '';
    current.pullError.value = '';
  }

// #region ab
  /// Pulls the address book data from the server.
  ///
  /// If `force` is `ForcePullAb.listAndCurrent`, the function will pull the list of address books, current address book, and try initialize personal address book.
  /// If `force` is `ForcePullAb.current`, the function will only pull the current address book.
  /// If `quiet` is true, the function will not display any notifications or errors.
  var _pulling = false;
  Future<void> pullAb(
      {required ForcePullAb? force, required bool quiet}) async {
    if (bind.isDisableAb()) return;
    if (!gFFI.userModel.isLogin) return;
    if (_pulling) return;
    if (force == null && _pulledOnce) {
      return;
    }
    _pulling = true;
    if (!quiet) {
      _listPullError.value = '';
      current.pullError.value = '';
    }
    AbRequestScope? request;
    var completedForCurrentSession = false;
    try {
      final base = await bind.mainGetApiServer();
      request = await AbRequestScope.create(
        apiBase: base,
        initialUri: Uri.parse('$base/api/ab/personal'),
      );
      final pulled = await _pullAb(request, force: force, quiet: quiet);
      if (!pulled) return;
      if (request.unauthorized) {
        await request.clearVisibleStateIfUnauthorized();
        return;
      }
      if (!await request.isCurrent()) return;
      await _refreshTab();
      if (!await request.isCurrent()) return;
      if (!_issue9Mode) {
        final capability = legacyMode.value ? 'legacy' : 'commercial_multi';
        if (!await request.confirmCapability(capability)) return;
        if (!await request.activateGenerationIfCurrent()) return;
        _publishWritableModels(request);
      } else if (!await _completeIssue9Pull()) {
        return;
      }
      if (!await request.isCurrent()) return;
      _cacheGenerationHandle = request.handleJson;
      _cacheAuthNamespace = request.authNamespace;
      _callbackPeerUpdate();
      await _saveCache(request: request, expectedModel: current);
      completedForCurrentSession = await request.isCurrent();
    } catch (error) {
      if (request != null && await request.isCurrent()) {
        debugPrint('pull address book error: $error');
      }
    } finally {
      _pulling = false;
      if (completedForCurrentSession) {
        _pulledOnce = true;
      }
    }
  }

  Future<bool> _pullAb(AbRequestScope request,
      {required ForcePullAb? force, required bool quiet}) async {
    if (force == null && listInitialized && current.initialized) return true;
    debugPrint("pullAb, force: $force, quiet: $quiet");
    if (listInitialized &&
        force != ForcePullAb.listAndCurrent &&
        (!current.initialized || force == ForcePullAb.current)) {
      try {
        await current.pullAb(quiet: quiet, requestScope: request);
      } catch (e) {
        if (await request.isCurrent()) {
          debugPrint("pull current Ab error: $e");
        }
      }
      if (!current.initialized || !await request.isCurrent()) return false;
      _stateRevision += 1;
      return true;
    }

    final previousPersonalGuid = _personalAbGuid;
    final previousIssue9Mode = _issue9Mode;
    final previousLegacyConfirmed = _legacyConfirmed;
    final previousLegacyMode = legacyMode.value;
    final previousMaxPeerOneAb = _maxPeerOneAb;

    void restoreProbeState() {
      _personalAbGuid = previousPersonalGuid;
      _issue9Mode = previousIssue9Mode;
      _legacyConfirmed = previousLegacyConfirmed;
      legacyMode.value = previousLegacyMode;
      _maxPeerOneAb = previousMaxPeerOneAb;
      _issue9FirstPage = null;
      _issue9FirstResult = null;
      _pendingIssue9Ack = null;
      _pendingIssue9Target = null;
    }

    try {
      _personalAbGuid = null;
      _issue9Mode = false;
      _legacyConfirmed = false;
      _issue9FirstPage = null;
      _issue9FirstResult = null;

      if (!await _getPersonalAbGuid(request, quiet: quiet) ||
          !await request.isCurrent()) {
        restoreProbeState();
        return false;
      }

      final nextLegacyMode = _personalAbGuid == null && !_issue9Mode;
      if (!nextLegacyMode && !_issue9Mode) {
        if (!await _getAbSettings(request, quiet: quiet) ||
            !await request.isCurrent()) {
          restoreProbeState();
          return false;
        }
      }

      final nextBooks = <String, BaseAb>{};
      if (_personalAbGuid != null) {
        debugPrint("pull ab list");
        final profiles = <AbProfile>[
          AbProfile(
            _personalAbGuid!,
            _personalAddressBookName,
            gFFI.userModel.userName.value,
            null,
            ShareRule.read.value,
            null,
          ),
        ];
        if (!await _getSharedAbProfiles(request, profiles, quiet: quiet) ||
            !await request.isCurrent()) {
          restoreProbeState();
          return false;
        }
        for (final profile in profiles) {
          nextBooks[profile.name] = Ab(
            profile,
            profile.guid == _personalAbGuid,
            writableConfirmed: false,
            generationKey: request.generationKey,
          );
        }
      } else if (_issue9Mode) {
        nextBooks[_issue9AddressBookName] = Issue9Ab(
          _pullIssue9AddressBook,
          (result) {
            _pendingIssue9Ack = result.request;
            _pendingIssue9Target = result.target;
          },
        );
      } else {
        nextBooks[_legacyAddressBookName] = LegacyAb(
          writableConfirmed: false,
          generationKey: request.generationKey,
        );
      }

      var nextCurrentName = _currentName.value;
      if (!listInitialized) {
        final lastName = bind.getLocalFlutterOption(k: kOptionCurrentAbName);
        if (nextBooks.containsKey(lastName)) {
          nextCurrentName = lastName;
        }
      }
      if (!nextBooks.containsKey(nextCurrentName)) {
        nextCurrentName = _issue9Mode
            ? _issue9AddressBookName
            : nextLegacyMode
                ? _legacyAddressBookName
                : _personalAddressBookName;
      }
      final nextCurrent = nextBooks[nextCurrentName];
      if (nextCurrent == null) {
        restoreProbeState();
        return false;
      }
      await nextCurrent.pullAb(quiet: quiet, requestScope: request);
      if (!nextCurrent.initialized || !await request.isCurrent()) {
        restoreProbeState();
        return false;
      }
      if (!nextCurrent.isPersonal()) {
        final personal = nextBooks[_personalAddressBookName];
        if (personal == null) {
          restoreProbeState();
          return false;
        }
        await personal.pullAb(quiet: quiet, requestScope: request);
        if (!personal.initialized || !await request.isCurrent()) {
          restoreProbeState();
          return false;
        }
      }

      final receipt = await _commitVisibleList(
        request,
        _AbVisibleListState(
          generation: request.generation,
          books: Map<String, BaseAb>.unmodifiable(nextBooks),
          currentName: nextCurrentName,
          legacyMode: nextLegacyMode,
        ),
      );
      return _visibleCommit.owns(receipt);
    } catch (error) {
      restoreProbeState();
      if (await request.isCurrent()) {
        debugPrint("pull ab list error: $error");
        _setListPullError(error, quiet: quiet);
      }
      return false;
    }
  }

  void _setListPullError(Object err, {required bool quiet, int? statusCode}) {
    if (!quiet) {
      _listPullError.value =
          '${translate('pull_ab_failed_tip')}: ${translate(err.toString())}';
    }
    if (statusCode == 401) {
      gFFI.userModel.reset(resetOther: true);
    }
  }

  Future<bool> _getAbSettings(AbRequestScope request,
      {required bool quiet}) async {
    int? statusCode;
    try {
      final api = "${request.apiBase}/api/ab/settings";
      var headers = <String, String>{'Content-Type': 'application/json'};
      _setEmptyBody(headers);
      final resp = await request.send(http.HttpMethod.post, Uri.parse(api),
          headers: headers);
      statusCode = resp.statusCode;
      if (statusCode == 404) {
        debugPrint("HTTP 404, api server doesn't support shared address book");
        _maxPeerOneAb = 0;
        return true;
      }
      Map<String, dynamic> json =
          _jsonDecodeRespMap(decode_http_response(resp), resp.statusCode);
      if (json.containsKey('error')) {
        throw json['error'];
      }
      if (statusCode != 200) {
        throw 'HTTP $statusCode';
      }
      final maxPeerOneAb = json['max_peer_one_ab'] ?? 0;
      if (maxPeerOneAb is! int || maxPeerOneAb < 0) {
        throw const FormatException('Invalid max_peer_one_ab');
      }
      _maxPeerOneAb = maxPeerOneAb;
      return true;
    } catch (err) {
      if (!await request.isCurrent() || request.unauthorized) return false;
      debugPrint('get ab settings err: ${err.toString()}');
      _setListPullError(err, quiet: quiet, statusCode: statusCode);
    }
    return false;
  }

  /// Loads `/api/ab/personal`.
  /// Returns `true` to continue init, `false` to stop after a real error.
  Future<bool> _getPersonalAbGuid(AbRequestScope request,
      {required bool quiet}) async {
    int? statusCode;
    try {
      final api = "${request.apiBase}/api/ab/personal";
      var headers = <String, String>{'Content-Type': 'application/json'};
      _setEmptyBody(headers);
      final resp = await request.send(http.HttpMethod.post, Uri.parse(api),
          headers: headers);
      statusCode = resp.statusCode;
      if (shouldProbeIssue9AddressBook(statusCode)) {
        debugPrint("HTTP $statusCode, probing Issue #9 address-book API");
        return await _probeIssue9AddressBook(request, quiet: quiet);
      }
      Map<String, dynamic> json =
          _jsonDecodeRespMap(decode_http_response(resp), resp.statusCode);
      if (json.containsKey('error')) {
        throw json['error'];
      }
      if (statusCode != 200) {
        throw 'HTTP $statusCode';
      }
      _personalAbGuid = parsePersonalAddressBookGuid(json);
      // New server: guid is available, continue in non-legacy mode.
      return true;
    } catch (err) {
      if (!await request.isCurrent() || request.unauthorized) return false;
      debugPrint('get personal ab err: ${err.toString()}');
      _setListPullError(err, quiet: quiet, statusCode: statusCode);
    }
    // Real error: stop the current pull.
    return false;
  }

  Future<bool> _probeIssue9AddressBook(AbRequestScope request,
      {required bool quiet}) async {
    int? statusCode;
    try {
      final base = request.apiBase;
      final uri = Uri.parse('$base/api/ab').replace(queryParameters: {
        'page': '1',
        'page_size': '200',
      });
      var response = await request.send(
        http.HttpMethod.get,
        uri,
        headers: const {'Accept': 'application/json'},
      );
      statusCode = response.statusCode;
      if (statusCode == 400) {
        response = await request.send(
          http.HttpMethod.get,
          Uri.parse('$base/api/ab'),
          headers: const {'Accept': 'application/json'},
        );
        statusCode = response.statusCode;
        if (statusCode != 200) {
          throw 'HTTP $statusCode';
        }
        final bareBody = decode_http_response(response).trim();
        if (_isStrictLegacyAddressBookBody(bareBody)) {
          _legacyConfirmed = true;
          return true;
        }
        throw const FormatException('地址簿服务声明了新协议标记，但分页请求无效');
      }
      if (statusCode != 200) {
        throw 'HTTP $statusCode';
      }
      final contentType = response.headers['content-type'] ?? '';
      if (!contentType.toLowerCase().startsWith('application/json')) {
        throw const FormatException('地址簿响应 Content-Type 无效');
      }
      final body = decode_http_response(response).trim();
      if (_isStrictLegacyAddressBookBody(body)) {
        _legacyConfirmed = true;
        return true;
      }
      final decoded = jsonDecode(body);
      _issue9FirstPage = Issue9FullPage.fromJson(decoded);
      _issue9FirstResult = request.requestContext;
      final handle = request.handleJson;
      if (!isWeb &&
          (handle == null ||
              !await bind.mainAuthClearPersonalHashAllowlistIfCurrent(
                  handleJson: handle))) {
        return false;
      }
      if (!await request.isCurrent()) return false;
      if (!await request.confirmCapability(
        'issue9_v2',
        forceFullPending: true,
      )) {
        return false;
      }
      if (!await request.isCurrent()) return false;
      _issue9Mode = true;
      return true;
    } catch (error) {
      if (!await request.isCurrent() || request.unauthorized) return false;
      _setListPullError(error, quiet: quiet, statusCode: statusCode);
      return false;
    }
  }

  bool _isStrictLegacyAddressBookBody(String body) {
    if (body == 'null') return true;
    final decoded = jsonDecode(body);
    if (decoded is! Map<String, dynamic>) return false;
    if (decoded['mode'] != null || decoded['ab_ver'] != null) return false;
    return decoded.containsKey('data');
  }

  Future<Issue9PullResult> _pullIssue9AddressBook(List<Peer> previous) async {
    const pageSize = 200;
    var pageNumber = 1;
    int? target;
    int? total;
    final items = <Issue9AddressBookItem>[];
    final identities = <String>{};
    Issue9FullPage? page = _issue9FirstPage;
    http.StrictHttpResult? request = _issue9FirstResult;
    final base = request?.normalizedApiBase ?? await bind.mainGetApiServer();
    _issue9FirstPage = null;
    _issue9FirstResult = null;
    while (true) {
      if (page == null) {
        final query = <String, String>{
          'page': pageNumber.toString(),
          'page_size': pageSize.toString(),
          if (target != null) 'sync_ver': target.toString(),
        };
        final uri = Uri.parse('$base/api/ab').replace(queryParameters: query);
        final result = await http.getCredentialed(
          uri,
          headers: const {'Accept': 'application/json'},
          requestContext: request,
        );
        request ??= result;
        final response = result.response;
        if (response.statusCode != 200) {
          throw 'HTTP ${response.statusCode}';
        }
        final contentType = response.headers['content-type'] ?? '';
        if (!contentType.toLowerCase().startsWith('application/json')) {
          throw const FormatException('地址簿响应 Content-Type 无效');
        }
        page =
            Issue9FullPage.fromJson(jsonDecode(decode_http_response(response)));
      }
      target ??= page.abVer;
      total ??= page.total;
      if (page.abVer != target ||
          page.total != total ||
          page.page != pageNumber ||
          page.pageSize != pageSize) {
        throw const FormatException('Address-book snapshot changed');
      }
      for (final item in page.items) {
        if (!identities.add(item.identity)) {
          throw const FormatException('Duplicate address-book identity');
        }
        items.add(item);
      }
      if (page.items.length > pageSize ||
          (page.hasMore && page.items.length != pageSize)) {
        throw const FormatException('Invalid address-book page length');
      }
      if (items.length > total) {
        throw const FormatException('Address-book total mismatch');
      }
      final expectedLoaded =
          pageNumber * pageSize < total ? pageNumber * pageSize : total;
      if (items.length != expectedLoaded) {
        throw const FormatException('Address-book page offset mismatch');
      }
      if (page.hasMore != (items.length < total)) {
        throw const FormatException('Address-book has_more mismatch');
      }
      if (!page.hasMore) {
        if (items.length != total) {
          throw const FormatException('Address-book total mismatch');
        }
        break;
      }
      if (page.items.isEmpty || items.length >= total) {
        throw const FormatException('Invalid address-book pagination');
      }
      pageNumber += 1;
      page = null;
    }
    if (request == null) {
      throw const FormatException('地址簿响应缺少认证上下文');
    }
    if (!await request.isCurrent()) {
      throw const FormatException('地址簿认证上下文已失效');
    }
    final next = Issue9AddressBookState.replaceAll(items, previous);
    return Issue9PullResult(next, request, target);
  }

  Future<bool> _getSharedAbProfiles(
      AbRequestScope request, List<AbProfile> profiles,
      {required bool quiet}) async {
    final api = "${request.apiBase}/api/ab/shared/profiles";
    int? statusCode;
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
        var headers = <String, String>{'Content-Type': 'application/json'};
        _setEmptyBody(headers);
        final resp =
            await request.send(http.HttpMethod.post, uri, headers: headers);
        statusCode = resp.statusCode;
        if (statusCode == 404) {
          debugPrint(
              "HTTP 404, api server doesn't support shared address book");
          return true;
        }
        Map<String, dynamic> json =
            _jsonDecodeRespMap(decode_http_response(resp), resp.statusCode);
        if (json.containsKey('error')) {
          throw json['error'];
        }
        if (statusCode != 200) {
          throw 'HTTP $statusCode';
        }
        if (json.containsKey('total')) {
          if (total == 0) total = json['total'];
          if (json.containsKey('data')) {
            final data = json['data'];
            if (data is List) {
              for (final profile in data) {
                final u = AbProfile.fromJson(profile);
                if (sharedAddressBookCollidesWithPersonal(
                  name: u.name,
                  guid: u.guid,
                  personalGuid: _personalAbGuid,
                )) {
                  throw const FormatException(
                      'Shared address book collides with personal profile');
                }
                int index = profiles.indexWhere((e) => e.name == u.name);
                if (index < 0) {
                  profiles.add(u);
                } else {
                  profiles[index] = u;
                }
              }
            }
          }
        }
      } while (current * pageSize < total);
      return true;
    } catch (err) {
      if (!await request.isCurrent() || request.unauthorized) return false;
      debugPrint('_getSharedAbProfiles err: ${err.toString()}');
      _setListPullError(err, quiet: quiet, statusCode: statusCode);
    }
    return false;
  }

// #endregion

// #region rule
  List<String> addressBooksCanWrite() {
    List<String> list = [];
    addressbooks.forEach((key, value) async {
      if (value.canWrite()) {
        list.add(key);
      }
    });
    return list;
  }

// #endregion

// #region peer
  _AbMutationGuard? _captureMutation(String name) {
    final model = addressbooks[name];
    if (model == null) return null;
    final guard = _AbMutationGuard(this, name, model);
    return guard.sameState ? guard : null;
  }

  Future<bool> _finishSuccessfulMutation(
    _AbMutationGuard guard, {
    bool pullNonLegacy = true,
    bool refreshPeers = false,
    bool refreshTab = false,
    bool saveCache = false,
    bool notifyPeers = false,
  }) async {
    if (!await guard.isCurrent()) return false;
    if (pullNonLegacy && guard.addressBookName != _legacyAddressBookName) {
      await guard.model.pullAb(quiet: true);
      if (!guard.model.initialized || !await guard.isCurrent()) return false;
    }
    if (!await guard.isCurrent()) return false;
    _stateRevision += 1;
    if (refreshPeers) {
      guard.model.peers.refresh();
    }
    if (refreshTab &&
        _currentName.value == guard.addressBookName &&
        await guard.isCurrent()) {
      await _refreshTab();
    }
    if (!await guard.isCurrent()) return false;
    if (saveCache &&
        !await _saveCache(
          mutationGuard: guard,
          expectedModel: guard.model,
        )) {
      return false;
    }
    if (!await guard.isCurrent()) return false;
    if (notifyPeers) {
      _callbackPeerUpdate();
    }
    if (guard.model is LegacyAb && guard.model is! Issue9Ab) {
      showToast(translate('Successful'));
    }
    return true;
  }

  Future<String?> addIdToCurrent(String id, String alias, String password,
      List<dynamic> tags, String note) async {
    if (currentAbPeers.where((element) => element.id == id).isNotEmpty) {
      return "$id already exists in address book $_currentName";
    }
    Map<String, dynamic> peer = {
      'id': id,
      'alias': alias,
      'tags': tags,
    };
    // avoid set existing password to empty
    if (password.isNotEmpty) {
      peer['password'] = password;
    }
    if (note.isNotEmpty) {
      peer['note'] = note;
    }
    return await addPeersTo([peer], _currentName.value);
  }

  // Use Map<String, dynamic> rather than Peer to distinguish between empty and null
  Future<String?> addPeersTo(
    List<Map<String, dynamic>> ps,
    String name,
  ) async {
    final guard = _captureMutation(name);
    if (guard == null) {
      return 'no such addressbook: $name';
    }
    final peers = ps
        .map((peer) => Map<String, dynamic>.from(peer))
        .toList(growable: false);
    for (var peer in peers) {
      guard.model.removeNonExistentTags(peer);
    }
    final errMsg = await guard.model.addPeers(peers);
    if (errMsg != null || !await guard.isCurrent()) {
      return errMsg;
    }
    final completed = await _finishSuccessfulMutation(
      guard,
      refreshTab: true,
      saveCache: true,
    );
    if (!completed) return 'address-book session changed';
    _syncAllFromRecent = true;
    return null;
  }

  Future<bool> changeTagForPeers(List<String> ids, List<dynamic> tags) async {
    final guard = _captureMutation(_currentName.value);
    if (guard == null) return false;
    final ret = await guard.model.changeTagForPeers(
      List<String>.from(ids),
      List<dynamic>.from(tags),
    );
    if (!ret || !await guard.isCurrent()) return false;
    return await _finishSuccessfulMutation(
      guard,
      refreshPeers: true,
      saveCache: true,
    );
  }

  Future<bool> changeAlias({required String id, required String alias}) async {
    final guard = _captureMutation(_currentName.value);
    if (guard == null) return false;
    final ret = await guard.model.changeAlias(id: id, alias: alias);
    if (!ret || !await guard.isCurrent()) return false;
    return await _finishSuccessfulMutation(
      guard,
      refreshPeers: true,
      saveCache: true,
    );
  }

  Future<bool> changeNote({required String id, required String note}) async {
    final guard = _captureMutation(_currentName.value);
    if (guard == null) return false;
    final ret = await guard.model.changeNote(id: id, note: note);
    if (!ret || !await guard.isCurrent()) return false;
    return await _finishSuccessfulMutation(
      guard,
      refreshPeers: true,
      saveCache: false,
    );
  }

  Future<bool> changePersonalHashPassword(String id, String hash) async {
    final name = addressbooks.containsKey(_personalAddressBookName)
        ? _personalAddressBookName
        : _legacyAddressBookName;
    final guard = _captureMutation(name);
    if (guard == null) return false;
    final ret = await guard.model.changePersonalHashPassword(id, hash);
    if (!ret || !await guard.isCurrent()) return false;
    return await _finishSuccessfulMutation(guard, saveCache: true);
  }

  Future<bool> changeSharedPassword(
      String abName, String id, String password) async {
    final guard = _captureMutation(abName);
    if (guard == null) return false;
    final ret = await guard.model.changeSharedPassword(id, password);
    if (!ret || !await guard.isCurrent()) return false;
    return await _finishSuccessfulMutation(guard, saveCache: false);
  }

  Future<bool> deletePeers(List<String> ids) async {
    final guard = _captureMutation(_currentName.value);
    if (guard == null) return false;
    final capturedIds = List<String>.unmodifiable(ids);
    final ret = await guard.model.deletePeers(capturedIds);
    if (!ret || !await guard.isCurrent()) return false;
    final completed = await _finishSuccessfulMutation(
      guard,
      refreshPeers: true,
      refreshTab: true,
      saveCache: true,
      notifyPeers: true,
    );
    if (!completed) return false;
    if (legacyMode.value && guard.model.isPersonal()) {
      // non-legacy mode not add peers automatically
      Future.delayed(const Duration(seconds: 2), () async {
        if (!await guard.isCurrent() || !shouldSyncAb()) return;
        var hasSynced = false;
        for (var id in capturedIds) {
          if (await bind.mainPeerExists(id: id)) {
            hasSynced = true;
            break;
          }
          if (!await guard.isCurrent()) return;
        }
        if (hasSynced && await guard.isCurrent()) {
          BotToast.showText(
              contentColor: Colors.lightBlue,
              text: translate('synced_peer_readded_tip'));
          _syncAllFromRecent = true;
        }
      });
    }
    return true;
  }

// #endregion

// #region tags
  Future<bool> addTags(List<String> tagList) async {
    final guard = _captureMutation(_currentName.value);
    if (guard == null) return false;
    final capturedTags =
        tagList.where((tag) => tag != kUntagged).toList(growable: false);
    final ret = await guard.model.addTags(capturedTags, const {});
    if (!ret || !await guard.isCurrent()) return false;
    return await _finishSuccessfulMutation(guard, saveCache: true);
  }

  Future<bool> renameTag(String oldTag, String newTag) async {
    final guard = _captureMutation(_currentName.value);
    if (guard == null) return false;
    final ret = await guard.model.renameTag(oldTag, newTag);
    if (!ret || !await guard.isCurrent()) return false;
    if (!await _finishSuccessfulMutation(guard, saveCache: true)) return false;
    if (!await guard.isCurrent()) return false;
    guard.model.selectedTags.value = guard.model.selectedTags.map((e) {
      if (e == oldTag) {
        return newTag;
      } else {
        return e;
      }
    }).toList();
    return true;
  }

  Future<bool> setTagColor(String tag, Color color) async {
    final guard = _captureMutation(_currentName.value);
    if (guard == null) return false;
    final ret = await guard.model.setTagColor(tag, color);
    if (!ret || !await guard.isCurrent()) return false;
    return await _finishSuccessfulMutation(guard, saveCache: true);
  }

  Future<bool> deleteTag(String tag) async {
    final guard = _captureMutation(_currentName.value);
    if (guard == null) return false;
    final ret = await guard.model.deleteTag(tag);
    if (!ret || !await guard.isCurrent()) return false;
    if (!await _finishSuccessfulMutation(guard, saveCache: true)) return false;
    if (!await guard.isCurrent()) return false;
    guard.model.selectedTags.remove(tag);
    return true;
  }

// #endregion

// #region sync from recent
  Future<void> _syncFromRecent({bool push = true}) async {
    final guard = _captureMutation(_currentName.value);
    if (guard == null || _syncFromRecentLock) return;
    _syncFromRecentLock = true;
    try {
      await _syncFromRecentWithoutLock(guard, push: push);
    } finally {
      _syncFromRecentLock = false;
    }
  }

  Future<void> _syncFromRecentWithoutLock(
    _AbMutationGuard guard, {
    bool push = true,
  }) async {
    Future<List<Peer>> getRecentPeers() async {
      try {
        if (!await guard.isCurrent()) return [];
        List<String> filteredPeerIDs;
        if (_syncAllFromRecent) {
          _syncAllFromRecent = false;
          filteredPeerIDs = [];
        } else {
          final new_stored_str = await bind.mainGetNewStoredPeers();
          if (!await guard.isCurrent()) return [];
          if (new_stored_str.isEmpty) return [];
          filteredPeerIDs = (jsonDecode(new_stored_str) as List<dynamic>)
              .map((e) => e.toString())
              .toList();
          if (filteredPeerIDs.isEmpty) return [];
        }
        final loadStr = await bind.mainLoadRecentPeersForAb(
            filter: jsonEncode(filteredPeerIDs));
        if (!await guard.isCurrent()) return [];
        if (loadStr.isEmpty) {
          return [];
        }
        List<dynamic> mapPeers = jsonDecode(loadStr);
        List<Peer> recents = List.empty(growable: true);
        for (var m in mapPeers) {
          if (m is Map<String, dynamic>) {
            recents.add(Peer.fromJson(m));
          }
        }
        return recents;
      } catch (e) {
        debugPrint('getRecentPeers: $e');
      }
      return [];
    }

    try {
      if (!shouldSyncAb() || !await guard.isCurrent()) return;
      final recents = await getRecentPeers();
      if (recents.isEmpty || !await guard.isCurrent()) return;
      debugPrint("sync from recent, len: ${recents.length}");
      if (guard.model.canWrite() && guard.model.initialized) {
        await guard.model.syncFromRecent(recents);
      }
    } catch (e) {
      debugPrint('_syncFromRecentWithoutLock: $e');
    }
  }

  void setShouldAsync(bool v) async {
    await bind.mainSetLocalOption(
        key: syncAbOption, value: v ? 'Y' : defaultOptionNo);
    _syncAllFromRecent = true;
    _timerCounter = 0;
  }

// #endregion

// #region cache
  Future<bool> _saveCache({
    AbRequestScope? request,
    _AbMutationGuard? mutationGuard,
    BaseAb? expectedModel,
  }) async {
    final saveSequence = ++_cacheSaveSequence;
    final expected = expectedModel ?? current;
    final generationKey = request?.generationKey ?? expected.stateGenerationKey;
    final generationHandle =
        request?.handleJson ?? expected.stateGenerationHandle;
    final trackedModels = <String, BaseAb>{};
    final entries = <Map<String, dynamic>>[];
    var sameGeneration = true;
    addressbooks.forEach((key, value) {
      if (!value.isPersonal() && key != _currentName.value) return;
      if (!isWeb && value.stateGenerationKey != generationKey) {
        sameGeneration = false;
        return;
      }
      trackedModels[key] = value;
      entries.add(_serializeCacheEntry(key, value));
    });
    MapEntry<String, BaseAb>? expectedEntry;
    for (final entry in addressbooks.entries) {
      if (identical(entry.value, expected)) {
        expectedEntry = entry;
        break;
      }
    }
    if (!sameGeneration ||
        expectedEntry == null ||
        (!isWeb &&
            (generationKey == null ||
                generationHandle == null ||
                generationHandle.isEmpty))) {
      return false;
    }
    trackedModels.putIfAbsent(expectedEntry.key, () => expected);
    String? namespace =
        request?.authNamespace ?? _namespaceFromHandle(generationHandle);
    final capture = _AbCacheCapture(
      entriesJson: jsonEncode(entries),
      stateRevision: _stateRevision,
      currentName: _currentName.value,
      models: Map<String, BaseAb>.unmodifiable(trackedModels),
      generationKey: generationKey,
      generationHandle: generationHandle,
      authNamespace: namespace,
    );

    try {
      namespace ??= await getAuthCacheNamespace();
      if (namespace == null) return false;
      final payload = jsonEncode(<String, dynamic>{
        "auth_namespace": namespace,
        "ab_entries": jsonDecode(capture.entriesJson),
      });
      bool sameState() {
        if (_cacheSaveSequence != saveSequence ||
            _stateRevision != capture.stateRevision ||
            _currentName.value != capture.currentName ||
            (mutationGuard != null && !mutationGuard.sameState)) {
          return false;
        }
        for (final entry in capture.models.entries) {
          if (!identical(addressbooks[entry.key], entry.value) ||
              (!isWeb &&
                  entry.value.stateGenerationKey != capture.generationKey)) {
            return false;
          }
        }
        return true;
      }

      final stateGuard = StateGenerationGuard(
        sameState: sameState,
        sameGeneration: () async {
          if (isWeb) {
            return await getAuthCacheNamespace() == namespace;
          }
          return await AbRequestScope.isHandleCurrent(capture.generationHandle);
        },
      );
      var nativeSaved = true;
      final committed = await stateGuard.commitFrozen<String>(
        payload,
        (frozen) async {
          if (isWeb) {
            await bind.mainSaveAb(json: frozen);
          } else {
            nativeSaved = await bind.mainAuthSaveAbCacheIfCurrent(
              handleJson: capture.generationHandle!,
              payloadJson: frozen,
            );
          }
        },
      );
      if (committed && nativeSaved) {
        _cacheGenerationHandle = capture.generationHandle;
        _cacheAuthNamespace = namespace;
        return true;
      }
      return false;
    } catch (e) {
      debugPrint('ab save:$e');
      return false;
    }
  }

  String? _namespaceFromHandle(String? handle) {
    if (handle == null || handle.isEmpty) return null;
    try {
      return AuthRequestGeneration.fromHandleJson(handle).cursorKey;
    } catch (_) {
      return null;
    }
  }

  Map<String, dynamic> _serializeCacheEntry(String key, BaseAb value) {
    return {
      "kind": value is Issue9Ab
          ? "issue9_v2"
          : value is LegacyAb
              ? "legacy"
              : "commercial",
      "guid": value.sharedProfile()?.guid ?? '',
      "name": key,
      "tags": value.tags.toList(growable: false),
      "peers": value.peers
          .map((e) => e.toAddressBookCacheJson(
              includingHash: value.isPersonal() && value is! Issue9Ab))
          .toList(growable: false),
      "tag_colors": jsonEncode(Map<String, int>.from(value.tagColors))
    };
  }

  trySetCurrentToLast() {
    final name = bind.getLocalFlutterOption(k: kOptionCurrentAbName);
    if (addressbooks.containsKey(name)) {
      _currentName.value = name;
    }
  }

  Future<void> loadCache() async {
    try {
      if (_cacheLoadOnceFlag || currentAbLoading.value) return;
      _cacheLoadOnceFlag = true;
      AbRequestScope? request;
      String? namespace;
      if (isWeb) {
        namespace = await getAuthCacheNamespace();
      } else {
        request = await AbRequestScope.create();
        namespace = request.authNamespace;
      }
      if (namespace == null) return;
      final cache = await bind.mainLoadAb();
      if (currentAbLoading.value) return;
      final data = jsonDecode(cache);
      if (data is! Map<String, dynamic> ||
          data['auth_namespace'] != namespace) {
        return;
      }
      final GenerationCommitReceipt? receipt;
      if (isWeb) {
        receipt = _visibleCommit.replaceLocal<Map<String, dynamic>>(
          data,
          _deserializeCache,
        );
      } else {
        final generation = request?.generation;
        if (request == null || generation == null) return;
        receipt = await _visibleCommit.commit<Map<String, dynamic>>(
          generation: generation,
          isGenerationCurrent: (expected) async =>
              request!.generation?.sameAs(expected) == true &&
              await request.isCurrent(),
          payload: data,
          apply: (payload) {
            _visibleGeneration = generation;
            _deserializeCache(payload);
            for (final model in addressbooks.values) {
              model.bindVisibleGeneration(generation);
            }
          },
          rollback: (stillOwned) {
            if (stillOwned()) {
              _clearVisibleListForGenerationRollback();
            }
          },
        );
        if (receipt == null && _visibleGeneration?.sameAs(generation) == true) {
          _visibleCommit.invalidate();
          _clearVisibleListForGenerationRollback();
        }
      }
      if (!_visibleCommit.owns(receipt)) return;
      _cacheGenerationHandle = request?.handleJson;
      _cacheAuthNamespace = namespace;
      legacyMode.value = addressbooks.containsKey(_legacyAddressBookName);
      trySetCurrentToLast();
    } catch (e) {
      debugPrint("load ab cache: $e");
    }
  }

  void _resetForCacheRestore() {
    AbRequestScope.invalidateActiveGeneration();
    for (final model in addressbooks.values) {
      model.invalidateVisibleCommit();
    }
    _stateRevision += 1;
    _cacheSaveSequence += 1;
    addressbooks.clear();
    _currentName.value = '';
    _listPullError.value = '';
    _pulledOnce = false;
    _issue9Mode = false;
    _legacyConfirmed = false;
    legacyMode.value = false;
    _personalAbGuid = null;
    _maxPeerOneAb = 0;
    _issue9FirstPage = null;
    _issue9FirstResult = null;
    _pendingIssue9Ack = null;
    _pendingIssue9Target = null;
    _syncAllFromRecent = true;
    _syncFromRecentLock = false;
    _addressBookConsumerGeneration = null;
    _issue9RefreshPending = false;
    _cacheGenerationHandle = null;
    _cacheAuthNamespace = null;
    listInitialized = false;
  }

  void _deserializeCache(dynamic data) {
    if (data == null) return;
    _resetForCacheRestore();
    final abEntries = data['ab_entries'];
    if (abEntries is List) {
      for (var i = 0; i < abEntries.length; i++) {
        var abEntry = abEntries[i];
        if (abEntry is Map<String, dynamic>) {
          var guid = abEntry['guid'];
          var name = abEntry['name'];
          var kind = abEntry['kind'];
          final BaseAb ab;
          if (kind == 'issue9_v2' || name == _issue9AddressBookName) {
            ab = Issue9Ab(
              _pullIssue9AddressBook,
              (result) {
                _pendingIssue9Ack = result.request;
                _pendingIssue9Target = result.target;
              },
            );
          } else if (kind == 'legacy' || name == _legacyAddressBookName) {
            ab = LegacyAb();
          } else {
            if (name == null || guid == null) {
              continue;
            }
            ab = Ab(AbProfile(guid, name, '', '', ShareRule.read.value, null),
                name == _personalAddressBookName);
          }
          addressbooks[name] = ab;
          if (abEntry['tags'] is List) {
            ab.tags.value =
                (abEntry['tags'] as List).map((e) => e.toString()).toList();
          }
          if (abEntry['peers'] is List) {
            for (var peer in abEntry['peers']) {
              final cachedPeer = Peer.fromJson(peer);
              if (ab is Issue9Ab && !_validIssue9CachedPeer(cachedPeer)) {
                throw const FormatException(
                    'Invalid cached Issue #9 address-book peer');
              }
              ab.peers.add(cachedPeer);
            }
          }
          if (abEntry['tag_colors'] is String) {
            Map<String, dynamic> map = jsonDecode(abEntry['tag_colors']);
            ab.tagColors.value = Map<String, int>.from(map);
          }
        }
      }
      if (abEntries.isNotEmpty) {
        _stateRevision += 1;
        _callbackPeerUpdate();
      }
    }
  }

  bool _validIssue9CachedPeer(Peer peer) {
    final instanceId = peer.addressBookInstanceId;
    final source = peer.addressBookSource;
    final permission = peer.addressBookPermission;
    if (instanceId == null || !RegExp(r'^[0-9a-f]{64}$').hasMatch(instanceId)) {
      return false;
    }
    if (source == 'owned') {
      return permission == 'full_control' && peer.addressBookShareId == null;
    }
    if (source == 'shared') {
      return (permission == 'view_only' || permission == 'full_control') &&
          peer.addressBookShareId != null &&
          peer.addressBookShareId! > 0;
    }
    return false;
  }

// #endregion

// #region tools
  Peer? find(String id) {
    return currentAbPeers.firstWhereOrNull((e) => e.id == id);
  }

  bool idContainByCurrent(String id) {
    return currentAbPeers.where((element) => element.id == id).isNotEmpty;
  }

  void unsetSelectedTags() {
    selectedTags.clear();
  }

  List<dynamic> getPeerTags(String id) {
    final it = currentAbPeers.where((p0) => p0.id == id);
    if (it.isEmpty) {
      return [];
    } else {
      return it.first.tags;
    }
  }

  String getPeerNote(String id) {
    final it = currentAbPeers.where((p0) => p0.id == id);
    if (it.isEmpty) {
      return '';
    } else {
      return it.first.note;
    }
  }

  Color getCurrentAbTagColor(String tag) {
    if (tag == kUntagged) {
      return MyTheme.accent;
    }
    int? colorValue = current.tagColors[tag];
    if (colorValue != null) {
      return Color(colorValue);
    }
    return str2color2(tag, existing: current.tagColors.values.toList());
  }

  List<String> addressBookNames() {
    return addressbooks.keys.toList();
  }

  String personalAddressBookName() {
    return _personalAddressBookName;
  }

  Future<void> setCurrentName(String name) async {
    final oldName = _currentName.value;
    if (addressbooks.containsKey(name)) {
      _currentName.value = name;
    } else {
      if (addressbooks.containsKey(_personalAddressBookName)) {
        _currentName.value = _personalAddressBookName;
      } else if (addressbooks.containsKey(_legacyAddressBookName)) {
        _currentName.value = _legacyAddressBookName;
      } else {
        _currentName.value = '';
      }
    }
    final guard = _captureMutation(_currentName.value);
    if (guard == null) return;
    if (!current.initialized) {
      await guard.model.pullAb(quiet: false);
    }
    if (!await guard.isCurrent()) return;
    await _refreshTab();
    if (!await guard.isCurrent()) return;
    if (oldName != _currentName.value) {
      _stateRevision += 1;
      _syncAllFromRecent = true;
      await _saveCache(
        mutationGuard: guard,
        expectedModel: guard.model,
      );
    }
  }

  bool isCurrentAbFull(bool warn) {
    final res = current.isFull();
    if (res && warn) {
      BotToast.showText(
          contentColor: Colors.red, text: translate('exceed_max_devices'));
    }
    return res;
  }

  Future<void> _refreshTab() async {
    await platformFFI.tryHandle({'name': LoadEvent.addressBook});
  }

  List<String> idExistIn(String id) {
    List<String> v = [];
    addressbooks.forEach((key, value) {
      if (value.peers.any((e) => e.id == id)) {
        v.add(key);
      }
    });
    return v;
  }

  List<Peer> allPeers() {
    List<Peer> v = [];
    addressbooks.forEach((key, value) {
      v.addAll(value.peers.map((e) => Peer.copy(e)).toList());
    });
    return v;
  }

  String translatedName(String name) {
    if (name == _personalAddressBookName || name == _legacyAddressBookName) {
      return translate(name);
    } else {
      return name;
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

  String? getdefaultSharedPassword() {
    if (current.isPersonal()) {
      return null;
    }
    final profile = current.sharedProfile();
    if (profile == null) {
      return null;
    }
    try {
      if (profile.info is Map) {
        final password = (profile.info as Map)['password'];
        if (password is String && password.isNotEmpty) {
          return password;
        }
      }
      return null;
    } catch (e) {
      debugPrint("getdefaultSharedPassword: $e");
      return null;
    }
  }

// #endregion
}

abstract class BaseAb {
  final peers = List<Peer>.empty(growable: true).obs;
  final RxList<String> tags = <String>[].obs;
  final RxMap<String, int> tagColors = Map<String, int>.fromEntries([]).obs;
  final selectedTags = List<String>.empty(growable: true).obs;
  final GenerationCommitCoordinator _visibleCommit =
      GenerationCommitCoordinator();
  AuthRequestGeneration? _visibleGeneration;

  final pullError = "".obs;
  final pushError = "".obs;
  final abLoading = false
      .obs; // Indicates whether the UI should show a loading state for the address book.
  var abPulling =
      false; // Tracks whether a pull operation is currently in progress to prevent concurrent pulls. Unlike abLoading, this is not tied to UI updates.
  bool initialized = false;

  String? get stateGenerationKey => null;

  String? get stateGenerationHandle => null;

  String? get personalHashSource => null;

  void invalidateVisibleCommit() {
    _visibleCommit.invalidate();
  }

  void bindVisibleGeneration(AuthRequestGeneration generation) {
    _visibleGeneration = generation;
  }

  Future<GenerationCommitReceipt?> commitVisibleForRequest<T>({
    required AbRequestScope request,
    required T payload,
    required void Function(T payload) apply,
    required void Function() rollback,
  }) async {
    if (isWeb) {
      return _visibleCommit.replaceLocal(payload, apply);
    }
    final generation = request.generation;
    if (generation == null) return null;
    final receipt = await _visibleCommit.commit<T>(
      generation: generation,
      isGenerationCurrent: (expected) async =>
          request.generation?.sameAs(expected) == true &&
          await request.isCurrent(),
      payload: payload,
      apply: (value) {
        _visibleGeneration = generation;
        apply(value);
      },
      rollback: (stillOwned) {
        if (stillOwned()) {
          rollback();
        }
      },
    );
    if (receipt == null) {
      _clearVisibleGenerationIfOwned(generation);
    }
    return receipt;
  }

  bool ownsVisibleCommit(GenerationCommitReceipt? receipt) =>
      _visibleCommit.owns(receipt);

  Future<bool> commitVisibleErrorForRequest({
    required AbRequestScope request,
    required RxString target,
    required String error,
  }) async {
    final GenerationCommitReceipt? receipt;
    if (isWeb) {
      receipt = _visibleCommit.replaceLocal<String>(
        error,
        (value) => target.value = value,
      );
    } else {
      final generation = request.generation;
      if (generation == null) return false;
      receipt = await _visibleCommit.commit<String>(
        generation: generation,
        isGenerationCurrent: (expected) async =>
            request.generation?.sameAs(expected) == true &&
            await request.isCurrent(),
        payload: error,
        apply: (value) => target.value = value,
        rollback: (stillOwned) {
          if (stillOwned()) {
            target.value = '';
          }
        },
      );
      if (receipt == null) {
        _clearVisibleGenerationIfOwned(generation);
      }
    }
    return _visibleCommit.owns(receipt);
  }

  void clearVisibleDataForGenerationRollback() {
    _visibleGeneration = null;
    initialized = false;
    peers.clear();
    tags.clear();
    tagColors.clear();
    selectedTags.clear();
    pullError.value = '';
    pushError.value = '';
  }

  void _clearVisibleGenerationIfOwned(AuthRequestGeneration generation) {
    if (_visibleGeneration?.sameAs(generation) != true) return;
    _visibleCommit.invalidate();
    clearVisibleDataForGenerationRollback();
  }

  Future<bool> _replacePersonalHashAllowlist(AbRequestScope request) async {
    final source = personalHashSource;
    if (source == null || isWeb) return true;
    final handle = request.handleJson;
    final receipt = request.personalHashReceipt;
    if (handle == null ||
        receipt == null ||
        receipt.isEmpty ||
        !await request.isCurrent()) {
      return false;
    }
    try {
      final replaced = await bind.mainAuthCommitPersonalHashReceipt(
        handleJson: handle,
        receiptId: receipt,
      );
      if (replaced) {
        request.personalHashReceipt = null;
      }
      return replaced && await request.isCurrent();
    } catch (_) {
      return false;
    }
  }

  Future<bool> clearPersonalHashAllowlistIfCurrent(
      AbRequestScope request) async {
    if (personalHashSource == null || isWeb) return true;
    final handle = request.handleJson;
    if (handle == null || !await request.isCurrent()) return false;
    try {
      final cleared = await bind.mainAuthClearPersonalHashAllowlistIfCurrent(
          handleJson: handle);
      return cleared && await request.isCurrent();
    } catch (_) {
      return false;
    }
  }

  Future<bool> boundStateIsCurrent() async {
    if (!identical(gFFI.abModel.addressbooks[name()], this)) return false;
    if (isWeb) return true;
    final generation = stateGenerationKey;
    final handle = stateGenerationHandle;
    return generation != null &&
        handle != null &&
        AbRequestScope.isActiveGeneration(generation) &&
        await AbRequestScope.isHandleCurrent(handle) &&
        identical(gFFI.abModel.addressbooks[name()], this);
  }

  String name();

  bool isPersonal() {
    return name() == _personalAddressBookName ||
        name() == _legacyAddressBookName ||
        name() == _issue9AddressBookName;
  }

  bool isLegacy() {
    return name() == _legacyAddressBookName;
  }

  Future<void> pullAb({quiet = false, AbRequestScope? requestScope}) async {
    if (abPulling) return;
    abPulling = true;
    if (!quiet) {
      abLoading.value = true;
      pullError.value = "";
    }
    initialized = false;
    debugPrint("pull ab \"${name()}\"");
    AbRequestScope? request = requestScope;
    try {
      request ??= await AbRequestScope.create();
      final pulled = await pullAbImpl(quiet: quiet, requestScope: request);
      if (request.unauthorized) {
        await request.clearVisibleStateIfUnauthorized();
      } else if (await request.isCurrent()) {
        if (pulled && !await _replacePersonalHashAllowlist(request)) {
          return;
        }
        initialized = pulled;
      }
    } catch (e) {
      if (request != null && await request.isCurrent()) {
        debugPrint("Error occurred while pulling address book: $e");
      }
    } finally {
      abLoading.value = false;
      abPulling = false;
    }
  }

  Future<bool> pullAbImpl({quiet = false, AbRequestScope? requestScope});

  Future<String?> addPeers(List<Map<String, dynamic>> ps);
  removeHash(Map<String, dynamic> p) {
    p.remove('hash');
  }

  removePassword(Map<String, dynamic> p) {
    p.remove('password');
  }

  removeNonExistentTags(Map<String, dynamic> p) {
    try {
      final oldTags = p.remove('tags');
      if (oldTags is List) {
        final newTags = oldTags.where((e) => tagContainBy(e)).toList();
        p['tags'] = newTags;
      }
    } catch (e) {
      print("removeNonExistentTags: $e");
    }
  }

  Future<bool> changeTagForPeers(List<String> ids, List<dynamic> tags);

  Future<bool> changeAlias({required String id, required String alias});

  Future<bool> changeNote({required String id, required String note});

  Future<bool> changePersonalHashPassword(String id, String hash);

  Future<bool> changeSharedPassword(String id, String password);

  Future<bool> deletePeers(List<String> ids);

  Future<bool> addTags(List<String> tagList, Map<String, int> tagColorMap);

  bool tagContainBy(String tag) {
    return tags.where((element) => element == tag).isNotEmpty;
  }

  Future<bool> renameTag(String oldTag, String newTag);

  Future<bool> setTagColor(String tag, Color color);

  Future<bool> deleteTag(String tag);

  bool isFull();

  void setSharedProfile(AbProfile profile);

  AbProfile? sharedProfile();

  bool canWrite();

  bool fullControl();

  Future<void> syncFromRecent(List<Peer> recents);
}

class _LegacyAbDraft {
  final List<Peer> peers;
  final List<String> tags;
  final Map<String, int> tagColors;

  _LegacyAbDraft(this.peers, this.tags, this.tagColors);
}

class _LegacyPullState {
  final int licensedDevices;
  final bool empty;
  final Map<String, dynamic>? data;

  const _LegacyPullState({
    required this.licensedDevices,
    required this.empty,
    required this.data,
  });
}

class LegacyAb extends BaseAb {
  bool get emtpy => peers.isEmpty && tags.isEmpty;
  // licensedDevices is obtained from personal ab, shared ab restrict it in server
  var licensedDevices = 0;
  bool writableConfirmed;
  String? _generationKey;
  String? _generationHandleJson;

  LegacyAb({this.writableConfirmed = false, String? generationKey})
      : _generationKey = generationKey;

  @override
  String? get stateGenerationKey => _generationKey;

  @override
  String? get stateGenerationHandle => _generationHandleJson;

  @override
  String? get personalHashSource => 'legacy_personal';

  void confirmFor(AbRequestScope request) {
    _generationKey = request.generationKey;
    _generationHandleJson = request.handleJson;
  }

  bool accepts(AbRequestScope request) {
    return request.matchesGeneration(_generationKey);
  }

  _LegacyAbDraft _createDraft() {
    final draftPeers = peers.map((peer) {
      final copy = Peer.copy(peer);
      copy.tags = peer.tags.toList();
      return copy;
    }).toList(growable: true);
    return _LegacyAbDraft(
      draftPeers,
      tags.toList(growable: true),
      Map<String, int>.from(tagColors),
    );
  }

  void _commitDraft(_LegacyAbDraft draft) {
    peers.assignAll(draft.peers);
    tags.assignAll(draft.tags);
    tagColors.assignAll(draft.tagColors);
  }

  @override
  AbProfile? sharedProfile() {
    return null;
  }

  @override
  void setSharedProfile(AbProfile? profile) {}

  @override
  bool canWrite() {
    return writableConfirmed &&
        AbRequestScope.isActiveGeneration(_generationKey);
  }

  @override
  bool fullControl() {
    return writableConfirmed &&
        AbRequestScope.isActiveGeneration(_generationKey);
  }

  @override
  bool isFull() {
    return licensedDevices > 0 && peers.length >= licensedDevices;
  }

  @override
  String name() {
    return _legacyAddressBookName;
  }

  @override
  Future<bool> pullAbImpl({quiet = false, AbRequestScope? requestScope}) async {
    final request = requestScope ?? await AbRequestScope.create();
    if (writableConfirmed && !accepts(request)) return false;
    final api = "${request.apiBase}/api/ab";
    try {
      final resp = await request.send(
        http.HttpMethod.get,
        Uri.parse(api),
        headers: const {
          'Content-Type': 'application/json',
          'Accept-Encoding': 'gzip',
        },
      );
      if (resp.statusCode != 200) {
        throw 'HTTP ${resp.statusCode}';
      }
      Map<String, dynamic>? data;
      int nextLicensedDevices = licensedDevices;
      var empty = false;
      final responseBody = decode_http_response(resp).trim();
      if (responseBody.toLowerCase() == "null") {
        empty = true;
      } else {
        if (responseBody.isEmpty) {
          throw const FormatException('Invalid legacy address-book response');
        }
        final Map<String, dynamic> json =
            _jsonDecodeRespMap(responseBody, resp.statusCode);
        if (json.containsKey('error')) {
          throw json['error'];
        }
        if (!json.containsKey('data') || json['data'] is! String) {
          throw const FormatException('Invalid legacy address-book payload');
        }
        if (json['licensed_devices'] is int) {
          nextLicensedDevices = json['licensed_devices'] as int;
        }
        final decodedData = jsonDecode(json['data'] as String);
        if (decodedData == null) {
          empty = true;
        } else if (decodedData is Map<String, dynamic>) {
          data = decodedData;
        } else {
          throw const FormatException('Invalid legacy address-book data');
        }
      }
      final receipt = await commitVisibleForRequest<_LegacyPullState>(
        request: request,
        payload: _LegacyPullState(
          licensedDevices: nextLicensedDevices,
          empty: empty,
          data: data,
        ),
        apply: (state) {
          licensedDevices = state.licensedDevices;
          if (state.empty) {
            tags.clear();
            tagColors.clear();
            peers.clear();
          } else if (state.data != null) {
            _deserialize(state.data!);
          }
        },
        rollback: () {
          licensedDevices = 0;
          clearVisibleDataForGenerationRollback();
        },
      );
      return ownsVisibleCommit(receipt);
    } catch (err) {
      if (!quiet) {
        await commitVisibleErrorForRequest(
          request: request,
          target: pullError,
          error:
              '${translate('pull_ab_failed_tip')}: ${translate(err.toString())}',
        );
      }
    } finally {
      await request.clearVisibleStateIfUnauthorized();
    }
    return false;
  }

  Future<bool> _pushDraft(
    _LegacyAbDraft draft, {
    bool toastIfFail = true,
    bool toastIfSucc = true,
  }) async {
    debugPrint("pushAb: toastIfFail:$toastIfFail, toastIfSucc:$toastIfSucc");
    if (!canWrite()) return false;
    if (!gFFI.userModel.isLogin) return false;
    pushError.value = '';
    bool ret = false;
    AbRequestScope? request;
    try {
      request = await AbRequestScope.create();
      if (!accepts(request) || !await request.isCurrent()) return false;
      if (!await clearPersonalHashAllowlistIfCurrent(request)) {
        return false;
      }
      final api = "${request.apiBase}/api/ab";
      final body = jsonEncode({"data": jsonEncode(_serializeDraft(draft))});
      final resp = await request.send(
        http.HttpMethod.post,
        Uri.parse(api),
        headers: const {'Content-Type': 'application/json'},
        body: body,
      );
      if (resp.statusCode == 200 &&
          (resp.body.isEmpty || resp.body.toLowerCase() == 'null')) {
        ret = true;
      } else {
        Map<String, dynamic> json =
            _jsonDecodeRespMap(decode_http_response(resp), resp.statusCode);
        if (json.containsKey('error')) {
          throw json['error'];
        } else if (resp.statusCode == 200) {
          ret = true;
        } else {
          throw 'HTTP ${resp.statusCode}';
        }
      }
    } catch (e) {
      if (request != null) {
        await commitVisibleErrorForRequest(
          request: request,
          target: pushError,
          error:
              '${translate('push_ab_failed_tip')}: ${translate(e.toString())}',
        );
      }
    } finally {
      await request?.clearVisibleStateIfUnauthorized();
    }

    if (request == null || !await boundStateIsCurrent()) {
      return false;
    }
    if (ret) {
      final receipt = await commitVisibleForRequest<_LegacyAbDraft>(
        request: request,
        payload: draft,
        apply: _commitDraft,
        rollback: clearVisibleDataForGenerationRollback,
      );
      return ownsVisibleCommit(receipt);
    }
    return false;
  }

  Future<bool> pushAb({bool toastIfFail = true, bool toastIfSucc = true}) =>
      _pushDraft(
        _createDraft(),
        toastIfFail: toastIfFail,
        toastIfSucc: toastIfSucc,
      );

// #region Peer
  @override
  Future<String?> addPeers(List<Map<String, dynamic>> ps) async {
    if (!canWrite()) return translate('Read-only');
    final draft = _createDraft();
    bool full = false;
    for (var p in ps) {
      if (licensedDevices <= 0 || draft.peers.length < licensedDevices) {
        p.remove('password'); // legacy ab ignore password
        final index = draft.peers.indexWhere((e) => e.id == p['id']);
        if (index >= 0) {
          _merge(Peer.fromJson(p), draft.peers[index]);
          _mergePeerFromGroup(draft.peers[index]);
        } else {
          draft.peers.add(Peer.fromJson(p));
        }
      } else {
        full = true;
        break;
      }
    }
    if (full) {
      return translate("exceed_max_devices");
    } else if (!await _pushDraft(draft)) {
      return "Failed to push to server";
    } else {
      return null;
    }
  }

  _mergePeerFromGroup(Peer p) {
    final g = gFFI.groupModel.peers.firstWhereOrNull((e) => p.id == e.id);
    if (g == null) return;
    if (p.username.isEmpty) {
      p.username = g.username;
    }
    if (p.hostname.isEmpty) {
      p.hostname = g.hostname;
    }
    if (p.platform.isEmpty) {
      p.platform = g.platform;
    }
  }

  @override
  Future<bool> changeTagForPeers(List<String> ids, List<dynamic> tags) async {
    if (!canWrite()) return false;
    final draft = _createDraft();
    draft.peers.map((e) {
      if (ids.contains(e.id)) {
        e.tags = tags.toList();
      }
    }).toList();
    return await _pushDraft(draft);
  }

  @override
  Future<bool> changeAlias({required String id, required String alias}) async {
    if (!canWrite()) return false;
    final draft = _createDraft();
    final it = draft.peers.where((element) => element.id == id);
    if (it.isEmpty) {
      return false;
    }
    it.first.alias = alias;
    return await _pushDraft(draft);
  }

  @override
  Future<bool> changeNote({required String id, required String note}) async {
    // no need to implement
    return false;
  }

  @override
  Future<bool> changeSharedPassword(String id, String password) async {
    // no need to implement
    return false;
  }

  @override
  Future<void> syncFromRecent(List<Peer> recents) async {
    if (!canWrite()) return;
    final draft = _createDraft();
    bool peerSyncEqual(Peer a, Peer b) {
      return a.hash == b.hash &&
          a.username == b.username &&
          a.platform == b.platform &&
          a.hostname == b.hostname &&
          a.alias == b.alias;
    }

    bool needSync = false;
    for (var i = 0; i < recents.length; i++) {
      var r = recents[i];
      var index = draft.peers.indexWhere((e) => e.id == r.id);
      if (index < 0) {
        if (licensedDevices <= 0 || draft.peers.length < licensedDevices) {
          draft.peers.add(Peer.copy(r));
          needSync = true;
        }
      } else {
        Peer old = Peer.copy(draft.peers[index]);
        _merge(r, draft.peers[index]);
        if (!peerSyncEqual(draft.peers[index], old)) {
          needSync = true;
        }
      }
    }
    if (needSync) {
      if (await _pushDraft(
        draft,
        toastIfSucc: false,
        toastIfFail: false,
      )) {
        final guard = gFFI.abModel._captureMutation(name());
        if (guard == null || !await guard.isCurrent()) return;
        gFFI.abModel._stateRevision += 1;
        if (gFFI.abModel.currentName.value == name()) {
          await gFFI.abModel._refreshTab();
        }
        if (!await guard.isCurrent()) return;
        await gFFI.abModel._saveCache(
          mutationGuard: guard,
          expectedModel: this,
        );
      }
    }
    // Pull cannot be used for sync to avoid cyclic sync.
  }

  void _merge(Peer r, Peer p) {
    p.hash = r.hash.isEmpty ? p.hash : r.hash;
    p.username = r.username.isEmpty ? p.username : r.username;
    p.hostname = r.hostname.isEmpty ? p.hostname : r.hostname;
    p.platform = r.platform.isEmpty ? p.platform : r.platform;
    p.alias = p.alias.isEmpty ? r.alias : p.alias;
  }

  @override
  Future<bool> changePersonalHashPassword(String id, String hash) async {
    if (!canWrite()) return false;
    final draft = _createDraft();
    bool changed = false;
    final it = draft.peers.where((element) => element.id == id);
    if (it.isNotEmpty) {
      if (it.first.hash != hash) {
        it.first.hash = hash;
        changed = true;
      }
    }
    if (changed) {
      return await _pushDraft(
        draft,
        toastIfSucc: false,
        toastIfFail: false,
      );
    }
    return true;
  }

  @override
  Future<bool> deletePeers(List<String> ids) async {
    if (!canWrite()) return false;
    final draft = _createDraft();
    draft.peers.removeWhere((e) => ids.contains(e.id));
    return await _pushDraft(draft);
  }
// #endregion

// #region Tag
  @override
  Future<bool> addTags(
      List<String> tagList, Map<String, int> tagColorMap) async {
    if (!canWrite()) return false;
    final draft = _createDraft();
    for (var e in tagList) {
      if (!draft.tags.contains(e)) {
        draft.tags.add(e);
      }
      if (draft.tagColors[e] == null) {
        draft.tagColors[e] =
            str2color2(e, existing: draft.tagColors.values.toList()).value;
      }
    }
    return await _pushDraft(draft);
  }

  @override
  Future<bool> renameTag(String oldTag, String newTag) async {
    if (!canWrite()) return false;
    final draft = _createDraft();
    if (draft.tags.contains(newTag)) {
      pushError.value = 'Tag $newTag already exists';
      return false;
    }
    draft.tags.replaceRange(
      0,
      draft.tags.length,
      draft.tags.map((e) => e == oldTag ? newTag : e).toList(growable: false),
    );
    for (var peer in draft.peers) {
      peer.tags = peer.tags.map((e) {
        if (e == oldTag) {
          return newTag;
        } else {
          return e;
        }
      }).toList();
    }
    int? oldColor = draft.tagColors[oldTag];
    if (oldColor != null) {
      draft.tagColors.remove(oldTag);
      draft.tagColors.addAll({newTag: oldColor});
    }
    return await _pushDraft(draft);
  }

  @override
  Future<bool> setTagColor(String tag, Color color) async {
    if (!canWrite()) return false;
    final draft = _createDraft();
    if (draft.tags.contains(tag)) {
      draft.tagColors[tag] = color.value;
    }
    return await _pushDraft(draft);
  }

  @override
  Future<bool> deleteTag(String tag) async {
    if (!canWrite()) return false;
    final draft = _createDraft();
    draft.tags.removeWhere((element) => element == tag);
    draft.tagColors.remove(tag);
    for (var peer in draft.peers) {
      if (peer.tags.isEmpty) {
        continue;
      }
      if (peer.tags.contains(tag)) {
        peer.tags.remove(tag);
      }
    }
    return await _pushDraft(draft);
  }

// #endregion

  Map<String, dynamic> _serializeDraft(_LegacyAbDraft draft) {
    final peersJsonData =
        draft.peers.map((e) => e.toCustomJson(includingHash: true)).toList();
    for (var e in draft.tags) {
      if (draft.tagColors[e] == null) {
        draft.tagColors[e] =
            str2color2(e, existing: draft.tagColors.values.toList()).value;
      }
    }
    final tagColorJsonData = jsonEncode(draft.tagColors);
    return {
      "tags": draft.tags,
      "peers": peersJsonData,
      "tag_colors": tagColorJsonData
    };
  }

  _deserialize(dynamic data) {
    if (data == null) return;
    final oldOnlineIDs = peers.where((e) => e.online).map((e) => e.id).toList();
    tags.clear();
    tagColors.clear();
    peers.clear();
    if (data['tags'] is List) {
      tags.value = (data['tags'] as List).map((e) => e.toString()).toList();
    }
    if (data['peers'] is List) {
      for (final peer in data['peers']) {
        peers.add(Peer.fromJson(peer));
      }
    }
    if (isFull()) {
      peers.removeRange(licensedDevices, peers.length);
    }
    // restore online
    peers
        .where((e) => oldOnlineIDs.contains(e.id))
        .map((e) => e.online = true)
        .toList();
    if (data['tag_colors'] is String) {
      Map<String, dynamic> map = jsonDecode(data['tag_colors']);
      tagColors.value = Map<String, int>.from(map);
    }
    // add color to tag
    final tagsWithoutColor =
        tags.toList().where((e) => !tagColors.containsKey(e)).toList();
    for (var t in tagsWithoutColor) {
      tagColors[t] = str2color2(t, existing: tagColors.values.toList()).value;
    }
  }
}

class Issue9Ab extends LegacyAb {
  final Future<Issue9PullResult> Function(List<Peer>) puller;
  final void Function(Issue9PullResult) onCommitted;

  Issue9Ab(this.puller, this.onCommitted);

  @override
  String name() => _issue9AddressBookName;

  @override
  String? get personalHashSource => null;

  @override
  bool canWrite() => false;

  @override
  bool fullControl() => false;

  @override
  bool isFull() => true;

  @override
  Future<bool> pullAbImpl({quiet = false, AbRequestScope? requestScope}) async {
    final scope = requestScope ?? await AbRequestScope.create();
    try {
      final result = await puller(peers.toList(growable: false));
      if (scope.handleJson != result.request.handleJson ||
          !await scope.isCurrent() ||
          !await result.request.isCurrent()) {
        return false;
      }
      final online = {
        for (final peer in peers) peer.id: peer.online,
      };
      final receipt = await commitVisibleForRequest<Issue9PullResult>(
        request: scope,
        payload: result,
        apply: (state) {
          peers.assignAll(state.peers);
          for (final peer in peers) {
            peer.online = online[peer.id] ?? false;
          }
          tags.clear();
          tagColors.clear();
        },
        rollback: clearVisibleDataForGenerationRollback,
      );
      if (!ownsVisibleCommit(receipt) ||
          !await result.request.isCurrent() ||
          !ownsVisibleCommit(receipt)) {
        return false;
      }
      confirmFor(scope);
      onCommitted(result);
      return true;
    } catch (error) {
      if (!quiet) {
        await commitVisibleErrorForRequest(
          request: scope,
          target: pullError,
          error:
              '${translate('pull_ab_failed_tip')}: ${translate(error.toString())}',
        );
      }
      return false;
    }
  }
}

class _CommercialAbState {
  final List<Peer> peers;
  final List<String> tags;
  final Map<String, int> tagColors;

  const _CommercialAbState({
    required this.peers,
    required this.tags,
    required this.tagColors,
  });
}

class Ab extends BaseAb {
  AbProfile profile;
  late final bool personal;
  bool writableConfirmed;
  String? _generationKey;
  String? _generationHandleJson;
  bool get emtpy => peers.isEmpty && tags.isEmpty;

  Ab(
    this.profile,
    this.personal, {
    this.writableConfirmed = false,
    String? generationKey,
  }) : _generationKey = generationKey;

  @override
  String? get stateGenerationKey => _generationKey;

  @override
  String? get stateGenerationHandle => _generationHandleJson;

  @override
  String? get personalHashSource => personal ? 'commercial_personal' : null;

  void confirmFor(AbRequestScope request) {
    writableConfirmed = true;
    _generationKey = request.generationKey;
    _generationHandleJson = request.handleJson;
  }

  bool accepts(AbRequestScope request) {
    return request.matchesGeneration(_generationKey);
  }

  Future<AbRequestScope?> _beginActionRequest(String path) async {
    final base = await bind.mainGetApiServer();
    final request = await AbRequestScope.create(
      apiBase: base,
      initialUri: Uri.parse('$base$path'),
    );
    return accepts(request) ? request : null;
  }

  @override
  String name() {
    if (personal) {
      return _personalAddressBookName;
    } else {
      return profile.name;
    }
  }

  @override
  AbProfile? sharedProfile() {
    return profile;
  }

  @override
  void setSharedProfile(AbProfile profile) {
    this.profile = profile;
  }

  @override
  bool isFull() {
    return gFFI.abModel._maxPeerOneAb > 0 &&
        peers.length >= gFFI.abModel._maxPeerOneAb;
  }

  @override
  bool canWrite() {
    if (!writableConfirmed ||
        !AbRequestScope.isActiveGeneration(_generationKey)) {
      return false;
    }
    if (personal) {
      return true;
    } else {
      return profile.rule == ShareRule.readWrite.value ||
          profile.rule == ShareRule.fullControl.value;
    }
  }

  @override
  bool fullControl() {
    if (!writableConfirmed ||
        !AbRequestScope.isActiveGeneration(_generationKey)) {
      return false;
    }
    if (personal) {
      return true;
    } else {
      return profile.rule == ShareRule.fullControl.value;
    }
  }

  @override
  Future<bool> pullAbImpl({quiet = false, AbRequestScope? requestScope}) async {
    final request = requestScope ?? await AbRequestScope.create();
    if (!accepts(request)) return false;
    final tmpPeers = <Peer>[];
    if (!await _fetchPeers(request, tmpPeers, quiet: quiet)) {
      return false;
    }
    if (request.unauthorized) return false;
    final tmpTags = <AbTag>[];
    if (!await _fetchTags(request, tmpTags, quiet: quiet)) {
      return false;
    }
    final tmpTagColors = <String, int>{};
    for (var t in tmpTags) {
      tmpTagColors[t.name] = t.color;
    }
    final receipt = await commitVisibleForRequest<_CommercialAbState>(
      request: request,
      payload: _CommercialAbState(
        peers: tmpPeers,
        tags: tmpTags.map((tag) => tag.name).toList(growable: false),
        tagColors: Map<String, int>.unmodifiable(tmpTagColors),
      ),
      apply: (state) {
        peers.value = state.peers;
        tags.value = state.tags;
        tagColors.value = state.tagColors;
      },
      rollback: clearVisibleDataForGenerationRollback,
    );
    return ownsVisibleCommit(receipt);
  }

  Future<bool> _fetchPeers(AbRequestScope request, List<Peer> tmpPeers,
      {quiet = false}) async {
    final api = "${request.apiBase}/api/ab/peers";
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
              'ab': profile.guid,
            });
        final headers = <String, String>{'Content-Type': 'application/json'};
        _setEmptyBody(headers);
        final resp =
            await request.send(http.HttpMethod.post, uri, headers: headers);
        final Map<String, dynamic> json =
            _jsonDecodeRespMap(decode_http_response(resp), resp.statusCode);
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
              for (final profile in data) {
                final u = Peer.fromJson(profile);
                int index = tmpPeers.indexWhere((e) => e.id == u.id);
                if (index < 0) {
                  tmpPeers.add(u);
                } else {
                  tmpPeers[index] = u;
                }
              }
            }
          }
        }
      } while (current * pageSize < total);
      return true;
    } catch (err) {
      if (!quiet) {
        await commitVisibleErrorForRequest(
          request: request,
          target: pullError,
          error:
              '${translate('pull_ab_failed_tip')}: ${translate(err.toString())}',
        );
      }
    }
    return false;
  }

  Future<bool> _fetchTags(AbRequestScope request, List<AbTag> tmpTags,
      {quiet = false}) async {
    final api = "${request.apiBase}/api/ab/tags/${profile.guid}";
    try {
      var uri0 = Uri.parse(api);
      var uri = Uri(
        scheme: uri0.scheme,
        host: uri0.host,
        path: uri0.path,
        port: uri0.port,
      );
      final headers = <String, String>{'Content-Type': 'application/json'};
      _setEmptyBody(headers);
      final resp =
          await request.send(http.HttpMethod.post, uri, headers: headers);
      final List<dynamic> json =
          _jsonDecodeRespList(decode_http_response(resp), resp.statusCode);
      if (resp.statusCode != 200) {
        throw 'HTTP ${resp.statusCode}';
      }

      for (final d in json) {
        final t = AbTag.fromJson(d);
        int index = tmpTags.indexWhere((e) => e.name == t.name);
        if (index < 0) {
          tmpTags.add(t);
        } else {
          tmpTags[index] = t;
        }
      }
      return true;
    } catch (err) {
      if (!quiet) {
        await commitVisibleErrorForRequest(
          request: request,
          target: pullError,
          error:
              '${translate('pull_ab_failed_tip')}: ${translate(err.toString())}',
        );
      }
    }
    return false;
  }

// #region Peers
  @override
  Future<String?> addPeers(List<Map<String, dynamic>> ps) async {
    if (!canWrite()) return translate('Read-only');
    AbRequestScope? request;
    try {
      final path = "/api/ab/peer/add/${profile.guid}";
      request = await _beginActionRequest(path);
      if (request == null) return null;
      if (personal && !await clearPersonalHashAllowlistIfCurrent(request)) {
        return translate('Failed to update address book');
      }
      final api = "${request.apiBase}$path";
      for (var p in ps) {
        if (peers.firstWhereOrNull((e) => e.id == p['id']) != null) {
          continue;
        }
        if (isFull()) {
          return translate("exceed_max_devices");
        }
        if (personal) {
          removePassword(p);
        } else {
          removeHash(p);
        }
        String body = jsonEncode(p);
        final resp = await request.send(
          http.HttpMethod.post,
          Uri.parse(api),
          headers: const {'Content-Type': 'application/json'},
          body: body,
        );
        final errMsg = _jsonDecodeActionResp(resp);
        if (errMsg.isNotEmpty) {
          return errMsg;
        }
      }
    } catch (err) {
      if (request != null && await request.isCurrent()) {
        return err.toString();
      }
    } finally {
      await request?.clearVisibleStateIfUnauthorized();
    }
    return null;
  }

  @override
  Future<bool> changeTagForPeers(List<String> ids, List<dynamic> tags) async {
    if (!canWrite()) return false;
    AbRequestScope? request;
    try {
      final path = "/api/ab/peer/update/${profile.guid}";
      request = await _beginActionRequest(path);
      if (request == null) return false;
      final api = "${request.apiBase}$path";
      var ret = true;
      for (var id in ids) {
        final body = jsonEncode({"id": id, "tags": tags});
        final resp = await request.send(
          http.HttpMethod.put,
          Uri.parse(api),
          headers: const {'Content-Type': 'application/json'},
          body: body,
        );
        final errMsg = _jsonDecodeActionResp(resp);
        if (errMsg.isNotEmpty) {
          pushError.value = errMsg;
          ret = false;
          break;
        }
      }
      return ret;
    } catch (err) {
      if (request != null && await request.isCurrent()) {
        debugPrint('changeTagForPeers err: ${err.toString()}');
      }
      return false;
    } finally {
      await request?.clearVisibleStateIfUnauthorized();
    }
  }

  @override
  Future<bool> changeAlias({required String id, required String alias}) async {
    if (!canWrite()) return false;
    return await _updatePeer(
      {"id": id, "alias": alias},
      errorContext: 'changeAlias',
    );
  }

  @override
  Future<bool> changeNote({required String id, required String note}) async {
    if (!canWrite()) return false;
    return await _updatePeer(
      {"id": id, "note": note},
      errorContext: 'changeNote',
    );
  }

  Future<bool> _updatePeer(
    Object bodyContent, {
    required String errorContext,
    bool invalidatesPersonalHash = false,
  }) async {
    AbRequestScope? request;
    try {
      final path = "/api/ab/peer/update/${profile.guid}";
      request = await _beginActionRequest(path);
      if (request == null) return false;
      if (invalidatesPersonalHash &&
          !await clearPersonalHashAllowlistIfCurrent(request)) {
        return false;
      }
      final api = "${request.apiBase}$path";
      final body = jsonEncode(bodyContent);
      final resp = await request.send(
        http.HttpMethod.put,
        Uri.parse(api),
        headers: const {'Content-Type': 'application/json'},
        body: body,
      );
      final errMsg = _jsonDecodeActionResp(resp);
      if (errMsg.isNotEmpty) {
        pushError.value = errMsg;
        return false;
      }
      return true;
    } catch (err) {
      if (request != null && await request.isCurrent()) {
        debugPrint('$errorContext err: ${err.toString()}');
      }
      return false;
    } finally {
      await request?.clearVisibleStateIfUnauthorized();
    }
  }

  @override
  Future<bool> changePersonalHashPassword(String id, String hash) async {
    if (!personal || !canWrite()) return false;
    if (!peers.any((e) => e.id == id)) return true;
    return await _updatePeer(
      {"id": id, "hash": hash},
      errorContext: 'changePersonalHashPassword',
      invalidatesPersonalHash: true,
    );
  }

  @override
  Future<bool> changeSharedPassword(String id, String password) async {
    if (personal || !canWrite()) return false;
    return await _updatePeer(
      {"id": id, "password": password},
      errorContext: 'changeSharedPassword',
    );
  }

  @override
  Future<void> syncFromRecent(List<Peer> recents) async {
    if (!canWrite()) return;
    AbRequestScope? request;
    try {
      final path = "/api/ab/peer/update/${profile.guid}";
      request = await _beginActionRequest(path);
      if (request == null) return;
      final actionRequest = request;
      final api = "${actionRequest.apiBase}$path";
      var uiUpdate = false;

      Future<bool> trySyncOnePeer(Peer p, Peer r) async {
        final map = <String, String>{};
        if (p.sameServer != true &&
            r.username.isNotEmpty &&
            p.username != r.username) {
          map['username'] = r.username;
        }
        if (p.sameServer != true &&
            r.hostname.isNotEmpty &&
            p.hostname != r.hostname) {
          map['hostname'] = r.hostname;
        }
        if (p.sameServer != true &&
            r.platform.isNotEmpty &&
            p.platform != r.platform) {
          map['platform'] = r.platform;
        }
        if (personal && r.hash.isNotEmpty && p.hash != r.hash) {
          map['hash'] = r.hash;
        }
        if (map.isEmpty) {
          return false;
        }
        map['id'] = p.id;
        if (map['hash'] != null &&
            !await clearPersonalHashAllowlistIfCurrent(actionRequest)) {
          return false;
        }
        final resp = await actionRequest.send(
          http.HttpMethod.put,
          Uri.parse(api),
          headers: const {'Content-Type': 'application/json'},
          body: jsonEncode(map),
        );
        final errMsg = _jsonDecodeActionResp(resp);
        if (errMsg.isNotEmpty) {
          if (await actionRequest.isCurrent()) {
            debugPrint('syncOnePeer errMsg: $errMsg');
          }
          return false;
        }
        if (!await actionRequest.isCurrent() || !await boundStateIsCurrent()) {
          return false;
        }
        if (map['username'] != null) p.username = map['username']!;
        if (map['hostname'] != null) p.hostname = map['hostname']!;
        if (map['platform'] != null) p.platform = map['platform']!;
        if (map['hash'] != null) {
          p.hash = map['hash']!;
        }
        uiUpdate = true;
        return true;
      }

      // Not add new peers because IDs that are not on the server can't be synced, then sync will happen every startup.
      for (var p in peers) {
        Peer? r = recents.firstWhereOrNull((e) => e.id == p.id);
        if (r != null) {
          await trySyncOnePeer(p, r);
        }
      }
      if (!await request.isCurrent() || !await boundStateIsCurrent()) return;
      // Pull cannot be used for sync to avoid cyclic sync.
      if (uiUpdate && gFFI.abModel.currentName.value == profile.name) {
        peers.refresh();
      }
      if (uiUpdate) {
        gFFI.abModel._stateRevision += 1;
        await gFFI.abModel._saveCache(
          request: request,
          expectedModel: this,
        );
      }
    } catch (err) {
      if (request != null && await request.isCurrent()) {
        debugPrint('syncFromRecent err: ${err.toString()}');
      }
    } finally {
      await request?.clearVisibleStateIfUnauthorized();
    }
  }

  @override
  Future<bool> deletePeers(List<String> ids) async {
    if (!canWrite()) return false;
    AbRequestScope? request;
    try {
      final path = "/api/ab/peer/${profile.guid}";
      request = await _beginActionRequest(path);
      if (request == null) return false;
      if (personal && !await clearPersonalHashAllowlistIfCurrent(request)) {
        return false;
      }
      final api = "${request.apiBase}$path";
      final body = jsonEncode(ids);
      final resp = await request.send(
        http.HttpMethod.delete,
        Uri.parse(api),
        headers: const {'Content-Type': 'application/json'},
        body: body,
      );
      final errMsg = _jsonDecodeActionResp(resp);
      if (errMsg.isNotEmpty) {
        pushError.value = errMsg;
        return false;
      }
      return true;
    } catch (err) {
      if (request != null && await request.isCurrent()) {
        debugPrint('deletePeers err: ${err.toString()}');
      }
      return false;
    } finally {
      await request?.clearVisibleStateIfUnauthorized();
    }
  }
// #endregion

// #region Tags
  @override
  Future<bool> addTags(
      List<String> tagList, Map<String, int> tagColorMap) async {
    if (!canWrite()) return false;
    AbRequestScope? request;
    try {
      final path = "/api/ab/tag/add/${profile.guid}";
      request = await _beginActionRequest(path);
      if (request == null) return false;
      final api = "${request.apiBase}$path";
      for (var t in tagList) {
        final body = jsonEncode({
          "name": t,
          "color": tagColorMap[t] ??
              str2color2(t, existing: tagColors.values.toList()).value,
        });
        final resp = await request.send(
          http.HttpMethod.post,
          Uri.parse(api),
          headers: const {'Content-Type': 'application/json'},
          body: body,
        );
        final errMsg = _jsonDecodeActionResp(resp);
        if (errMsg.isNotEmpty) {
          pushError.value = errMsg;
          return false;
        }
      }
      return true;
    } catch (err) {
      if (request != null && await request.isCurrent()) {
        debugPrint('addTags err: ${err.toString()}');
      }
      return false;
    } finally {
      await request?.clearVisibleStateIfUnauthorized();
    }
  }

  @override
  Future<bool> renameTag(String oldTag, String newTag) async {
    if (!canWrite()) return false;
    if (tags.contains(newTag)) {
      pushError.value = 'Tag $newTag already exists';
      return false;
    }
    return await _performTagAction(
      http.HttpMethod.put,
      "/api/ab/tag/rename/${profile.guid}",
      {
        "old": oldTag,
        "new": newTag,
      },
      errorContext: 'renameTag',
    );
  }

  @override
  Future<bool> setTagColor(String tag, Color color) async {
    if (!canWrite()) return false;
    return await _performTagAction(
      http.HttpMethod.put,
      "/api/ab/tag/update/${profile.guid}",
      {
        "name": tag,
        "color": color.value,
      },
      errorContext: 'setTagColor',
    );
  }

  @override
  Future<bool> deleteTag(String tag) async {
    if (!canWrite()) return false;
    return await _performTagAction(
      http.HttpMethod.delete,
      "/api/ab/tag/${profile.guid}",
      [tag],
      errorContext: 'deleteTag',
    );
  }

  Future<bool> _performTagAction(
    http.HttpMethod method,
    String path,
    Object bodyContent, {
    required String errorContext,
  }) async {
    AbRequestScope? request;
    try {
      request = await _beginActionRequest(path);
      if (request == null) return false;
      final resp = await request.send(
        method,
        Uri.parse('${request.apiBase}$path'),
        headers: const {'Content-Type': 'application/json'},
        body: jsonEncode(bodyContent),
      );
      final errMsg = _jsonDecodeActionResp(resp);
      if (errMsg.isNotEmpty) {
        pushError.value = errMsg;
        return false;
      }
      return true;
    } catch (err) {
      if (request != null && await request.isCurrent()) {
        debugPrint('$errorContext err: ${err.toString()}');
      }
      return false;
    } finally {
      await request?.clearVisibleStateIfUnauthorized();
    }
  }

// #endregion
}

// DummyAb is for current ab is null
class DummyAb extends BaseAb {
  @override
  bool isFull() {
    return false;
  }

  @override
  Future<String?> addPeers(List<Map<String, dynamic>> ps) async {
    return "dummpy";
  }

  @override
  Future<bool> addTags(
      List<String> tagList, Map<String, int> tagColorMap) async {
    return false;
  }

  @override
  bool canWrite() {
    return false;
  }

  @override
  bool fullControl() {
    return false;
  }

  @override
  Future<bool> changeAlias({required String id, required String alias}) async {
    return false;
  }

  @override
  Future<bool> changeNote({required String id, required String note}) async {
    return false;
  }

  @override
  Future<bool> changePersonalHashPassword(String id, String hash) async {
    return false;
  }

  @override
  Future<bool> changeSharedPassword(String id, String password) async {
    return false;
  }

  @override
  Future<bool> changeTagForPeers(List<String> ids, List tags) async {
    return false;
  }

  @override
  Future<bool> deletePeers(List<String> ids) async {
    return false;
  }

  @override
  Future<bool> deleteTag(String tag) async {
    return false;
  }

  @override
  String name() {
    return "dummpy";
  }

  @override
  Future<bool> pullAbImpl({quiet = false, AbRequestScope? requestScope}) async {
    return false;
  }

  @override
  Future<bool> renameTag(String oldTag, String newTag) async {
    return false;
  }

  @override
  Future<bool> setTagColor(String tag, Color color) async {
    return false;
  }

  @override
  AbProfile? sharedProfile() {
    return null;
  }

  @override
  void setSharedProfile(AbProfile profile) {}

  @override
  Future<void> syncFromRecent(List<Peer> recents) async {}
}

Map<String, dynamic> _jsonDecodeRespMap(String body, int statusCode) {
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

List<dynamic> _jsonDecodeRespList(String body, int statusCode) {
  try {
    List<dynamic> json = jsonDecode(body);
    return json;
  } catch (e) {
    final err = body.isNotEmpty && body.length < 128 ? body : e.toString();
    if (statusCode != 200) {
      throw 'HTTP $statusCode, $err';
    }
    throw err;
  }
}

String _jsonDecodeActionResp(http.Response resp) {
  var errMsg = '';
  if (resp.statusCode == 200 && resp.body.isEmpty) {
    // ok
  } else {
    try {
      errMsg = jsonDecode(resp.body)['error'].toString();
    } catch (_) {}
    if (errMsg.isEmpty) {
      if (resp.statusCode != 200) {
        errMsg = 'HTTP ${resp.statusCode}';
      }
      if (resp.body.isNotEmpty) {
        if (errMsg.isNotEmpty) {
          errMsg += ', ';
        }
        errMsg += resp.body;
      }
      if (errMsg.isEmpty) {
        errMsg = "unknown error";
      }
    }
  }
  return errMsg;
}

// https://github.com/seanmonstar/reqwest/issues/838
void _setEmptyBody(Map<String, String> headers) {
  headers['Content-Length'] = '0';
}
