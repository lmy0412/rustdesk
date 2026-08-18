import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/hbbs/hbbs.dart';
import 'package:flutter_hbb/models/platform_model.dart';
import 'package:flutter_hbb/models/state_generation_guard.dart';
import 'package:flutter_hbb/models/user_model.dart';
import 'package:get/get.dart';
import 'package:flutter_svg/flutter_svg.dart';
import 'package:url_launcher/url_launcher.dart';

import '../../common.dart';
import './dialog.dart';

const kOpSvgList = [
  'github',
  'gitlab',
  'google',
  'apple',
  'okta',
  'facebook',
  'azure',
  'auth0',
  'microsoft'
];

class _IconOP extends StatelessWidget {
  final String op;
  final String? icon;
  final EdgeInsets margin;
  const _IconOP(
      {Key? key,
      required this.op,
      required this.icon,
      this.margin = const EdgeInsets.symmetric(horizontal: 4.0)})
      : super(key: key);

  @override
  Widget build(BuildContext context) {
    final svgFile =
        kOpSvgList.contains(op.toLowerCase()) ? op.toLowerCase() : 'default';
    return Container(
      margin: margin,
      child: icon == null
          ? SvgPicture.asset(
              'assets/auth-$svgFile.svg',
              width: 20,
            )
          : SvgPicture.string(
              icon!,
              width: 20,
            ),
    );
  }
}

class ButtonOP extends StatelessWidget {
  final String op;
  final RxString curOP;
  final String? icon;
  final Color primaryColor;
  final double height;
  final Function() onTap;

  const ButtonOP({
    Key? key,
    required this.op,
    required this.curOP,
    required this.icon,
    required this.primaryColor,
    required this.height,
    required this.onTap,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    final opLabel = {
          'github': 'GitHub',
          'gitlab': 'GitLab'
        }[op.toLowerCase()] ??
        toCapitalized(op);
    return Row(children: [
      Container(
        height: height,
        width: 200,
        child: Obx(() => ElevatedButton(
            style: ElevatedButton.styleFrom(
              backgroundColor: curOP.value.isEmpty || curOP.value == op
                  ? primaryColor
                  : Colors.grey,
            ).copyWith(elevation: ButtonStyleButton.allOrNull(0.0)),
            onPressed: curOP.value.isEmpty || curOP.value == op ? onTap : null,
            child: Row(
              children: [
                SizedBox(
                  width: 30,
                  child: _IconOP(
                    op: op,
                    icon: icon,
                    margin: EdgeInsets.only(right: 5),
                  ),
                ),
                Expanded(
                  child: FittedBox(
                    fit: BoxFit.scaleDown,
                    child: Center(
                        child: Text(translate("Continue with {$opLabel}"))),
                  ),
                ),
              ],
            ))),
      ),
    ]);
  }
}

class ConfigOP {
  final String op;
  final String? icon;
  ConfigOP({required this.op, required this.icon});
}

typedef OidcLoginResultCallback = Future<bool> Function(
  LoginResponse response,
  NativeAuthStartTicket ownerTicket,
);

AuthRequestGeneration? _committedGeneration(LoginResponse response) {
  if (!response.committed || response.type != HttpType.kAuthResTypeToken) {
    return null;
  }
  try {
    return AuthRequestGeneration(
      normalizedApiBase: response.normalizedApiBase!,
      namespace: response.namespace!,
      cursorKey: response.cursorKey!,
      sessionEpoch: response.sessionEpoch!,
      sessionNonce: response.sessionNonce!,
    );
  } catch (_) {
    return null;
  }
}

bool? _isEmailChallenge(LoginResponse response) {
  return authChallengeUsesEmail(response.type, response.tfa_type);
}

class _WidgetAuthOwner {
  final NativeAuthStartTicket ticket;
  String? attemptJson;
  Timer? timer;
  bool pollInFlight = false;
  bool retired = false;
  bool committedAcknowledged = false;

  _WidgetAuthOwner(this.ticket);
}

class WidgetOP extends StatefulWidget {
  final ConfigOP config;
  final RxString curOP;
  final OidcLoginResultCallback cbLogin;
  const WidgetOP({
    Key? key,
    required this.config,
    required this.curOP,
    required this.cbLogin,
  }) : super(key: key);

  @override
  State<StatefulWidget> createState() {
    return _WidgetOPState();
  }
}

class _WidgetOPState extends State<WidgetOP> {
  _WidgetAuthOwner? _owner;
  String _stateMsg = '';
  String _failedMsg = '';
  String _url = '';

  @override
  void dispose() {
    final owner = _owner;
    _owner = null;
    if (owner != null) {
      owner.retired = true;
      owner.timer?.cancel();
      gFFI.userModel.releaseNativeAuthStart(owner.ticket);
      final attemptJson = owner.attemptJson;
      if (attemptJson != null && !owner.committedAcknowledged) {
        unawaited(gFFI.userModel.cancelNativeAttempt(attemptJson));
      }
    }
    super.dispose();
  }

  bool _isLocalOwner(_WidgetAuthOwner owner) =>
      mounted && !owner.retired && identical(_owner, owner);

  bool _ownsStart(_WidgetAuthOwner owner) =>
      _isLocalOwner(owner) && gFFI.userModel.ownsNativeAuthStart(owner.ticket);

  bool _ownsAttempt(_WidgetAuthOwner owner) =>
      _ownsStart(owner) && owner.attemptJson != null;

  bool _ensureAttemptOwnerOrRetire(_WidgetAuthOwner owner) {
    if (_ownsAttempt(owner)) return true;
    if (nativeAttemptNeedsExactRetirement(
      localOwner: _isLocalOwner(owner),
      globalOwner: gFFI.userModel.ownsNativeAuthStart(owner.ticket),
      hasAttempt: owner.attemptJson != null,
    )) {
      _retireOwnedAttempt(
        owner,
        clearCurrentOp: false,
        cancelNative: true,
      );
    }
    return false;
  }

  void _stopOwnerTimer(_WidgetAuthOwner owner) {
    owner.timer?.cancel();
    owner.timer = null;
  }

  void _detachOwnerForCallback(_WidgetAuthOwner owner) {
    if (!mounted || !identical(_owner, owner)) return;
    _stopOwnerTimer(owner);
    owner.retired = true;
    _owner = null;
  }

  void _supersedeLocalOwner(_WidgetAuthOwner owner) {
    owner.retired = true;
    _stopOwnerTimer(owner);
    final attemptJson = owner.attemptJson;
    if (attemptJson != null && !owner.committedAcknowledged) {
      unawaited(gFFI.userModel.cancelNativeAttempt(attemptJson));
    }
  }

  void _retireOwnedAttempt(
    _WidgetAuthOwner owner, {
    required bool clearCurrentOp,
    bool cancelNative = false,
  }) {
    if (!mounted || !identical(_owner, owner)) return;
    final ownsGlobalTicket = gFFI.userModel.ownsNativeAuthStart(owner.ticket);
    owner.retired = true;
    _owner = null;
    _stopOwnerTimer(owner);
    if (clearCurrentOp &&
        ownsGlobalTicket &&
        widget.curOP.value == widget.config.op) {
      widget.curOP.value = '';
    }
    gFFI.userModel.releaseNativeAuthStart(owner.ticket);
    final attemptJson = owner.attemptJson;
    if (cancelNative && attemptJson != null && !owner.committedAcknowledged) {
      unawaited(gFFI.userModel.cancelNativeAttempt(attemptJson));
    }
  }

  Future<bool> _attemptIsCurrent(_WidgetAuthOwner owner) async {
    if (!_ensureAttemptOwnerOrRetire(owner)) return false;
    final current =
        await gFFI.userModel.isNativeAttemptCurrent(owner.attemptJson);
    if (!_ensureAttemptOwnerOrRetire(owner)) return false;
    if (!current) {
      _retireOwnedAttempt(
        owner,
        clearCurrentOp: true,
        cancelNative: true,
      );
      return false;
    }
    return true;
  }

  Future<bool> _generationIsCurrent(
    _WidgetAuthOwner owner,
    AuthRequestGeneration generation,
  ) async {
    if (!_ensureAttemptOwnerOrRetire(owner)) return false;
    final current = await gFFI.userModel.isNativeGenerationCurrent(generation);
    if (!_ensureAttemptOwnerOrRetire(owner)) return false;
    if (!current) {
      _retireOwnedAttempt(
        owner,
        clearCurrentOp: true,
        cancelNative: true,
      );
      return false;
    }
    return true;
  }

  void _beginQueryState(_WidgetAuthOwner owner) {
    if (!_ensureAttemptOwnerOrRetire(owner)) return;
    final timer = Timer.periodic(const Duration(seconds: 1), (timer) {
      if (!_ensureAttemptOwnerOrRetire(owner)) {
        timer.cancel();
        if (identical(owner.timer, timer)) owner.timer = null;
        return;
      }
      unawaited(_updateState(owner));
    });
    owner.timer = timer;
  }

  Future<void> _updateState(_WidgetAuthOwner owner) async {
    if (!_ensureAttemptOwnerOrRetire(owner) || owner.pollInFlight) return;
    owner.pollInFlight = true;
    try {
      final attemptJson = owner.attemptJson!;
      final result = await bind.mainAccountAuthResult(attemptJson: attemptJson);
      if (!_ensureAttemptOwnerOrRetire(owner)) return;
      if (result.isEmpty) {
        throw const FormatException('OIDC 结果为空');
      }

      final decoded = jsonDecode(result);
      if (decoded is! Map<String, dynamic>) {
        throw const FormatException('OIDC 结果格式无效');
      }

      // provenance 必须在读取任何可见结果前先与本 Widget owner 全等匹配。
      requireOwnedNativeAuthResultAttempt(decoded, attemptJson);

      final authBodyValue = decoded['auth_body'];
      if (authBodyValue != null) {
        if (authBodyValue is! Map<String, dynamic>) {
          throw const FormatException('OIDC 认证结果格式无效');
        }
        final authBody = Map<String, dynamic>.from(authBodyValue);
        final isCommitted = authBody['type'] == HttpType.kAuthResTypeToken &&
            authBody['access_token'] == null;
        // challenge 的 nested auth_body 必须与顶层 origin 和本地 owner
        // 同时全等；committed DTO 则只在顶层携带 provenance，并由五字段
        // generation 继续门禁。
        if (!isCommitted || authBody['native_attempt'] != null) {
          requireOwnedNativeAuthResultAttempt(authBody, attemptJson);
        }

        LoginResponse response;
        if (isCommitted) {
          final generation = AuthRequestGeneration.fromMap(authBody);
          if (!await _generationIsCurrent(owner, generation)) return;
          response =
              await gFFI.userModel.getLoginResponseFromAuthBody(authBody);
          final handoff = NativeCommittedHandoff();
          final accepted = await handoff.run(
            validateBeforeAck: () => _generationIsCurrent(owner, generation),
            acknowledge: () => gFFI.userModel.ackNativeAttempt(attemptJson),
            onAcknowledged: () => owner.committedAcknowledged = true,
            publishVisible: () =>
                gFFI.userModel.acceptNativeCommittedLogin(response),
            isVisibleCurrent: () =>
                gFFI.userModel.isVisibleLoginResponseCurrent(response),
          );
          if (!accepted) {
            _retireOwnedAttempt(
              owner,
              clearCurrentOp: true,
              cancelNative: true,
            );
            return;
          }
        } else {
          if (!await _attemptIsCurrent(owner)) return;
          response =
              await gFFI.userModel.getLoginResponseFromAuthBody(authBody);
          if (!await _attemptIsCurrent(owner)) return;
        }

        response.nativeAttemptJson ??= attemptJson;
        if (!_ensureAttemptOwnerOrRetire(owner)) {
          // ACK 后界面可以消失，但全局 Rx 已保证提交；此处只跳过局部 UI。
          return;
        }
        _detachOwnerForCallback(owner);
        if (widget.curOP.value == widget.config.op) {
          widget.curOP.value = '';
        }
        var callbackOwnsAttempt = false;
        try {
          callbackOwnsAttempt = await widget.cbLogin(response, owner.ticket);
        } finally {
          if (!callbackOwnsAttempt) {
            gFFI.userModel.releaseNativeAuthStart(owner.ticket);
            if (!owner.committedAcknowledged) {
              unawaited(gFFI.userModel.cancelNativeAttempt(attemptJson));
            }
          }
        }
        return;
      }

      // URL、状态和错误只能在 attempt 仍是 native current 时发布。
      if (!await _attemptIsCurrent(owner)) {
        _retireOwnedAttempt(owner, clearCurrentOp: true);
        return;
      }
      if (decoded['state_msg'] is! String ||
          decoded['failed_msg'] is! String ||
          (decoded['url'] != null && decoded['url'] is! String)) {
        throw const FormatException('OIDC 状态结果格式无效');
      }
      final stateMsg = decoded['state_msg'] as String;
      final failedMsg = decoded['failed_msg'] as String;
      final url = decoded['url'] as String?;
      final urlLaunched = decoded['url_launched'] == true;

      if (_url.isEmpty && url != null && url.isNotEmpty) {
        final uri = Uri.tryParse(url);
        if (uri == null || (uri.scheme != 'http' && uri.scheme != 'https')) {
          throw const FormatException('OIDC 登录地址无效');
        }
        if (!urlLaunched) {
          await launchUrl(uri, mode: LaunchMode.externalApplication);
          if (!await _attemptIsCurrent(owner)) return;
        }
        if (!_ensureAttemptOwnerOrRetire(owner)) return;
        _url = url;
      }

      if (!_ensureAttemptOwnerOrRetire(owner)) return;
      setState(() {
        _stateMsg = stateMsg;
        _failedMsg = failedMsg;
      });
      if (failedMsg.isNotEmpty) {
        _retireOwnedAttempt(
          owner,
          clearCurrentOp: true,
          cancelNative: true,
        );
      }
    } on FormatException {
      // 无法证明 provenance 的结果不得产生 UI 副作用。
      _retireOwnedAttempt(
        owner,
        clearCurrentOp: true,
        cancelNative: true,
      );
    } catch (_) {
      // OIDC 错误只由带正确 provenance 的 typed 结果显示。
      _retireOwnedAttempt(
        owner,
        clearCurrentOp: true,
        cancelNative: true,
      );
    } finally {
      owner.pollInFlight = false;
    }
  }

  _resetState() {
    _stateMsg = '';
    _failedMsg = '';
    _url = '';
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        ButtonOP(
          op: widget.config.op,
          curOP: widget.curOP,
          icon: widget.config.icon,
          primaryColor: str2color(widget.config.op, 0x7f),
          height: 36,
          onTap: () async {
            final ticket = gFFI.userModel.claimNativeAuthStart();
            final previous = _owner;
            if (previous != null) _supersedeLocalOwner(previous);
            final owner = _WidgetAuthOwner(ticket);
            _owner = owner;
            _resetState();
            widget.curOP.value = widget.config.op;
            try {
              final attemptJson = await gFFI.userModel.beginNativeOidc(
                ticket,
                op: widget.config.op,
                rememberMe: true,
              );
              if (!_ownsStart(owner) || attemptJson == null) return;
              owner.attemptJson = nativeAuthAttemptOpaqueFromValue(attemptJson);
              if (!await _attemptIsCurrent(owner)) {
                _retireOwnedAttempt(owner, clearCurrentOp: true);
                return;
              }
              _beginQueryState(owner);
            } catch (_) {
              if (!_ownsStart(owner)) return;
              setState(() => _failedMsg = 'OIDC 登录启动失败');
              _retireOwnedAttempt(
                owner,
                clearCurrentOp: true,
                cancelNative: true,
              );
            }
          },
        ),
        Obx(() {
          if (widget.curOP.isNotEmpty &&
              widget.curOP.value != widget.config.op) {
            _failedMsg = '';
          }
          return Offstage(
            offstage:
                _failedMsg.isEmpty && widget.curOP.value != widget.config.op,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.center,
              children: [
                if (_stateMsg.isNotEmpty && _failedMsg.isEmpty)
                  Padding(
                    padding: const EdgeInsets.only(top: 8.0),
                    child: SelectableText(
                      translate(_stateMsg),
                      style: DefaultTextStyle.of(context)
                          .style
                          .copyWith(fontSize: 12),
                    ),
                  ),
                if (_failedMsg.isNotEmpty)
                  Padding(
                    padding: const EdgeInsets.only(top: 8.0),
                    child: Builder(builder: (context) {
                      final errorColor = Theme.of(context).colorScheme.error;
                      final bgColor = Theme.of(context)
                          .colorScheme
                          .errorContainer
                          .withOpacity(0.3);
                      return Container(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 8.0, vertical: 6.0),
                        decoration: BoxDecoration(
                          color: bgColor,
                          borderRadius: BorderRadius.circular(4.0),
                        ),
                        child: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(Icons.error_outline,
                                color: errorColor, size: 16),
                            const SizedBox(width: 6),
                            Flexible(
                              child: SelectableText(
                                translate(_failedMsg),
                                style:
                                    DefaultTextStyle.of(context).style.copyWith(
                                          fontSize: 13,
                                          color: errorColor,
                                        ),
                              ),
                            ),
                          ],
                        ),
                      );
                    }),
                  ),
              ],
            ),
          );
        }),
        Obx(
          () => Offstage(
            offstage: widget.curOP.value != widget.config.op,
            child: const SizedBox(
              height: 5.0,
            ),
          ),
        ),
        Obx(
          () => Offstage(
            offstage: widget.curOP.value != widget.config.op,
            child: ConstrainedBox(
              constraints: BoxConstraints(maxHeight: 20),
              child: ElevatedButton(
                onPressed: () async {
                  final owner = _owner;
                  if (owner == null || !_ownsStart(owner)) return;
                  _resetState();
                  final attemptJson = owner.attemptJson;
                  _retireOwnedAttempt(owner,
                      clearCurrentOp: true, cancelNative: false);
                  if (attemptJson != null) {
                    await gFFI.userModel.cancelNativeAttempt(attemptJson);
                  }
                },
                child: Text(
                  translate('Cancel'),
                  style: TextStyle(fontSize: 15),
                ),
              ),
            ),
          ),
        ),
      ],
    );
  }
}

class LoginWidgetOP extends StatelessWidget {
  final List<ConfigOP> ops;
  final RxString curOP;
  final OidcLoginResultCallback cbLogin;

  LoginWidgetOP({
    Key? key,
    required this.ops,
    required this.curOP,
    required this.cbLogin,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    var children = ops
        .map((op) => [
              WidgetOP(
                config: op,
                curOP: curOP,
                cbLogin: cbLogin,
              ),
              const Divider(
                indent: 5,
                endIndent: 5,
              )
            ])
        .expand((i) => i)
        .toList();
    if (children.isNotEmpty) {
      children.removeLast();
    }
    return SingleChildScrollView(
        child: Container(
            width: 200,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              mainAxisAlignment: MainAxisAlignment.spaceAround,
              children: children,
            )));
  }
}

class LoginWidgetUserPass extends StatelessWidget {
  final TextEditingController username;
  final TextEditingController pass;
  final String? usernameMsg;
  final String? passMsg;
  final bool isInProgress;
  final RxString curOP;
  final Function() onLogin;
  final FocusNode? userFocusNode;
  const LoginWidgetUserPass({
    Key? key,
    this.userFocusNode,
    required this.username,
    required this.pass,
    required this.usernameMsg,
    required this.passMsg,
    required this.isInProgress,
    required this.curOP,
    required this.onLogin,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Padding(
        padding: EdgeInsets.all(0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.center,
          children: [
            const SizedBox(height: 8.0),
            DialogTextField(
                title: translate(DialogTextField.kUsernameTitle),
                controller: username,
                focusNode: userFocusNode,
                prefixIcon: DialogTextField.kUsernameIcon,
                errorText: usernameMsg),
            PasswordWidget(
              controller: pass,
              autoFocus: false,
              reRequestFocus: true,
              errorText: passMsg,
            ),
            // NOT use Offstage to wrap LinearProgressIndicator
            if (isInProgress) const LinearProgressIndicator(),
            const SizedBox(height: 12.0),
            FittedBox(
                child:
                    Row(mainAxisAlignment: MainAxisAlignment.center, children: [
              Container(
                height: 38,
                width: 200,
                child: Obx(() => ElevatedButton(
                      child: Text(
                        translate('Login'),
                        style: TextStyle(fontSize: 16),
                      ),
                      onPressed: !isInProgress &&
                              (curOP.value.isEmpty || curOP.value == 'rustdesk')
                          ? () {
                              onLogin();
                            }
                          : null,
                    )),
              ),
            ])),
          ],
        ));
  }
}

const kAuthReqTypeOidc = 'oidc/';

// call this directly
Future<bool?> loginDialog() async {
  var username =
      TextEditingController(text: UserModel.getLocalUserInfo()?['name'] ?? '');
  var password = TextEditingController();
  final userFocusNode = FocusNode()..requestFocus();
  final refocusTimer =
      Timer(const Duration(milliseconds: 100), userFocusNode.requestFocus);

  String? usernameMsg;
  String? passwordMsg;
  var isInProgress = false;
  NativeAuthStartTicket? passwordOwnerTicket;
  String? passwordAttemptJson;
  String? passwordAcknowledgedAttemptJson;
  var loginDialogActive = true;
  final RxString curOP = ''.obs;
  // Track hover state for the close icon
  bool isCloseHovered = false;

  final loginOptions = [].obs;
  Future.delayed(Duration.zero, () async {
    loginOptions.value = await UserModel.queryOidcLoginOptions();
  });

  Future<void> finalizePasswordOwner() async {
    final ticket = passwordOwnerTicket;
    final attemptJson = passwordAttemptJson;
    final acknowledged = attemptJson != null &&
        nativeAuthAttemptsMatch(
          attemptJson,
          passwordAcknowledgedAttemptJson ?? '',
        );
    passwordOwnerTicket = null;
    passwordAttemptJson = null;
    if (!acknowledged) {
      passwordAcknowledgedAttemptJson = null;
    }
    if (ticket != null) {
      gFFI.userModel.releaseNativeAuthStart(ticket);
    }
    if (attemptJson != null && !acknowledged) {
      await gFFI.userModel.cancelNativeAttempt(attemptJson);
    }
  }

  void transferPasswordOwner(
    NativeAuthStartTicket? ticket,
    String? attemptJson,
  ) {
    if (identical(passwordOwnerTicket, ticket) &&
        passwordAttemptJson == attemptJson) {
      passwordOwnerTicket = null;
      passwordAttemptJson = null;
      passwordAcknowledgedAttemptJson = null;
    }
  }

  bool? res;
  try {
    res = await gFFI.dialogManager.show<bool>((setState, close, context) {
      username.addListener(() {
        if (loginDialogActive && context.mounted && usernameMsg != null) {
          setState(() => usernameMsg = null);
        }
      });

      password.addListener(() {
        if (loginDialogActive && context.mounted && passwordMsg != null) {
          setState(() => passwordMsg = null);
        }
      });

      onDialogCancel() {
        isInProgress = false;
        unawaited(finalizePasswordOwner());
        close(false);
      }

      bool ownsTicket(NativeAuthStartTicket? ticket) =>
          loginDialogActive &&
          context.mounted &&
          (ticket == null ? isWeb : gFFI.userModel.ownsNativeAuthStart(ticket));

      Future<bool> ownsCurrentAttempt(
        NativeAuthStartTicket? ticket,
        String? attemptJson,
      ) async {
        if (!ownsTicket(ticket)) return false;
        if (attemptJson == null) return isWeb;
        final current =
            await gFFI.userModel.isNativeAttemptCurrent(attemptJson);
        return current && ownsTicket(ticket);
      }

      Future<bool> ownsCurrentGeneration(
        NativeAuthStartTicket? ticket,
        AuthRequestGeneration? generation,
      ) async {
        if (isWeb) return ownsTicket(ticket);
        if (!ownsTicket(ticket) || generation == null) return false;
        final current =
            await gFFI.userModel.isNativeGenerationCurrent(generation);
        return current && ownsTicket(ticket);
      }

      void finishPasswordAttempt(
        NativeAuthStartTicket? ticket,
        String? attemptJson, {
        required bool cancelNative,
      }) {
        final acknowledged = attemptJson != null &&
            passwordAcknowledgedAttemptJson == attemptJson;
        if (identical(passwordOwnerTicket, ticket)) {
          passwordOwnerTicket = null;
          passwordAttemptJson = null;
          if (acknowledged) {
            passwordAcknowledgedAttemptJson = null;
          }
        }
        if (ticket != null) {
          gFFI.userModel.releaseNativeAuthStart(ticket);
        }
        if (cancelNative && attemptJson != null && !acknowledged) {
          unawaited(gFFI.userModel.cancelNativeAttempt(attemptJson));
        }
      }

      bool isLocalPasswordAttempt(
        NativeAuthStartTicket? ticket,
        String? attemptJson,
      ) {
        if (!identical(passwordOwnerTicket, ticket)) return false;
        if (attemptJson == null) return passwordAttemptJson == null;
        final localAttempt = passwordAttemptJson;
        // begin Future 刚返回而全局 ticket 已被 B 夺走时，opaque attempt
        // 可能尚未来得及写入 passwordAttemptJson；同一 local ticket 仍足以
        // 证明该返回值属于 A，必须由 A exact cancel。
        return localAttempt == null ||
            nativeAuthAttemptsMatch(localAttempt, attemptJson);
      }

      bool retirePasswordAttemptIfStartLost(
        NativeAuthStartTicket? ticket,
        String? attemptJson,
      ) {
        if (isWeb ||
            ticket == null ||
            !isLocalPasswordAttempt(ticket, attemptJson) ||
            gFFI.userModel.ownsNativeAuthStart(ticket)) {
          return false;
        }

        // B 可能只夺取了全局 start ticket，随后在 native begin 前失败。
        // 此时 A 仍须 exact cancel 自己；只复位密码 A 的 in-flight，不能清
        // 共用的 curOP（它可能已经属于 OIDC B）。
        finishPasswordAttempt(
          ticket,
          attemptJson,
          cancelNative: true,
        );
        if (loginDialogActive && context.mounted) {
          setState(() => isInProgress = false);
        }
        return true;
      }

      void stopPasswordUiIfOwned(NativeAuthStartTicket? ticket) {
        if (!loginDialogActive ||
            !context.mounted ||
            !identical(passwordOwnerTicket, ticket) ||
            (!isWeb &&
                (ticket == null ||
                    !gFFI.userModel.ownsNativeAuthStart(ticket)))) {
          return;
        }
        if (curOP.value == 'rustdesk') {
          curOP.value = '';
        }
        setState(() => isInProgress = false);
      }

      Future<bool> handleLoginResponse(
        LoginResponse resp,
        bool storeIfAccessToken,
        void Function([dynamic])? close,
        NativeAuthStartTicket? ownerTicket,
      ) async {
        if (!ownsTicket(ownerTicket)) return false;
        switch (resp.type) {
          case HttpType.kAuthResTypeToken:
            if (resp.committed || resp.access_token != null) {
              if (!isWeb &&
                  (!resp.committed ||
                      !gFFI.userModel.isVisibleLoginResponseCurrent(resp))) {
                return false;
              }
              if (isWeb && resp.nativeAttemptJson != null) {
                if (!await ownsCurrentAttempt(
                        ownerTicket, resp.nativeAttemptJson) ||
                    !await gFFI.userModel
                        .ackNativeAttempt(resp.nativeAttemptJson)) {
                  return false;
                }
              }
              if (isWeb) {
                await gFFI.userModel.acceptWebLoginResponse(
                  resp,
                  storeAccessToken: storeIfAccessToken,
                );
              }
              final mayCloseDialog = ownsTicket(ownerTicket);
              finishPasswordAttempt(
                ownerTicket,
                resp.nativeAttemptJson,
                cancelNative: false,
              );
              if (mayCloseDialog && close != null) {
                close(true);
              }
              return true;
            }
            break;
          default:
            final isEmailVerification = _isEmailChallenge(resp);
            if (isEmailVerification != null) {
              if (!await ownsCurrentAttempt(
                  ownerTicket, resp.nativeAttemptJson)) {
                return false;
              }
              // 从此由验证码对话框持有 exact attempt；主登录框的 finally
              // 不得因外部 dismiss 再取消同一能力。
              transferPasswordOwner(ownerTicket, resp.nativeAttemptJson);
              if (isMobile) {
                if (close != null) close(null);
                unawaited(verificationCodeDialog(
                  resp.user,
                  resp.secret,
                  isEmailVerification,
                  nativeAttemptJson: resp.nativeAttemptJson,
                  ownerTicket: ownerTicket,
                ));
                return true;
              } else {
                if (!ownsTicket(ownerTicket)) return false;
                setState(() => isInProgress = false);
                // Workaround for web, close the dialog first, then show the verification code dialog.
                // Otherwise, the text field will keep selecting the text and we can't input the code.
                // Not sure why this happens.
                if (isWeb && close != null) close(null);
                final verificationResponse = await verificationCodeDialog(
                  resp.user,
                  resp.secret,
                  isEmailVerification,
                  nativeAttemptJson: resp.nativeAttemptJson,
                  ownerTicket: ownerTicket,
                );
                if (isWeb) return true;
                if (verificationResponse != null &&
                    gFFI.userModel
                        .isVisibleLoginResponseCurrent(verificationResponse)) {
                  if (loginDialogActive && close != null) close(true);
                  return true;
                }
                // 验证框已在 finally 中完成 exact 收尾；这里只恢复仍挂载的主框 UI。
                if (loginDialogActive && context.mounted) {
                  if (curOP.value == 'rustdesk') curOP.value = '';
                  setState(() => isInProgress = false);
                }
                return true;
              }
            } else if (ownsTicket(ownerTicket)) {
              passwordMsg = "Failed, bad tfa type from server";
              setState(() {});
            }
            return false;
        }
        return false;
      }

      onLogin() async {
        // 同一 owner 的 strict login 不允许并发复用 exact attempt。
        if (!loginDialogActive || isInProgress) return;
        // validate
        if (username.text.isEmpty) {
          setState(() => usernameMsg = translate('Username missed'));
          return;
        }
        if (password.text.isEmpty) {
          setState(() => passwordMsg = translate('Password missed'));
          return;
        }
        final usernameValue = username.text;
        final passwordValue = password.text;
        curOP.value = 'rustdesk';
        setState(() => isInProgress = true);
        NativeAuthStartTicket? ownerTicket;
        String? attemptJson;
        try {
          late final String id;
          late final String uuid;
          if (!isWeb) {
            final existingTicket = passwordOwnerTicket;
            final existingAttempt = passwordAttemptJson;
            if (existingTicket != null &&
                existingAttempt != null &&
                await ownsCurrentAttempt(existingTicket, existingAttempt)) {
              ownerTicket = existingTicket;
              attemptJson = existingAttempt;
            } else {
              ownerTicket = gFFI.userModel.claimNativeAuthStart();
              final oldAttempt = passwordAttemptJson;
              passwordOwnerTicket = ownerTicket;
              passwordAttemptJson = null;
              passwordAcknowledgedAttemptJson = null;
              if (oldAttempt != null) {
                unawaited(gFFI.userModel.cancelNativeAttempt(oldAttempt));
              }
              attemptJson = await gFFI.userModel.beginNativeLogin(ownerTicket);
              if (!ownsTicket(ownerTicket) || attemptJson == null) {
                throw const StaleAuthGenerationException();
              }
              attemptJson = nativeAuthAttemptOpaqueFromValue(attemptJson);
              passwordAttemptJson = attemptJson;
            }
            if (!await ownsCurrentAttempt(ownerTicket, attemptJson)) {
              throw const StaleAuthGenerationException();
            }
            id = await bind.mainGetMyId();
            if (!await ownsCurrentAttempt(ownerTicket, attemptJson)) {
              throw const StaleAuthGenerationException();
            }
            uuid = await bind.mainGetUuid();
            if (!await ownsCurrentAttempt(ownerTicket, attemptJson)) {
              throw const StaleAuthGenerationException();
            }
          } else {
            id = await bind.mainGetMyId();
            if (!loginDialogActive || !context.mounted) return;
            uuid = await bind.mainGetUuid();
            if (!loginDialogActive || !context.mounted) return;
          }

          final resp = await gFFI.userModel.login(
            LoginRequest(
              username: usernameValue,
              password: passwordValue,
              id: id,
              uuid: uuid,
              autoLogin: true,
              type: HttpType.kAuthReqTypeAccount,
              nativeAttemptJson: attemptJson,
            ),
          );
          if (!isWeb) {
            if (!ownsTicket(ownerTicket)) {
              throw const StaleAuthGenerationException();
            }
            if (resp.committed) {
              final generation = _committedGeneration(resp);
              if (!await ownsCurrentGeneration(ownerTicket, generation)) {
                throw const StaleAuthGenerationException();
              }
              final handoff = NativeCommittedHandoff();
              final accepted = await handoff.run(
                validateBeforeAck: () =>
                    ownsCurrentGeneration(ownerTicket, generation),
                acknowledge: () => gFFI.userModel.ackNativeAttempt(attemptJson),
                onAcknowledged: () {
                  passwordAcknowledgedAttemptJson = attemptJson;
                },
                publishVisible: () =>
                    gFFI.userModel.acceptNativeCommittedLogin(resp),
                isVisibleCurrent: () =>
                    gFFI.userModel.isVisibleLoginResponseCurrent(resp),
              );
              if (!accepted) {
                throw const StaleAuthGenerationException();
              }
            } else if (!nativeAuthAttemptsMatch(
                    attemptJson!, resp.nativeAttemptJson ?? '') ||
                !await ownsCurrentAttempt(ownerTicket, attemptJson)) {
              throw const StaleAuthGenerationException();
            }
          }
          final handled =
              await handleLoginResponse(resp, true, close, ownerTicket);
          if (!handled && !isWeb) {
            if (retirePasswordAttemptIfStartLost(ownerTicket, attemptJson)) {
              return;
            }
            stopPasswordUiIfOwned(ownerTicket);
            finishPasswordAttempt(
              ownerTicket,
              attemptJson,
              cancelNative: true,
            );
          }
        } on StaleAuthGenerationException {
          // 代际失效属于预期取消，不显示旧账号错误。
          if (!isWeb) {
            if (retirePasswordAttemptIfStartLost(ownerTicket, attemptJson)) {
              return;
            }
            stopPasswordUiIfOwned(ownerTicket);
            finishPasswordAttempt(
              ownerTicket,
              attemptJson,
              cancelNative: true,
            );
          }
        } on RequestException catch (err) {
          if (retirePasswordAttemptIfStartLost(ownerTicket, attemptJson)) {
            return;
          }
          final errorMatchesAttempt = isWeb ||
              (attemptJson != null &&
                  err.nativeAttemptJson != null &&
                  nativeAuthAttemptsMatch(attemptJson, err.nativeAttemptJson!));
          var errorOwned = isWeb;
          try {
            errorOwned = errorOwned ||
                (attemptJson == null
                    ? ownsTicket(ownerTicket)
                    : await ownsCurrentAttempt(ownerTicket, attemptJson));
          } catch (_) {
            if (!isWeb && isLocalPasswordAttempt(ownerTicket, attemptJson)) {
              finishPasswordAttempt(
                ownerTicket,
                attemptJson,
                cancelNative: true,
              );
              if (loginDialogActive && context.mounted) {
                setState(() => isInProgress = false);
              }
            }
            return;
          }
          if (retirePasswordAttemptIfStartLost(ownerTicket, attemptJson)) {
            return;
          }
          if (errorOwned) {
            passwordMsg = translate(err.cause);
          } else if (!isWeb &&
              isLocalPasswordAttempt(ownerTicket, attemptJson)) {
            finishPasswordAttempt(
              ownerTicket,
              attemptJson,
              cancelNative: true,
            );
            if (loginDialogActive && context.mounted) {
              setState(() => isInProgress = false);
            }
            return;
          }
          if (!isWeb && !err.recoverable && errorMatchesAttempt) {
            stopPasswordUiIfOwned(ownerTicket);
            finishPasswordAttempt(
              ownerTicket,
              attemptJson,
              cancelNative: true,
            );
          }
        } catch (_) {
          if (retirePasswordAttemptIfStartLost(ownerTicket, attemptJson)) {
            return;
          }
          var errorOwned = isWeb;
          try {
            errorOwned = errorOwned ||
                (attemptJson == null
                    ? ownsTicket(ownerTicket)
                    : await ownsCurrentAttempt(ownerTicket, attemptJson));
          } catch (_) {
            errorOwned = false;
          }
          if (retirePasswordAttemptIfStartLost(ownerTicket, attemptJson)) {
            return;
          }
          if (errorOwned) {
            passwordMsg = "Unknown Error";
            if (!isWeb) {
              stopPasswordUiIfOwned(ownerTicket);
              finishPasswordAttempt(
                ownerTicket,
                attemptJson,
                cancelNative: true,
              );
            }
          } else if (!isWeb &&
              isLocalPasswordAttempt(ownerTicket, attemptJson)) {
            finishPasswordAttempt(
              ownerTicket,
              attemptJson,
              cancelNative: true,
            );
            if (loginDialogActive && context.mounted) {
              setState(() => isInProgress = false);
            }
            return;
          }
        }
        if (retirePasswordAttemptIfStartLost(ownerTicket, attemptJson)) {
          return;
        }
        if (loginDialogActive &&
            context.mounted &&
            (isWeb ||
                (identical(passwordOwnerTicket, ownerTicket) &&
                    ownerTicket != null &&
                    gFFI.userModel.ownsNativeAuthStart(ownerTicket)))) {
          if (curOP.value == 'rustdesk') curOP.value = '';
          setState(() => isInProgress = false);
        }
      }

      thirdAuthWidget() => Obx(() {
            return Offstage(
              offstage: loginOptions.isEmpty,
              child: Column(
                children: [
                  const SizedBox(
                    height: 8.0,
                  ),
                  Center(
                      child: Text(
                    translate('or'),
                    style: TextStyle(fontSize: 16),
                  )),
                  const SizedBox(
                    height: 8.0,
                  ),
                  LoginWidgetOP(
                    ops: loginOptions
                        .map((e) => ConfigOP(op: e['name'], icon: e['icon']))
                        .toList(),
                    curOP: curOP,
                    cbLogin: (resp, ownerTicket) async {
                      if (!ownsTicket(ownerTicket)) return false;
                      if (resp.committed) {
                        if (!await ownsCurrentGeneration(
                                ownerTicket, _committedGeneration(resp)) ||
                            !gFFI.userModel
                                .isVisibleLoginResponseCurrent(resp)) {
                          return false;
                        }
                      } else if (!await ownsCurrentAttempt(
                          ownerTicket, resp.nativeAttemptJson)) {
                        return false;
                      }
                      return await handleLoginResponse(
                          resp, false, close, ownerTicket);
                    },
                  ),
                ],
              ),
            );
          });

      final title = Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            translate('Login'),
          ).marginOnly(top: MyTheme.dialogPadding),
          MouseRegion(
            onEnter: (_) => setState(() => isCloseHovered = true),
            onExit: (_) => setState(() => isCloseHovered = false),
            child: InkWell(
              child: Icon(
                Icons.close,
                size: 25,
                // No need to handle the branch of null.
                // Because we can ensure the color is not null when debug.
                color: isCloseHovered
                    ? Colors.white
                    : Theme.of(context)
                        .textTheme
                        .titleLarge
                        ?.color
                        ?.withOpacity(0.55),
              ),
              onTap: onDialogCancel,
              hoverColor: Colors.red,
              borderRadius: BorderRadius.circular(5),
            ),
          ).marginOnly(top: 10, right: 15),
        ],
      );
      final titlePadding = EdgeInsets.fromLTRB(MyTheme.dialogPadding, 0, 0, 0);

      return CustomAlertDialog(
        title: title,
        titlePadding: titlePadding,
        contentBoxConstraints: BoxConstraints(minWidth: 400),
        content: Column(
          crossAxisAlignment: CrossAxisAlignment.center,
          children: [
            const SizedBox(
              height: 8.0,
            ),
            LoginWidgetUserPass(
              username: username,
              pass: password,
              usernameMsg: usernameMsg,
              passMsg: passwordMsg,
              isInProgress: isInProgress,
              curOP: curOP,
              onLogin: onLogin,
              userFocusNode: userFocusNode,
            ),
            thirdAuthWidget(),
          ],
        ),
        onCancel: onDialogCancel,
        onSubmit: onLogin,
      );
    });

    loginDialogActive = false;
    if (res != null) {
      await UserModel.updateOtherModels();
    }

    return res;
  } finally {
    loginDialogActive = false;
    refocusTimer.cancel();
    username.dispose();
    password.dispose();
    userFocusNode.dispose();
    // dismissAll/dismissByTag 不触发 onCancel，仍必须精确收回本层 owner。
    await finalizePasswordOwner();
  }
}

Future<LoginResponse?> verificationCodeDialog(
  UserPayload? user,
  String? secret,
  bool isEmailVerification, {
  String? nativeAttemptJson,
  NativeAuthStartTicket? ownerTicket,
}) async {
  var autoLogin = true;
  var isInProgress = false;
  var attemptAcknowledged = false;
  var verificationDialogActive = true;
  String? errorText;

  final code = TextEditingController();

  LoginResponse? res;
  try {
    res = await gFFI.dialogManager
        .show<LoginResponse>((setState, close, context) {
      bool ownsTicket() =>
          verificationDialogActive &&
          context.mounted &&
          (ownerTicket == null
              ? isWeb && nativeAttemptJson == null
              : gFFI.userModel.ownsNativeAuthStart(ownerTicket));

      Future<bool> ownsCurrentAttempt() async {
        if (!ownsTicket()) return false;
        if (nativeAttemptJson == null) return isWeb;
        final current =
            await gFFI.userModel.isNativeAttemptCurrent(nativeAttemptJson);
        return current && ownsTicket();
      }

      void cancelVerification() {
        close(null);
      }

      void onVerify() async {
        if (!verificationDialogActive || isInProgress) return;
        setState(() => isInProgress = true);
        final codeValue = code.text;
        if (!await ownsCurrentAttempt()) {
          if (verificationDialogActive && context.mounted) close(null);
          return;
        }

        try {
          final id = await bind.mainGetMyId();
          if (!await ownsCurrentAttempt()) {
            throw const StaleAuthGenerationException();
          }
          final uuid = await bind.mainGetUuid();
          if (!await ownsCurrentAttempt()) {
            throw const StaleAuthGenerationException();
          }
          final resp = await gFFI.userModel.login(
            LoginRequest(
              verificationCode: codeValue,
              tfaCode: isEmailVerification ? null : codeValue,
              secret: secret,
              username: user?.name,
              id: id,
              uuid: uuid,
              autoLogin: autoLogin,
              type: HttpType.kAuthReqTypeEmailCode,
              nativeAttemptJson: nativeAttemptJson,
            ),
          );

          switch (resp.type) {
            case HttpType.kAuthResTypeToken:
              if (resp.committed || resp.access_token != null) {
                if (!isWeb) {
                  final generation = _committedGeneration(resp);
                  if (!ownsTicket() ||
                      generation == null ||
                      !await gFFI.userModel
                          .isNativeGenerationCurrent(generation) ||
                      !ownsTicket()) {
                    throw const StaleAuthGenerationException();
                  }
                  final handoff = NativeCommittedHandoff();
                  final accepted = await handoff.run(
                    validateBeforeAck: () async {
                      if (!ownsTicket()) return false;
                      final current = await gFFI.userModel
                          .isNativeGenerationCurrent(generation);
                      return current && ownsTicket();
                    },
                    acknowledge: () =>
                        gFFI.userModel.ackNativeAttempt(nativeAttemptJson),
                    onAcknowledged: () => attemptAcknowledged = true,
                    publishVisible: () =>
                        gFFI.userModel.acceptNativeCommittedLogin(resp),
                    isVisibleCurrent: () =>
                        gFFI.userModel.isVisibleLoginResponseCurrent(resp),
                  );
                  if (!accepted) {
                    throw const StaleAuthGenerationException();
                  }
                }
                if (isWeb && resp.access_token != null) {
                  if (nativeAttemptJson != null) {
                    final acked = await gFFI.userModel
                        .ackNativeAttempt(nativeAttemptJson);
                    if (!acked) throw const StaleAuthGenerationException();
                    attemptAcknowledged = true;
                  }
                  await gFFI.userModel.acceptWebLoginResponse(
                    resp,
                    storeAccessToken: true,
                  );
                }
                if (!ownsTicket()) return;
                close(resp);
                return;
              }
              break;
            default:
              errorText = "Failed, bad response from server";
              break;
          }
        } on StaleAuthGenerationException {
          // 验证码对应的原登录代际已失效，禁止旧对话框继续提交。
          if (verificationDialogActive && context.mounted) close(null);
          return;
        } on RequestException catch (err) {
          final errorOwned = await ownsCurrentAttempt();
          if (!errorOwned) {
            if (verificationDialogActive && context.mounted) close(null);
            return;
          }
          errorText = translate(err.cause);
          if (!err.recoverable) {
            if (verificationDialogActive && context.mounted) close(null);
            return;
          }
        } catch (_) {
          if (!await ownsCurrentAttempt()) {
            if (verificationDialogActive && context.mounted) close(null);
            return;
          }
          errorText = "Unknown Error";
          if (!isWeb || nativeAttemptJson != null) {
            if (verificationDialogActive && context.mounted) close(null);
            return;
          }
        }

        if (verificationDialogActive &&
            context.mounted &&
            await ownsCurrentAttempt()) {
          setState(() => isInProgress = false);
        }
      }

      final codeField = isEmailVerification
          ? DialogEmailCodeField(
              controller: code,
              errorText: errorText,
              readyCallback: onVerify,
              onChanged: () => errorText = null,
            )
          : Dialog2FaField(
              controller: code,
              errorText: errorText,
              readyCallback: onVerify,
              onChanged: () => errorText = null,
            );

      getOnSubmit() => codeField.isReady && !isInProgress ? onVerify : null;

      return CustomAlertDialog(
          title: Text(translate("Verification code")),
          contentBoxConstraints: BoxConstraints(maxWidth: 300),
          content: Column(
            children: [
              Offstage(
                  offstage: !isEmailVerification || user?.email == null,
                  child: TextField(
                    decoration: InputDecoration(
                        labelText: "Email", prefixIcon: Icon(Icons.email)),
                    readOnly: true,
                    controller: TextEditingController(text: user?.email),
                  ).workaroundFreezeLinuxMint()),
              isEmailVerification
                  ? const SizedBox(height: 8)
                  : const Offstage(),
              codeField,
              /*
            CheckboxListTile(
              contentPadding: const EdgeInsets.all(0),
              dense: true,
              controlAffinity: ListTileControlAffinity.leading,
              title: Row(children: [
                Expanded(child: Text(translate("Trust this device")))
              ]),
              value: trustThisDevice,
              onChanged: (v) {
                if (v == null) return;
                setState(() => trustThisDevice = !trustThisDevice);
              },
            ),
            */
              // NOT use Offstage to wrap LinearProgressIndicator
              if (isInProgress) const LinearProgressIndicator(),
            ],
          ),
          onCancel: cancelVerification,
          onSubmit: getOnSubmit(),
          actions: [
            dialogButton("Cancel",
                onPressed: cancelVerification, isOutline: true),
            dialogButton("Verify", onPressed: getOnSubmit()),
          ]);
    });
    verificationDialogActive = false;
    // 移动端需先关闭登录框再刷新其他模型，避免软键盘反复弹出。
    if (isMobile &&
        res != null &&
        (isWeb || gFFI.userModel.isVisibleLoginResponseCurrent(res))) {
      await UserModel.updateOtherModels();
    }

    return res;
  } catch (error) {
    debugPrint('验证码对话框打开失败: $error');
    return null;
  } finally {
    verificationDialogActive = false;
    code.dispose();
    // OverlayDialogManager 的外部 dismiss 不会触发 onCancel。
    if (ownerTicket != null) {
      gFFI.userModel.releaseNativeAuthStart(ownerTicket);
    }
    if (nativeAttemptJson != null && !attemptAcknowledged) {
      await gFFI.userModel.cancelNativeAttempt(nativeAttemptJson);
    }
  }
}

void logOutConfirmDialog() {
  gFFI.dialogManager.show((setState, close, context) {
    submit() {
      close();
      gFFI.userModel.logOut();
    }

    return CustomAlertDialog(
      content: Text(translate("logout_tip")),
      actions: [
        dialogButton(translate("Cancel"), onPressed: close, isOutline: true),
        dialogButton(translate("OK"), onPressed: submit),
      ],
      onSubmit: submit,
      onCancel: close,
    );
  });
}
