import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:flutter_hbb/consts.dart';
import 'package:http/http.dart' as http;
import '../models/platform_model.dart';
import 'package:flutter_hbb/common.dart';
export 'package:http/http.dart' show Response;

enum HttpMethod { get, post, put, delete }

const _nativeSessionMarker = 'X-RustDesk-Native-Session';

class StrictHttpResult {
  final http.Response response;
  final String handleJson;
  final String requestId;
  final String normalizedApiBase;
  final String namespace;
  final int sessionEpoch;
  final String sessionNonce;
  final String cursorKey;
  final int cursor;
  final String? personalHashReceipt;

  const StrictHttpResult({
    required this.response,
    required this.handleJson,
    required this.requestId,
    required this.normalizedApiBase,
    required this.namespace,
    required this.sessionEpoch,
    required this.sessionNonce,
    required this.cursorKey,
    required this.cursor,
    this.personalHashReceipt,
  });

  Future<bool> isCurrent() async {
    return await bind.mainAuthIsRequestCurrent(handleJson: handleJson);
  }

  Future<bool> acknowledgeCursor(int target, {bool allowReset = false}) async {
    return await bind.mainAuthCompleteAddressBookPull(
      handleJson: handleJson,
      expected: cursor,
      target: target,
      allowReset: allowReset,
    );
  }

  bool hasSameRequestIdentity(StrictHttpResult other) {
    return handleJson == other.handleJson &&
        requestId == other.requestId &&
        normalizedApiBase == other.normalizedApiBase &&
        namespace == other.namespace &&
        sessionEpoch == other.sessionEpoch &&
        sessionNonce == other.sessionNonce &&
        cursorKey == other.cursorKey &&
        cursor == other.cursor;
  }
}

class HttpService {
  Future<http.Response> sendRequest(
    Uri url,
    HttpMethod method, {
    Map<String, String>? headers,
    dynamic body,
  }) async {
    final requestHeaders = Map<String, String>.from(
        headers ?? {'Content-Type': 'application/json'});
    final requiresNativeSession =
        requestHeaders.remove(_nativeSessionMarker) == 'required';

    if (requiresNativeSession && !(isWeb || kIsWeb)) {
      final result = await sendCredentialedRequest(
        url,
        method,
        headers: requestHeaders,
        body: body,
      );
      return result.response;
    }

    // Use Rust HTTP implementation for non-web platforms for consistency.
    var useFlutterHttp = (isWeb || kIsWeb);
    if (!useFlutterHttp) {
      final enableFlutterHttpOnRust =
          mainGetLocalBoolOptionSync(kOptionEnableFlutterHttpOnRust);
      // Use flutter http if:
      // Not `enableFlutterHttpOnRust` and no proxy is set
      useFlutterHttp =
          !(enableFlutterHttpOnRust || await bind.mainGetProxyStatus());
    }

    if (useFlutterHttp) {
      return await _pollFlutterHttp(url, method,
          headers: requestHeaders, body: body);
    }

    String headersJson = jsonEncode(requestHeaders);
    String methodName = method.toString().split('.').last;
    await bind.mainHttpRequest(
        url: url.toString(),
        method: methodName.toLowerCase(),
        body: body,
        header: headersJson);

    var resJson = await _pollForResponse(url.toString());
    return _parseHttpResponse(resJson);
  }

  Future<StrictHttpResult> sendCredentialedRequest(
    Uri url,
    HttpMethod method, {
    Map<String, String>? headers,
    dynamic body,
    Duration timeout = const Duration(seconds: 10),
    StrictHttpResult? requestContext,
    String? handleJson,
  }) async {
    if (isWeb || kIsWeb) {
      throw UnsupportedError('Web 端不支持 native 认证传输');
    }
    if (requestContext != null && handleJson != null) {
      throw ArgumentError('requestContext 与 handleJson 不能同时提供');
    }
    final capturedHandleJson = requestContext?.handleJson ??
        handleJson ??
        await bind.mainAuthBeginRequest(url: url.toString());
    final requestHeaders = Map<String, String>.from(headers ?? const {});
    requestHeaders.remove(_nativeSessionMarker);
    final bodyText =
        body == null ? null : (body is String ? body : jsonEncode(body));
    final resultJson = await bind.mainAuthStrictRequest(
      handleJson: capturedHandleJson,
      url: url.toString(),
      method: method.name,
      body: bodyText,
      headersJson: jsonEncode(requestHeaders),
      timeoutMs: timeout.inMilliseconds,
    );
    final decoded = jsonDecode(resultJson);
    if (decoded is! Map<String, dynamic>) {
      throw const FormatException('严格 HTTP 响应格式无效');
    }
    final status = decoded['status'];
    final responseBody = decoded['body'];
    final epoch = decoded['session_epoch'];
    final cursor = decoded['cursor'];
    final requestId = decoded['request_id'];
    final normalizedApiBase = decoded['normalized_api_base'];
    final namespace = decoded['namespace'];
    final sessionNonce = decoded['session_nonce'];
    final cursorKey = decoded['cursor_key'];
    final personalHashReceipt = decoded['personal_hash_receipt'];
    if (status is! int ||
        responseBody is! String ||
        epoch is! int ||
        cursor is! int ||
        cursor < 0 ||
        requestId is! String ||
        requestId.isEmpty ||
        normalizedApiBase is! String ||
        normalizedApiBase.isEmpty ||
        namespace is! String ||
        namespace.isEmpty ||
        sessionNonce is! String ||
        sessionNonce.isEmpty ||
        cursorKey is! String ||
        cursorKey.isEmpty ||
        (personalHashReceipt != null &&
            (personalHashReceipt is! String ||
                personalHashReceipt.isEmpty ||
                personalHashReceipt.length > 64))) {
      throw const FormatException('严格 HTTP 响应字段无效');
    }
    final safeHeaders = <String, String>{};
    final contentType = decoded['content_type'];
    final retryAfter = decoded['retry_after'];
    if (contentType is String && contentType.isNotEmpty) {
      safeHeaders['content-type'] = contentType;
    }
    if (retryAfter is String && retryAfter.isNotEmpty) {
      safeHeaders['retry-after'] = retryAfter;
    }
    final result = StrictHttpResult(
      response: http.Response(responseBody, status, headers: safeHeaders),
      handleJson: capturedHandleJson,
      requestId: requestId,
      normalizedApiBase: normalizedApiBase,
      namespace: namespace,
      sessionEpoch: epoch,
      sessionNonce: sessionNonce,
      cursorKey: cursorKey,
      cursor: cursor,
      personalHashReceipt:
          personalHashReceipt is String ? personalHashReceipt : null,
    );
    if (requestContext != null &&
        !result.hasSameRequestIdentity(requestContext)) {
      throw const FormatException('分页严格 HTTP 请求身份发生变化');
    }
    if (status == 401) {
      await bind.mainAuthClearIfCurrent(handleJson: capturedHandleJson);
    }
    return result;
  }

  Future<http.Response> _pollFlutterHttp(
    Uri url,
    HttpMethod method, {
    Map<String, String>? headers,
    dynamic body,
  }) async {
    var response = http.Response('', 400);

    switch (method) {
      case HttpMethod.get:
        response = await http.get(url, headers: headers);
        break;
      case HttpMethod.post:
        response = await http.post(url, headers: headers, body: body);
        break;
      case HttpMethod.put:
        response = await http.put(url, headers: headers, body: body);
        break;
      case HttpMethod.delete:
        response = await http.delete(url, headers: headers, body: body);
        break;
      default:
        throw Exception('Unsupported HTTP method');
    }

    return response;
  }

  Future<String> _pollForResponse(String url) async {
    String? responseJson = " ";
    while (responseJson == " ") {
      responseJson = await bind.mainGetHttpStatus(url: url);
      if (responseJson == null) {
        throw Exception('The HTTP request failed');
      }
      if (responseJson == " ") {
        await Future.delayed(const Duration(milliseconds: 100));
      }
    }
    return responseJson!;
  }

  http.Response _parseHttpResponse(String responseJson) {
    try {
      var parsedJson = jsonDecode(responseJson);
      String body = parsedJson['body'];
      Map<String, String> headers = {};
      for (var key in parsedJson['headers'].keys) {
        headers[key] = parsedJson['headers'][key];
      }
      int statusCode = parsedJson['status_code'];
      return http.Response(body, statusCode, headers: headers);
    } catch (e) {
      print('Failed to parse response\n$responseJson\nError:\n$e');
      throw Exception('Failed to parse response.\n$responseJson');
    }
  }
}

Future<http.Response> get(Uri url, {Map<String, String>? headers}) async {
  return await HttpService().sendRequest(url, HttpMethod.get, headers: headers);
}

Future<http.Response> post(Uri url,
    {Map<String, String>? headers, Object? body, Encoding? encoding}) async {
  return await HttpService()
      .sendRequest(url, HttpMethod.post, body: body, headers: headers);
}

Future<http.Response> put(Uri url,
    {Map<String, String>? headers, Object? body, Encoding? encoding}) async {
  return await HttpService()
      .sendRequest(url, HttpMethod.put, body: body, headers: headers);
}

Future<http.Response> delete(Uri url,
    {Map<String, String>? headers, Object? body, Encoding? encoding}) async {
  return await HttpService()
      .sendRequest(url, HttpMethod.delete, body: body, headers: headers);
}

Future<StrictHttpResult> getCredentialed(
  Uri url, {
  Map<String, String>? headers,
  StrictHttpResult? requestContext,
  String? handleJson,
}) async {
  return await HttpService().sendCredentialedRequest(
    url,
    HttpMethod.get,
    headers: headers,
    requestContext: requestContext,
    handleJson: handleJson,
  );
}

Future<StrictHttpResult> postCredentialed(
  Uri url, {
  Map<String, String>? headers,
  Object? body,
  StrictHttpResult? requestContext,
  String? handleJson,
}) async {
  return await HttpService().sendCredentialedRequest(
    url,
    HttpMethod.post,
    body: body,
    headers: headers,
    requestContext: requestContext,
    handleJson: handleJson,
  );
}

Future<StrictHttpResult> putCredentialed(
  Uri url, {
  Map<String, String>? headers,
  Object? body,
  StrictHttpResult? requestContext,
  String? handleJson,
}) async {
  return await HttpService().sendCredentialedRequest(
    url,
    HttpMethod.put,
    body: body,
    headers: headers,
    requestContext: requestContext,
    handleJson: handleJson,
  );
}

Future<StrictHttpResult> deleteCredentialed(
  Uri url, {
  Map<String, String>? headers,
  Object? body,
  StrictHttpResult? requestContext,
  String? handleJson,
}) async {
  return await HttpService().sendCredentialedRequest(
    url,
    HttpMethod.delete,
    body: body,
    headers: headers,
    requestContext: requestContext,
    handleJson: handleJson,
  );
}

Future<String> beginCredentialedRequest(Uri url) async {
  if (isWeb || kIsWeb) {
    throw UnsupportedError('Web 端不支持 native 认证传输');
  }
  return await bind.mainAuthBeginRequest(url: url.toString());
}

Future<bool> isCredentialedRequestCurrent(String handleJson) async {
  if (isWeb || kIsWeb) return false;
  return await bind.mainAuthIsRequestCurrent(handleJson: handleJson);
}
