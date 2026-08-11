import 'package:flutter_hbb/common/hbbs/hbbs.dart';
import 'package:flutter_hbb/models/ab_model.dart';
import 'package:flutter_test/flutter_test.dart';

String repeatText(String value, int count) =>
    List<String>.filled(count, value).join();

Map<String, dynamic> item({
  String id = '100001',
  String instance =
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  String source = 'owned',
  String permission = 'full_control',
  int? shareId,
}) {
  return {
    'device_id': id,
    'instance_id': instance,
    'alias': '财务前台',
    'hostname': 'DESKTOP-A01',
    'os': 'Windows',
    'source': source,
    'permission': permission,
    'share_id': shareId,
    'shared_by_user_id': source == 'shared' ? 7 : null,
    'shared_by_username': source == 'shared' ? 'alice' : null,
  };
}

void main() {
  test('个人地址簿探测兼容 404 与 405', () {
    expect(shouldProbeIssue9AddressBook(404), isTrue);
    expect(shouldProbeIssue9AddressBook(405), isTrue);
    expect(shouldProbeIssue9AddressBook(400), isFalse);
    expect(shouldProbeIssue9AddressBook(500), isFalse);
  });

  test('商业地址簿 200 响应必须包含非空字符串 guid', () {
    expect(parsePersonalAddressBookGuid({'guid': ' personal-guid '}),
        'personal-guid');
    for (final value in <dynamic>[
      <String, dynamic>{},
      {'guid': null},
      {'guid': 42},
      {'guid': ''},
      {'guid': '   '},
      <dynamic>[],
    ]) {
      expect(
        () => parsePersonalAddressBookGuid(value),
        throwsFormatException,
      );
    }
  });

  test('共享地址簿不能覆盖个人地址簿的保留名称或 guid', () {
    expect(
      sharedAddressBookCollidesWithPersonal(
        name: 'My address book',
        guid: 'shared-guid',
        personalGuid: 'personal-guid',
      ),
      isTrue,
    );
    expect(
      sharedAddressBookCollidesWithPersonal(
        name: '团队地址簿',
        guid: 'personal-guid',
        personalGuid: 'personal-guid',
      ),
      isTrue,
    );
    expect(
      sharedAddressBookCollidesWithPersonal(
        name: '团队地址簿',
        guid: 'shared-guid',
        personalGuid: 'personal-guid',
      ),
      isFalse,
    );
  });

  test('解析完整地址簿并保留同一实例的本地标签', () {
    final full = Issue9FullPage.fromJson({
      'mode': 'full',
      'ab_ver': 1,
      'items': [item()],
      'page': 1,
      'page_size': 50,
      'total': 1,
      'has_more': false,
    });
    final previous = Issue9AddressBookState.replaceAll(full.items, const []);
    previous.single.tags = ['重要'];
    previous.single.username = 'operator';

    final refreshed = Issue9AddressBookState.replaceAll(full.items, previous);

    expect(refreshed.single.id, '100001');
    expect(refreshed.single.hash, isEmpty);
    expect(refreshed.single.tags, ['重要']);
    expect(refreshed.single.username, 'operator');
    expect(refreshed.single.addressBookPermission, 'full_control');
  });

  test('共享条目联合字段必须一致', () {
    final shared = Issue9AddressBookItem.fromJson(item(
      source: 'shared',
      permission: 'view_only',
      shareId: 42,
    ));
    expect(shared.shareId, 42);
    expect(
      () => Issue9AddressBookItem.fromJson(
          item(source: 'shared', permission: 'view_only')),
      throwsFormatException,
    );
  });

  test('地址簿文本边界与服务端 Unicode 协议一致', () {
    final maxScalarDeviceId = repeatText('😀', 100);
    expect(
      Issue9AddressBookItem.fromJson(item(id: maxScalarDeviceId)).deviceId,
      maxScalarDeviceId,
    );

    final maxAlias = repeatText('😀', 200);
    final maxHostname = repeatText('你', 66);
    final maxOs = repeatText('你', 33);
    final valid = item(id: maxScalarDeviceId)
      ..['alias'] = maxAlias
      ..['hostname'] = maxHostname
      ..['os'] = maxOs;
    final parsed = Issue9AddressBookItem.fromJson(valid);
    expect(parsed.alias, maxAlias);
    expect(parsed.hostname, maxHostname);
    expect(parsed.os, maxOs);

    for (final invalid in <Map<String, dynamic>>[
      item(id: repeatText('😀', 101)),
      item(id: 'device\n'),
      item()..['alias'] = repeatText('a', 201),
      item()..['alias'] = 'alias\u007f',
      item()..['hostname'] = repeatText('你', 67),
      item()..['hostname'] = 'host\n',
      item()..['os'] = repeatText('你', 34),
      item()..['os'] = 'os\u0085',
      item(source: 'shared', permission: 'view_only', shareId: 42)
        ..['shared_by_username'] = '',
      item(source: 'shared', permission: 'view_only', shareId: 42)
        ..['shared_by_username'] = repeatText('😀', 101),
      item(source: 'shared', permission: 'view_only', shareId: 42)
        ..['shared_by_username'] = 'alice\n',
    ]) {
      expect(
        () => Issue9AddressBookItem.fromJson(invalid),
        throwsFormatException,
      );
    }

    for (final invalidDeviceId in <String>[
      repeatText('😀', 101),
      'device\n',
    ]) {
      expect(
        () => Issue9DeltaPage.fromJson({
          'mode': 'delta',
          'ab_ver': 2,
          'next_ab_ver': 2,
          'changes': [
            {
              'version': 2,
              'operation': 'delete',
              'device_id': invalidDeviceId,
              'instance_id':
                  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
              'share_id': null,
              'item': null,
            }
          ],
          'page_size': 50,
          'has_more': false,
          'reset_required': false,
        }, 1),
        throwsFormatException,
      );
    }
  });

  test('旧实例删除不会删除相同外部ID的新实例', () {
    final oldItem = Issue9AddressBookItem.fromJson(item());
    final newItem = Issue9AddressBookItem.fromJson(item(
      instance:
          'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    ));
    final current =
        Issue9AddressBookState.replaceAll([oldItem, newItem], const []);
    final delta = Issue9DeltaPage.fromJson({
      'mode': 'delta',
      'ab_ver': 2,
      'next_ab_ver': 2,
      'changes': [
        {
          'version': 2,
          'operation': 'delete',
          'device_id': '100001',
          'instance_id':
              'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          'share_id': null,
          'item': null,
        }
      ],
      'page_size': 50,
      'has_more': false,
      'reset_required': false,
    }, 1);

    final next = Issue9AddressBookState.applyDelta(current, delta);

    expect(next, hasLength(1));
    expect(next.single.addressBookInstanceId,
        'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');
  });

  test('拒绝不连续版本和不安全实例标识', () {
    expect(
      () => Issue9DeltaPage.fromJson({
        'mode': 'delta',
        'ab_ver': 3,
        'next_ab_ver': 3,
        'changes': [
          {
            'version': 3,
            'operation': 'upsert',
            'device_id': '100001',
            'instance_id': 'bad',
            'share_id': null,
            'item': item(instance: 'bad'),
          }
        ],
        'page_size': 50,
        'has_more': false,
        'reset_required': false,
      }, 1),
      throwsFormatException,
    );
  });

  test('缓存恢复的旧版与商业地址簿在服务端确认前保持只读', () {
    final legacy = LegacyAb();
    final personal = Ab(
      AbProfile('personal', '个人地址簿', 'owner', null, ShareRule.fullControl.value,
          null),
      true,
    );
    final shared = Ab(
      AbProfile(
          'shared', '共享地址簿', 'owner', null, ShareRule.fullControl.value, null),
      false,
    );

    for (final addressBook in [legacy, personal, shared]) {
      expect(addressBook.canWrite(), isFalse);
      expect(addressBook.fullControl(), isFalse);
    }

    expect(LegacyAb(writableConfirmed: true).canWrite(), isFalse);
    expect(LegacyAb(writableConfirmed: true).fullControl(), isFalse);
    expect(
      Ab(
        AbProfile(
            'live', '在线地址簿', 'owner', null, ShareRule.fullControl.value, null),
        false,
        writableConfirmed: true,
      ).fullControl(),
      isFalse,
    );
  });

  test('personal hash 发布材料只来自 legacy 或 commercial personal', () {
    final legacy = LegacyAb();
    final personal = Ab(
      AbProfile('personal', '个人地址簿', 'owner', null, ShareRule.fullControl.value,
          null),
      true,
    );
    final shared = Ab(
      AbProfile(
          'shared', '共享地址簿', 'owner', null, ShareRule.fullControl.value, null),
      false,
    );
    final issue9 = Issue9Ab(
      (_) async => throw StateError('测试不执行网络拉取'),
      (_) {},
    );

    expect(legacy.personalHashSource, 'legacy_personal');
    expect(personal.personalHashSource, 'commercial_personal');
    expect(shared.personalHashSource, isNull);
    expect(issue9.personalHashSource, isNull);
  });
}
