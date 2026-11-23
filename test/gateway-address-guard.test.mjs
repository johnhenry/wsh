// test/gateway-address-guard.test.mjs -- the public-address guard behind the gateway's destination policy.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { isPublicAddress, parseIp, parseCidr, addressInCidr, sameAddress } from '../src/server/address-guard.mjs';

describe('isPublicAddress', () => {
  it('accepts ordinary global unicast addresses', () => {
    for (const a of ['8.8.8.8', '1.1.1.1', '93.184.216.34', '172.15.0.1', '172.32.0.1', '100.63.255.255', '100.128.0.1', '2606:4700:4700::1111', '2a00:1450:4001:81b::200e']) {
      assert.equal(isPublicAddress(a), true, a);
    }
  });

  it('refuses loopback, private, link-local, CGNAT, reserved and multicast IPv4', () => {
    for (const a of ['0.0.0.0', '0.1.2.3', '127.0.0.1', '127.255.255.254', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254',
      '100.64.0.1', '100.127.255.255', '192.0.0.8', '192.0.2.1', '198.18.0.1', '198.19.255.255', '198.51.100.7', '203.0.113.9', '224.0.0.1', '239.1.1.1', '240.0.0.1', '255.255.255.255']) {
      assert.equal(isPublicAddress(a), false, a);
    }
  });

  it('refuses IPv6 loopback, unspecified, ULA, link-local, site-local, multicast, documentation and the deprecated forms', () => {
    for (const a of ['::', '::1', '::2', 'fc00::1', 'fd12:3456::1', 'fe80::1', 'febf::1', 'fec0::1', 'ff02::1', '2001:db8::1', '3fff::1', '100::1', '2001::1', '2001:1::1', '5f00::1', '1::1', '::127.0.0.1', '::8.8.8.8']) {
      assert.equal(isPublicAddress(a), false, a);
    }
  });

  it('refuses mapped, NAT64 and 6to4 forms that wrap a non-public IPv4 address, and accepts the ones that wrap a public one', () => {
    for (const a of ['::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:10.0.0.1', '::ffff:a00:1', '::ffff:169.254.169.254', '::ffff:192.168.0.1', '0:0:0:0:0:ffff:7f00:1',
      '64:ff9b::7f00:1', '64:ff9b::127.0.0.1', '64:ff9b::a00:1', '64:ff9b::192.168.1.1', '64:ff9b:1::1', '2002:7f00:1::', '2002:a00:1::1', '2002:c0a8:101::1']) {
      assert.equal(isPublicAddress(a), false, a);
    }
    assert.equal(isPublicAddress('::ffff:8.8.8.8'), true);
    assert.equal(isPublicAddress('64:ff9b::808:808'), true);
    assert.equal(isPublicAddress('2002:808:808::1'), true);
  });

  it('refuses anything it cannot parse, a zone id, and non-strings', () => {
    for (const a of ['', 'localhost', 'example.com', '1.2.3', '1.2.3.4.5', '256.1.1.1', '01.2.3.4', '2130706433', '0x7f.0.0.1', '1.2.3.4/8', 'fe80::1%eth0', ':::', '1::2::3', 'g::1', '12345::1', '8.8.8.8 ', undefined, null, 5]) {
      assert.equal(isPublicAddress(a), a === '8.8.8.8 ', String(a)); // surrounding whitespace is trimmed; everything else is refused
    }
  });
});

describe('cidr helpers', () => {
  it('parses blocks and single addresses and tests membership, mapped addresses included', () => {
    assert.ok(parseCidr('10.0.0.0/8'));
    assert.equal(parseCidr('10.0.0.0/33'), null);
    assert.equal(parseCidr('::1/129'), null);
    assert.equal(parseCidr('nope'), null);
    assert.equal(parseCidr('1.2.3.4/8/9'), null);
    assert.equal(addressInCidr('10.9.9.9', parseCidr('10.0.0.0/8')), true);
    assert.equal(addressInCidr('11.0.0.1', parseCidr('10.0.0.0/8')), false);
    assert.equal(addressInCidr('127.0.0.1', parseCidr('127.0.0.1')), true);
    assert.equal(addressInCidr('127.0.0.2', parseCidr('127.0.0.1')), false);
    assert.equal(addressInCidr('::ffff:10.1.1.1', parseCidr('10.0.0.0/8')), true);
    assert.equal(addressInCidr('::1', parseCidr('::1')), true);
    assert.equal(addressInCidr('fd00::5', parseCidr('fc00::/7')), true);
    assert.equal(addressInCidr('10.0.0.1', parseCidr('fc00::/7')), false);
    assert.equal(sameAddress('127.0.0.1', '::ffff:7f00:1'), true);
    assert.equal(sameAddress('127.0.0.1', '127.0.0.2'), false);
    assert.equal(parseIp('::ffff:1.2.3.4').v, 6);
  });
});
