const { test } = require('node:test');
const assert = require('node:assert');
const { validateEmail, validatePassword, validateNote } = require('../utils');

test('email valid', () => assert.strictEqual(validateEmail('user@example.com'), null));
test('email invalid', () => { assert.ok(validateEmail('bad')); assert.ok(validateEmail('')); assert.ok(validateEmail(null)); assert.ok(validateEmail('a@b')); });
test('password valid', () => assert.strictEqual(validatePassword('Password123'), null));
test('password short', () => assert.ok(validatePassword('P1')));
test('password no digits', () => assert.ok(validatePassword('PasswordOnly')));
test('password no letters', () => assert.ok(validatePassword('12345678')));
test('note valid', () => { const r = validateNote({ title: 'T', content: 'C' }); assert.strictEqual(r.errors.length, 0); });
test('note empty title', () => { const r = validateNote({ title: '', content: 'C' }); assert.ok(r.errors.length > 0); });
test('note long title', () => { const r = validateNote({ title: 'x'.repeat(201), content: 'C' }); assert.ok(r.errors.length > 0); });