#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'fs';
import { webcrypto } from 'crypto';
globalThis.crypto = webcrypto;
globalThis.window = globalThis;
const kdbxweb = await import('../../data/kdbxweb.min.js');
globalThis.kdbxweb = kdbxweb;
await import('../../data/kdbx-shim.js');

const args = process.argv.slice(2);
if (args.length < 2) process.exit(1);
const dbPath = args[0];
const keyPath = args[1];
const out = args[2] || '/tmp/out.pmx1';
const credentials = new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(''), kdbxweb.ProtectedValue.fromBinary(readFileSync(keyPath)));
const db = await kdbxweb.Kdbx.load(readFileSync(dbPath), credentials);
const entries = [];
for (const group of db.getDefaultGroup().allGroups()) {
    for (const entry of group.entries) {
        entries.push({
            title: entry.fields.Title || '',
            login: entry.fields.UserName || '',
            password: entry.fields.Password ? entry.fields.Password.getText() : '',
            url: entry.fields.URL || '',
            note: entry.fields.Notes || '',
            tags: entry.tags ? entry.tags.join(' ') : '',
            totp: entry.fields.TOTP || '',
            totpDigits: '',
            totpPeriod: ''
        });
    }
}
for (const entry of db.getDefaultGroup().entries) {
    entries.push({
        title: entry.fields.Title || '',
        login: entry.fields.UserName || '',
        password: entry.fields.Password ? entry.fields.Password.getText() : '',
        url: entry.fields.URL || '',
        note: entry.fields.Notes || '',
        tags: entry.tags ? entry.tags.join(' ') : '',
        totp: entry.fields.TOTP || '',
        totpDigits: '',
        totpPeriod: ''
    });
}
const doc = {ok:true,format:"PMX1",version:1,count:entries.length,entries};
writeFileSync(out, JSON.stringify(doc));
console.log('wrote', out);
