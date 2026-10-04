'use strict';
const assert=require('node:assert/strict');
const {inspect}=require('./.github/actions/node-runtime-identity/identity.cjs');
let closed=0,read=0;
const io={realpathSync:()=>'/invented/node',openSync:()=>3,
 fstatSync:()=>({isFile:()=>true,size:3,ino:1,mtimeMs:1}),
 readSync:(fd,b)=>{if(read++)return 0;b.write('abc');return 3;},closeSync:()=>closed++};
const result=inspect(io,'/invented/link','v24.invented');
assert.equal(result.sha256,'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
assert.equal(result.other_actions_same_binary_verified,false);assert.equal(closed,1);
assert.throws(()=>inspect({...io,fstatSync:()=>({isFile:()=>true,size:134217729})},'x','x'));
assert.equal(closed,2);
console.log('2 mocked Node identity checks passed; no actual executable hashed');
