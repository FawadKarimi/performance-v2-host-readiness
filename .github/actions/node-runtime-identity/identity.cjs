'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
function inspect(io, executable, version) {
  const resolved = io.realpathSync(executable);
  const fd = io.openSync(resolved, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const before = io.fstatSync(fd);
    if (!before.isFile() || before.size > 128 * 1024 * 1024) throw Error('binary_size_or_type');
    const hash = crypto.createHash('sha256'), buffer = Buffer.alloc(65536);
    let count = 0, size;
    while ((size = io.readSync(fd, buffer, 0, buffer.length, null)) > 0) {
      count += size;
      if (count > before.size) throw Error('binary_changed');
      hash.update(buffer.subarray(0,size));
    }
    const after = io.fstatSync(fd);
    if (count !== before.size || after.ino !== before.ino || after.size !== before.size || after.mtimeMs !== before.mtimeMs) throw Error('binary_changed');
    return {status:'observed_not_accepted', executable, resolved, version, size:count, sha256:hash.digest('hex'),
      scope:'actual_local_identity_action_interpreter_only', other_actions_same_binary_verified:false};
  } finally { io.closeSync(fd); }
}
function main() {
  const folder = path.join(process.env.RUNNER_TEMP, `node-identity-${process.env.GITHUB_RUN_ID}-${process.env.GITHUB_RUN_ATTEMPT}`);
  fs.mkdirSync(folder,{mode:0o700});
  const save = (n,x) => fs.writeFileSync(path.join(folder,n),JSON.stringify(x,null,2)+'\n',{flag:'wx',mode:0o600});
  save('started.json',{status:'incomplete',accepted:false});
  try { save('report.json',inspect(fs,process.execPath,process.version)); }
  catch (error) { save('failed.json',{status:'unresolved',failure_type:error.name,accepted:false}); process.exitCode=1; }
}
module.exports={inspect};
if (require.main === module) main();
