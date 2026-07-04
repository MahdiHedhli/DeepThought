// Prototype pollution (CWE-1321) fixture: a VULNERABLE and a PATCHED function in one
// file, so a single scan of DT-PP-MERGE proves it discriminates. Modeled on the seed,
// js-yaml CVE-2025-64718 (an unguarded merge assignment). No code here executes in the
// benchmark; the detector only parses it.

// VULNERABLE: an unguarded merge. The hasOwnProperty check is a benign DUPLICATE-key
// guard — it writes when the key is NOT already present, so a "__proto__" key (never an
// own key of a fresh object) is written straight through and pollutes Object.prototype.
function mergeVulnerable(destination, source) {
  var keys = Object.keys(source);
  for (var i = 0; i < keys.length; i++) {
    var key = keys[i];
    if (!Object.prototype.hasOwnProperty.call(destination, key)) {
      destination[key] = source[key]; // SINK: unguarded write by a dynamic, copied key
    }
  }
  return destination;
}

// PATCHED: the same merge, but the proto key is checked before the write.
function mergePatched(destination, source) {
  var keys = Object.keys(source);
  for (var i = 0; i < keys.length; i++) {
    var key = keys[i];
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    if (!Object.prototype.hasOwnProperty.call(destination, key)) {
      destination[key] = source[key];
    }
  }
  return destination;
}
