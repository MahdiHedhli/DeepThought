const path = require("path");

// Read-only benchmark fixture: these functions are parsed, never called.
function extractVulnerable(output, entry, writeFile) {
  const destination = path.join(output, entry.path);
  return writeFile(destination, entry.data);
}

function extractPatched(output, entry, writeFile) {
  const destination = path.resolve(output, entry.path);
  const resolvedOutput = path.resolve(output) + path.sep;
  if (!destination.startsWith(resolvedOutput)) {
    throw new Error("archive entry escapes destination");
  }
  return writeFile(destination, entry.data);
}

module.exports = { extractVulnerable, extractPatched };
